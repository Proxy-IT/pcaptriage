package rules

import (
	"sort"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
)

// The loss classifier is the shared substrate under R05, R06, R07 and — in the
// next part — R08. One sequence-tracking pass classifies every candidate
// retransmission exactly once, and each rule reads its own class out of the
// result.
//
// This sharing is not a convenience: it IS the suppression seam RULES.md's
// interaction order describes. R07 "runs before R05 and R06, and suppresses
// their findings for reclassified segments" — here that is structural rather
// than sequential. A segment classified as reordering lands in the reorder
// bucket and in no other; R05 and R06 never see it, so there is nothing to
// suppress after the fact and no window in which both rules could claim the
// same segment. The same pattern as R15's CaptureQuality gating: one owner
// establishes the fact, consumers read it, nobody re-derives it.
//
// Classification precedence, applied per candidate segment:
//
//  1. zero-window probe / keep-alive shapes — flow-control machinery, not loss;
//     excluded entirely (the R01 fixtures are full of them)
//  2. reordering (R07): arrived within the reorder window of the segment it
//     should have preceded, with IP ID consistent with original transmission
//     order — timing alone on IPv6, at lowered confidence
//  3. fast retransmission (R06): the peer had sent ≥3 duplicate ACKs asking
//     for exactly this segment
//  4. timeout retransmission (R05): a timer-shaped quiet gap preceded it, or
//     it belongs to a recovery episode an RTO opened
//  5. unclassified: a retransmission with none of those shapes. Counted in the
//     totals (R08's rates need it) but claimed by no rule.
type lossAnalyzer struct {
	// retained holds one entry per flow that showed any of the conditions.
	// This is the retained tier — flow state is gone by the time Emit runs.
	retained map[flow.Key]*lossFlowResult

	// Population baselines. Directions and flows that showed nothing count as
	// zeros; a condition present uniformly is background, not a finding.
	dirsWithData      int
	flowsWithData     int
	dirRetransRates   []float64 // non-zero per-direction retransmission rates
	flowFastRates     []float64 // non-zero per-flow fast-retransmit rates
	flowReorderShares []float64 // non-zero per-flow reorder shares
}

func newLossAnalyzer() *lossAnalyzer {
	return &lossAnalyzer{retained: make(map[flow.Key]*lossFlowResult)}
}

// lossDirState tracks one direction's data stream on the packet path.
type lossDirState struct {
	maxSeqEnd uint32
	maxValid  bool

	// The segment that last advanced the high-water mark: the one a reordered
	// segment should have preceded. Its IP ID is what "sane ordering" is
	// judged against. lastAdvancePkt is a value copy of the whole packet —
	// copied rather than snapshotted, so the hot path allocates nothing and a
	// context row can still be built if a reorder cites it later.
	lastAdvanceTime  time.Time
	lastAdvanceIPID  uint16
	lastAdvancePkt   capture.Packet
	lastAdvanceValid bool

	// lastDataTime is when this direction last sent data — the baseline for
	// the timer-shaped quiet gap that identifies an RTO.
	lastDataTime  time.Time
	lastDataValid bool

	// An RTO opens a recovery episode: segments retransmitted in its wake are
	// timeout-driven too, but only the opening gap is time lost. The episode
	// ends when new data advances the stream.
	inRTOEpisode bool

	// Exponential backoff: the same range retransmitted again after a longer
	// gap. "Retry intervals doubled each attempt" is only said when this
	// was actually observed.
	lastRetransSeqEnd uint32
	prevRetransGap    time.Duration
	backoffObserved   bool

	retrans      uint64 // rto + fast + unclassified — reorders excluded
	rto          uint64
	fast         uint64
	reorder      uint64
	unclassified uint64

	rtoTimeLost     time.Duration
	fastTimeCost    time.Duration
	maxReorderDelta time.Duration
	lastRTOTime     time.Time

	rtoEvidence     findings.Evidence
	fastEvidence    findings.Evidence
	reorderEvidence findings.Evidence
	// fastContext holds duplicate-ACK rows a fast-retransmit finding shows as
	// its trigger; reorderContext holds the overtaking segments a reorder
	// finding shows beside the late arrivals.
	fastContext    []findings.PacketRef
	reorderContext []findings.PacketRef
}

// lossAckState tracks the pure ACKs one side sends about the other side's
// data.
type lossAckState struct {
	lastAck    uint32
	ackValid   bool
	lastWindow uint16
	// dupRun counts consecutive ACKs identical to lastAck. Three of them is
	// the fast-retransmit trigger.
	dupRun       int
	firstDupTime time.Time
	dupTotal     uint64
	lastDupRef   *findings.PacketRef
}

// lossFlowState is the classifier's per-flow packet-path state.
type lossFlowState struct {
	dir [2]lossDirState
	ack [2]lossAckState
	// windowNow is the most recent receive window each side advertised, for
	// recognising zero-window probes.
	windowNow [2]uint16
	ipv6      bool
}

// lossDirResult is one direction's summary in the retained tier.
type lossDirResult struct {
	dataSegments uint64
	retrans      uint64
	rto          uint64
	fast         uint64
	reorder      uint64
	unclassified uint64

	rtoTimeLost     time.Duration
	fastTimeCost    time.Duration
	maxReorderDelta time.Duration
	backoffObserved bool

	rtoFrames     []uint64
	rtoFirst      uint64
	rtoWorst      uint64
	fastFrames    []uint64
	fastFirst     uint64
	fastWorst     uint64
	reorderFrames []uint64
	reorderFirst  uint64
	reorderWorst  uint64

	rtoPackets     []findings.PacketRef
	fastPackets    []findings.PacketRef
	reorderPackets []findings.PacketRef
}

// lossFlowResult is the per-flow summary moved into the retained tier.
type lossFlowResult struct {
	key    flow.Key
	dir    [2]lossDirResult
	ipv6   bool
	oneWay bool
	// proximate reports a timeout retransmission within the proximity window
	// of a RST on this flow.
	proximate bool
}

func (r *lossFlowResult) totalDataSegments() uint64 {
	return r.dir[0].dataSegments + r.dir[1].dataSegments
}
func (r *lossFlowResult) totalFast() uint64    { return r.dir[0].fast + r.dir[1].fast }
func (r *lossFlowResult) totalReorder() uint64 { return r.dir[0].reorder + r.dir[1].reorder }
func (r *lossFlowResult) totalRetrans() uint64 { return r.dir[0].retrans + r.dir[1].retrans }

// newFlow allocates the classifier's per-flow state.
func (a *lossAnalyzer) newFlow() *lossFlowState {
	s := &lossFlowState{}
	for d := range s.dir {
		// Worst-first for RTO evidence: the frames worth citing are the ones
		// after the longest stalls. First-first for the other two, where the
		// reader wants to see where the pattern started.
		s.dir[d].rtoEvidence.Mode = findings.ModeWorst
		s.dir[d].fastEvidence.Mode = findings.ModeFirst
		s.dir[d].reorderEvidence.Mode = findings.ModeFirst
	}
	return s
}

// onPacket classifies one packet.
func (a *lossAnalyzer) onPacket(s *lossFlowState, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	if p.AnyFlag(capture.FlagRST) {
		return
	}
	if p.IPVersion == 6 {
		s.ipv6 = true
	}
	s.windowNow[dir] = p.Window

	// Duplicate-ACK tracking for the ACKs this side sends. A pure ACK
	// identical to the previous one — same acknowledgement number, same
	// window — is the receiver saying "still missing the same segment". A
	// changed window is a window update, and a zero window is flow control;
	// neither is a loss signal (R01 owns the second).
	if p.AnyFlag(capture.FlagACK) && p.PayloadLength == 0 && !p.AnyFlag(capture.FlagSYN|capture.FlagFIN) {
		ack := &s.ack[dir]
		switch {
		case !ack.ackValid || p.Ack != ack.lastAck:
			ack.lastAck = p.Ack
			ack.ackValid = true
			ack.lastWindow = p.Window
			ack.dupRun = 0
		case p.Window == ack.lastWindow && p.Window > 0:
			ack.dupRun++
			ack.dupTotal++
			if ack.dupRun == 1 {
				ack.firstDupTime = p.Time
			}
			ref := findings.SnapshotPacket(p, findings.RoleContext,
				"Duplicate ACK — still asking for the same segment", "TCP Dup ACK")
			ack.lastDupRef = &ref
		default:
			// Same ack, different window: a window update. Not a duplicate,
			// and not a reset of the run either.
			ack.lastWindow = p.Window
		}
	}

	// Data segment classification.
	if p.PayloadLength == 0 || p.AnyFlag(capture.FlagSYN) {
		return
	}
	d := &s.dir[dir]
	end := p.SeqEnd()

	if !d.maxValid || capture.SeqLT(d.maxSeqEnd, end) {
		// New data. A partial overlap that still extends the stream counts as
		// an advance; v1 does not split segments.
		d.maxSeqEnd = end
		d.maxValid = true
		d.lastAdvanceTime = p.Time
		d.lastAdvanceIPID = p.IPID
		d.lastAdvancePkt = *p
		d.lastAdvanceValid = true
		if d.inRTOEpisode {
			// The stream is moving again: recovery is over.
			d.inRTOEpisode = false
		}
		d.lastDataTime = p.Time
		d.lastDataValid = true
		return
	}

	// Candidate: this segment does not advance the stream.

	// Zero-window probes and keep-alives are flow-control machinery. A probe
	// is a tiny segment sent into a closed window; a keep-alive is a one-byte
	// segment sitting just below the high-water mark on an idle connection.
	// Both re-occupy old sequence space without being retransmissions.
	if p.PayloadLength <= 1 {
		if s.windowNow[dir.Other()] == 0 {
			return // zero-window probe
		}
		if p.Seq+1 == d.maxSeqEnd {
			return // keep-alive shape
		}
	}

	quietGap := time.Duration(0)
	if d.lastDataValid {
		quietGap = p.Time.Sub(d.lastDataTime)
	}
	delta := p.Time.Sub(d.lastAdvanceTime)
	peerAck := &s.ack[dir.Other()]

	switch {
	// Reordering, checked first — this is R07 running before R05 and R06.
	// The segment arrived hard on the heels of data it should have preceded,
	// and on IPv4 its IP ID says it was sent earlier than that data. IPv6 has
	// no IP ID, so timing alone decides, at lowered confidence.
	case delta >= 0 && delta < Thresholds.R07ReorderMaxDelta &&
		(p.IPVersion == 6 || ipidBefore(p.IPID, d.lastAdvanceIPID)):
		d.reorder++
		if delta > d.maxReorderDelta {
			d.maxReorderDelta = delta
		}
		d.reorderEvidence.RecordPacket(p.Frame, p.Time, 0, func() findings.PacketRef {
			if d.lastAdvanceValid {
				ctx := findings.SnapshotPacket(&d.lastAdvancePkt, findings.RoleContext,
					"Arrived first, though sent later — the segment below should have preceded it")
				d.reorderContext = appendContext(d.reorderContext, ctx)
			}
			return findings.SnapshotPacket(p, findings.RoleFlagged,
				"Arrived after data it should have preceded — reordering, not loss", "TCP Out-Of-Order")
		})

	// Fast retransmission: the peer has been asking for exactly this segment
	// with three or more duplicate ACKs.
	case peerAck.ackValid && peerAck.dupRun >= Thresholds.R06DupAckMin && peerAck.lastAck == p.Seq:
		d.fast++
		d.retrans++
		cost := p.Time.Sub(peerAck.firstDupTime)
		if cost < 0 {
			cost = 0
		}
		d.fastTimeCost += cost
		dupRef := peerAck.lastDupRef
		d.fastEvidence.RecordPacket(p.Frame, p.Time, cost.Seconds(), func() findings.PacketRef {
			if dupRef != nil {
				d.fastContext = appendContext(d.fastContext, *dupRef)
			}
			return findings.SnapshotPacket(p, findings.RoleFlagged,
				"Retransmitted after duplicate ACKs — fast recovery", "TCP Fast Retransmission")
		})
		// The trigger is consumed: a following retransmission needs a fresh
		// run of duplicates to read as fast recovery.
		peerAck.dupRun = 0

	// Timeout retransmission: a timer-shaped quiet gap preceded it.
	case d.lastDataValid && quietGap >= Thresholds.R05MinRTOGap:
		d.rto++
		d.retrans++
		d.rtoTimeLost += quietGap
		d.lastRTOTime = p.Time
		d.inRTOEpisode = true
		if d.lastRetransSeqEnd == end && d.prevRetransGap > 0 &&
			float64(quietGap) >= float64(d.prevRetransGap)*Thresholds.R05BackoffMinRatio {
			d.backoffObserved = true
		}
		d.lastRetransSeqEnd = end
		d.prevRetransGap = quietGap
		d.rtoEvidence.RecordPacket(p.Frame, p.Time, quietGap.Seconds(), func() findings.PacketRef {
			return findings.SnapshotPacket(p, findings.RoleFlagged,
				"Retransmitted after "+formatDuration(quietGap)+" of silence — timer expiry, not fast recovery", "TCP Retransmission")
		})

	// Recovery continuation: retransmitted in the wake of an RTO, before any
	// new data has flowed. Timeout-driven, but the time was already counted
	// when the episode opened.
	case d.inRTOEpisode:
		d.rto++
		d.retrans++
		d.rtoEvidence.RecordPacket(p.Frame, p.Time, 0, func() findings.PacketRef {
			return findings.SnapshotPacket(p, findings.RoleFlagged,
				"Retransmitted during timeout recovery", "TCP Retransmission")
		})

	default:
		d.unclassified++
		d.retrans++
	}

	d.lastDataTime = p.Time
	d.lastDataValid = true
}

// onFlowEnd moves the per-flow summary into the retained tier.
func (a *lossAnalyzer) onFlowEnd(s *lossFlowState, fl *flow.State) {
	// Population accounting counts every flow, including the clean ones.
	var flowRetrans, flowFast, flowReorder, flowData uint64
	for d := flow.Direction(0); d < 2; d++ {
		segs := fl.DataSegments[d]
		if segs == 0 {
			continue
		}
		a.dirsWithData++
		flowData += segs
		ds := &s.dir[d]
		flowRetrans += ds.retrans
		flowFast += ds.fast
		flowReorder += ds.reorder
		if ds.retrans > 0 {
			a.dirRetransRates = append(a.dirRetransRates, float64(ds.retrans)/float64(segs))
		}
	}
	if flowData > 0 {
		a.flowsWithData++
		if flowFast > 0 {
			a.flowFastRates = append(a.flowFastRates, float64(flowFast)/float64(flowData))
		}
		if flowReorder > 0 {
			a.flowReorderShares = append(a.flowReorderShares, float64(flowReorder)/float64(flowData))
		}
	}

	if flowRetrans == 0 && flowReorder == 0 {
		return
	}

	res := &lossFlowResult{
		key:    fl.Key,
		ipv6:   s.ipv6,
		oneWay: fl.OneWay(),
	}
	for d := flow.Direction(0); d < 2; d++ {
		ds := &s.dir[d]
		dr := &res.dir[d]
		dr.dataSegments = fl.DataSegments[d]
		dr.retrans = ds.retrans
		dr.rto = ds.rto
		dr.fast = ds.fast
		dr.reorder = ds.reorder
		dr.unclassified = ds.unclassified
		dr.rtoTimeLost = ds.rtoTimeLost
		dr.fastTimeCost = ds.fastTimeCost
		dr.maxReorderDelta = ds.maxReorderDelta
		dr.backoffObserved = ds.backoffObserved

		dr.rtoFrames = ds.rtoEvidence.Frames()
		dr.rtoFirst = ds.rtoEvidence.FirstFrame()
		dr.rtoWorst = ds.rtoEvidence.WorstFrame()
		dr.fastFrames = ds.fastEvidence.Frames()
		dr.fastFirst = ds.fastEvidence.FirstFrame()
		dr.fastWorst = ds.fastEvidence.WorstFrame()
		dr.reorderFrames = ds.reorderEvidence.Frames()
		dr.reorderFirst = ds.reorderEvidence.FirstFrame()
		dr.reorderWorst = ds.reorderEvidence.WorstFrame()

		dr.rtoPackets = ds.rtoEvidence.Packets()
		dr.fastPackets = append(ds.fastEvidence.Packets(), ds.fastContext...)
		findings.SortPacketRefs(dr.fastPackets)
		dr.reorderPackets = append(ds.reorderEvidence.Packets(), ds.reorderContext...)
		findings.SortPacketRefs(dr.reorderPackets)

		if fl.SawRST && !ds.lastRTOTime.IsZero() {
			gap := fl.RSTTime.Sub(ds.lastRTOTime).Seconds()
			if gap >= 0 && gap <= 2.0 {
				res.proximate = true
			}
		}
	}

	a.retained[fl.Key] = res
}

// sortedResults returns the retained flows in deterministic key order.
func (a *lossAnalyzer) sortedResults() []*lossFlowResult {
	keys := make([]flow.Key, 0, len(a.retained))
	for k := range a.retained {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Compare(keys[j]) < 0 })
	out := make([]*lossFlowResult, 0, len(keys))
	for _, k := range keys {
		out = append(out, a.retained[k])
	}
	return out
}

// ipidBefore reports that a was assigned before b under wrapping 16-bit
// arithmetic — the "sane IP ID ordering" of R07: the late segment was sent
// earlier than the data that overtook it.
func ipidBefore(a, b uint16) bool { return int16(a-b) < 0 }

// appendContext keeps a bounded set of context packets, deduplicated by frame.
func appendContext(refs []findings.PacketRef, ref findings.PacketRef) []findings.PacketRef {
	for _, r := range refs {
		if r.Frame == ref.Frame {
			return refs
		}
	}
	if len(refs) >= maxClosingContexts {
		return refs
	}
	return append(refs, ref)
}
