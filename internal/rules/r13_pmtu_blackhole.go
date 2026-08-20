package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
	"github.com/Proxy-IT/pcaptriage/internal/stats"
)

// pmtuOutstanding bounds the unacknowledged segments tracked per direction.
//
// Packet-path state is evictable and capped by design (BRIEF section 5), so
// this cannot be an unbounded map of everything ever sent. A blackhole shows
// itself in the segments that never come back, and a sender with more than
// this many in flight and none of them landing has already demonstrated the
// pattern many times over.
const pmtuOutstanding = 32

// PMTUBlackhole implements R13 · pmtu-blackhole, TCP signal only.
//
// The pattern: segments above some size are sent, retransmitted, and never
// acknowledged, while smaller segments on the same connection are delivered
// normally. Something on the path will not carry the larger frames, and the
// message that would normally say so is not arriving.
//
// The size boundary is not a threshold this rule carries. It is read out of
// the capture: the largest payload that was actually acknowledged is the
// largest the path demonstrably accepts, and segments above that which were
// repeatedly retransmitted and never acknowledged are the ones failing. That
// is the same construction the offload gate uses — compare against what this
// capture observed, never against an assumed link size — and it is what lets
// the rule work without knowing the path's MTU, which is the thing being
// looked for.
type PMTUBlackhole struct {
	flows []pmtuResult
	// deliveredSizes is the largest payload each flow got acknowledged, for
	// every flow that delivered anything at all.
	//
	// This is the population a failing flow is compared against, and the
	// filter is deliberate: a flow that delivered nothing has not shown what
	// the path can carry, and letting it contribute a zero would drag the
	// median down and hide the very finding this rule exists to make. A
	// capture full of broken connections must not be able to make a broken
	// connection look ordinary.
	deliveredSizes []float64
}

type pmtuSeg struct {
	seq, end   uint32
	size       int
	sends      int
	firstFrame uint64
	firstTime  time.Time
	lastFrame  uint64
	lastTime   time.Time
}

type pmtuDir struct {
	// outstanding holds segments not yet acknowledged, oldest first.
	outstanding []pmtuSeg
	// maxDeliveredSize is the largest payload the peer acknowledged, which is
	// the largest this path has been shown to carry.
	maxDeliveredSize int
	deliveredCount   int
	// stuck accumulates segments that left the outstanding window without ever
	// being acknowledged, having been sent more than once.
	stuck []pmtuSeg
}

type pmtuFlowState struct {
	dir [2]pmtuDir
}

type pmtuResult struct {
	key        flow.Key
	sender     flow.Endpoint
	receiver   flow.Endpoint
	failedSize int
	// smallestFailed is the smallest payload that failed, which bounds where
	// the path's real limit sits.
	smallestFailed int
	deliveredSize  int
	deliveredCount int
	retransmits    int
	distinctStuck  int
	stallSeconds   float64
	evidence       findings.Evidence
}

// NewPMTUBlackhole returns the R13 detector.
func NewPMTUBlackhole() *PMTUBlackhole { return &PMTUBlackhole{} }

// Meta describes the rule.
func (r *PMTUBlackhole) Meta() Meta {
	return Meta{
		ID:         "R13",
		Name:       "pmtu-blackhole",
		BaseWeight: 7,
		Summary: "Large segments were retransmitted repeatedly and never acknowledged while " +
			"smaller ones on the same connection were delivered, which is the signature of a " +
			"size limit on the path that nothing is reporting back to the sender.",
	}
}

// NewFlow allocates the per-flow bookkeeping.
func (r *PMTUBlackhole) NewFlow() any { return &pmtuFlowState{} }

// OnPacket records what was sent and what was acknowledged.
func (r *PMTUBlackhole) OnPacket(fs any, _ *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*pmtuFlowState)
	if !ok {
		return
	}

	// An acknowledgement resolves outstanding segments in the other direction.
	if p.AnyFlag(capture.FlagACK) {
		s.dir[dir.Other()].resolve(p.Ack)
	}

	if p.PayloadLength == 0 || p.AnyFlag(capture.FlagSYN) {
		return
	}
	s.dir[dir].send(p)
}

// send records a data segment, or notes a repeat of one already outstanding.
func (d *pmtuDir) send(p *capture.Packet) {
	end := p.SeqEnd()
	for i := range d.outstanding {
		if d.outstanding[i].seq == p.Seq && d.outstanding[i].end == end {
			d.outstanding[i].sends++
			d.outstanding[i].lastFrame = p.Frame
			d.outstanding[i].lastTime = p.Time
			return
		}
	}
	if len(d.outstanding) >= pmtuOutstanding {
		// The oldest never resolved. Keep it if it was retransmitted, since
		// that is the pattern; drop it otherwise so an ordinary busy flow
		// costs nothing.
		oldest := d.outstanding[0]
		if oldest.sends > 1 {
			d.stuck = append(d.stuck, oldest)
		}
		d.outstanding = d.outstanding[1:]
	}
	d.outstanding = append(d.outstanding, pmtuSeg{
		seq: p.Seq, end: end, size: p.PayloadLength, sends: 1,
		firstFrame: p.Frame, firstTime: p.Time,
		lastFrame: p.Frame, lastTime: p.Time,
	})
}

// resolve clears every outstanding segment the acknowledgement covers.
func (d *pmtuDir) resolve(ack uint32) {
	keep := d.outstanding[:0]
	for _, seg := range d.outstanding {
		if capture.SeqLE(seg.end, ack) {
			d.deliveredCount++
			if seg.size > d.maxDeliveredSize {
				d.maxDeliveredSize = seg.size
			}
			continue
		}
		keep = append(keep, seg)
	}
	d.outstanding = keep
}

// OnFlowEnd decides whether this flow shows the pattern, and moves the answer
// into retained state before the flow is discarded.
func (r *PMTUBlackhole) OnFlowEnd(fs any, fl *flow.State) {
	s, ok := fs.(*pmtuFlowState)
	if !ok {
		return
	}

	for d := range s.dir {
		dd := &s.dir[d]
		// Every direction that delivered anything contributes to the
		// population, including this flow's own. A flow that carries small
		// segments and fails on large ones is evidence about what small
		// segments cost, and excluding it would bias the comparison in the
		// finding's favour.
		if dd.maxDeliveredSize > 0 {
			r.deliveredSizes = append(r.deliveredSizes, float64(dd.maxDeliveredSize))
		}

		// Anything still outstanding at the end was never acknowledged.
		for _, seg := range dd.outstanding {
			if seg.sends > 1 {
				dd.stuck = append(dd.stuck, seg)
			}
		}
		if len(dd.stuck) == 0 || dd.maxDeliveredSize == 0 {
			continue
		}
		if dd.deliveredCount < Thresholds.R13MinSmallDelivered {
			// Without enough delivered segments the "small ones succeed" half
			// is an anecdote, and the contrast the finding rests on is not
			// established.
			continue
		}

		// Only segments larger than anything this path was shown to carry.
		// A retransmitted segment at or below the delivered size failed for
		// some other reason, and attributing it to a size limit would be the
		// rule reaching past its evidence.
		var (
			retransmits  int
			distinct     int
			failedMax    int
			failedMin    int
			firstFail    time.Time
			lastActivity time.Time
			ev           findings.Evidence
		)
		ev.Mode = findings.ModeWorst
		for _, seg := range dd.stuck {
			if seg.size <= dd.maxDeliveredSize {
				continue
			}
			distinct++
			retransmits += seg.sends
			if seg.size > failedMax {
				failedMax = seg.size
			}
			if failedMin == 0 || seg.size < failedMin {
				failedMin = seg.size
			}
			if firstFail.IsZero() || seg.firstTime.Before(firstFail) {
				firstFail = seg.firstTime
			}
			if seg.lastTime.After(lastActivity) {
				lastActivity = seg.lastTime
			}
			ev.Record(seg.firstFrame, seg.firstTime, float64(seg.sends))
		}
		if distinct == 0 || retransmits < Thresholds.R13MinLargeRetransmits {
			continue
		}

		// The stall: from the first segment that never landed to the last
		// time the sender tried. That is time the transfer spent going
		// nowhere, and it is the cost this finding reports.
		var stall float64
		if !firstFail.IsZero() && lastActivity.After(firstFail) {
			stall = lastActivity.Sub(firstFail).Seconds()
		}

		sender := fl.Key.Endpoint(flow.Direction(d))
		receiver := fl.Key.Endpoint(flow.Direction(d).Other())
		r.flows = append(r.flows, pmtuResult{
			key: fl.Key, sender: sender, receiver: receiver,
			failedSize: failedMax, smallestFailed: failedMin,
			deliveredSize: dd.maxDeliveredSize, deliveredCount: dd.deliveredCount,
			retransmits: retransmits, distinctStuck: distinct,
			stallSeconds: stall, evidence: ev,
		})
	}
}

// Emit reports each flow showing the pattern.
func (r *PMTUBlackhole) Emit(pop *Population, out *findings.Store) {
	// Deterministic order: OnFlowEnd fires in flow-eviction order, which is
	// not stable across runs.
	sort.Slice(r.flows, func(i, j int) bool {
		if r.flows[i].key.String() != r.flows[j].key.String() {
			return r.flows[i].key.String() < r.flows[j].key.String()
		}
		return r.flows[i].sender.String() < r.flows[j].sender.String()
	})

	// What the rest of the capture manages. Enough contributors are needed for
	// this to be a population rather than an anecdote — below that the rule
	// still reports the pattern, but without the comparison, because a flow
	// that fails on size with nothing to be compared against has not been
	// shown to be unusual.
	populationSize := stats.Median(r.deliveredSizes)
	peerGroup := len(r.deliveredSizes) >= Thresholds.R13MinPeerFlows && populationSize > 0

	for _, f := range r.flows {
		// Both observed sizes, never a boundary between them. The capture
		// shows that 1400 failed and 300 succeeded; where the real limit sits
		// in between is exactly what it cannot say, and "segments above N"
		// would claim to know.
		sizePhrase := fmt.Sprintf("Segments of %d bytes", f.smallestFailed)
		if f.failedSize != f.smallestFailed {
			sizePhrase = fmt.Sprintf("Segments of %d to %d bytes", f.smallestFailed, f.failedSize)
		}
		obs := fmt.Sprintf(
			"%s were retransmitted repeatedly and never acknowledged, while segments up to "+
				"%d bytes were delivered normally on the same connection. %d segment%s failed "+
				"this way across %d transmission%s.",
			sizePhrase, f.deliveredSize,
			f.distinctStuck, pluralInt(f.distinctStuck),
			f.retransmits, pluralInt(f.retransmits))

		// The comparison, and what it is against. Naming the filter matters:
		// "other flows" would leave the reader to assume it meant every flow,
		// when it means the ones that actually delivered something — the only
		// ones that have demonstrated what a working path carries.
		ratio := 1.0
		if peerGroup && f.deliveredSize > 0 {
			ratio = populationSize / float64(f.deliveredSize)
			if ratio > 1.05 {
				obs += fmt.Sprintf(
					" Other connections in this capture that delivered data carried segments of "+
						"%d bytes, so the limit appears to be on this path rather than on the sender.",
					int(populationSize))
			}
		}

		// This build does not decode ICMP, so it cannot say whether the
		// network reported the size limit back to the sender. Saying "no such
		// messages were seen" would imply it looked; saying nothing at all
		// would leave the reader to assume the absence was meaningful. See
		// the RULES.md addendum — the specification's wording assumes an ICMP
		// signal this build does not have.
		obs += " This build does not examine ICMP, so whether the network reported the size " +
			"limit back to the sender is unknown."

		quality := findings.Confirmed
		basis := ""
		if pop.Quality.OffloadArtifacts {
			// The whole signal rests on segment sizes, and on an offloaded
			// capture the sizes recorded are not the sizes that travelled.
			// Degraded, never suppressed: the transfer really did stall.
			quality = findings.Inferred
			basis = pop.Quality.OffloadBasis +
				" This check compares the size of segments that failed against the size of ones that " +
				"succeeded, so on this capture those sizes are the ones to treat carefully."
		}

		metrics := map[string]any{
			"largest_delivered_bytes": f.deliveredSize,
			"smallest_failed_bytes":   f.smallestFailed,
			"largest_failed_bytes":    f.failedSize,
			"failed_segments":         f.distinctStuck,
			"transmissions":           f.retransmits,
			"delivered_segments":      f.deliveredCount,
			"stall_seconds":           round3(f.stallSeconds),
			"peer_delivered_bytes":    int(populationSize),
			"peer_flows":              len(r.deliveredSizes),
			"deficit_ratio":           round3(ratio),
		}

		fd := &findings.Finding{
			RuleID:       "R13",
			RuleName:     "pmtu-blackhole",
			ScopeKey:     f.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: fmt.Sprintf("%s → %s", f.sender.Addr, f.receiver.Addr),
			Title: fmt.Sprintf("Large packets failing while small packets succeed — %s ↔ %s",
				f.sender.Addr, f.receiver.Addr),
			Observation: obs,
			CheckNext: fmt.Sprintf(
				"MTU along the path between %s and %s, particularly any tunnel or VPN segment. "+
					"This pattern often presents as \"the connection works but transfers hang\".",
				f.sender.Addr, f.receiver.Addr),
			Frames:       f.evidence.Frames(),
			FirstFrame:   f.evidence.FirstFrame(),
			WorstFrame:   f.evidence.WorstFrame(),
			TotalCount:   uint64(f.retransmits),
			Quality:      quality,
			QualityBasis: basis,
			Metrics:      metrics,
			// Value carries a ratio and PopulationMedian is 1.0, which is a
			// different use of these fields from R04's — worth stating rather
			// than leaving to be rediscovered as an apparent bug.
			//
			// Deviation assumes higher is worse. R13's anomaly is a shortfall:
			// this path carries *less* than its peers, so the raw metric moves
			// the wrong way and comparing it directly would score a badly
			// broken flow as unremarkable. The metric is therefore the ratio
			// itself — how many times larger the size other flows deliver is
			// than the size this one manages — against a median of 1.0, which
			// is what a flow keeping up with its peers scores.
			//
			// With no peer group the ratio stays 1.0 and deviation is neutral,
			// so the finding falls back to what it scored before any
			// comparison existed. The comparison can only add signal where one
			// genuinely exists; it can never manufacture one.
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       r.Meta().BaseWeight,
				ImpactSeconds:    f.stallSeconds,
				Scope:            scoring.ScopeFlow,
				Value:            ratio,
				PopulationMedian: 1.0,
				PeerGroup:        peerGroup,
			}),
		}
		out.Add(fd)
	}
}
