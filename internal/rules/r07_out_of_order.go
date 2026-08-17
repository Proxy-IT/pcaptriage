package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
)

// OutOfOrderNotLoss implements R07 · out-of-order-not-loss.
//
// This rule exists to prevent other rules being wrong: segments that arrived
// out of sequence within the reorder window, with IP IDs consistent with their
// original transmission order, are reordering on the path — a NIC offload or
// multipath artifact — not retransmissions. Misreading them as loss sends
// someone to investigate the network for a setting.
//
// R07 owns the loss classifier's packet path. Its position ahead of R05 and
// R06 in the detector list is RULES.md's interaction order made literal, and
// the suppression it performs is structural: a segment it reclassifies lands
// in the reorder bucket and never reaches the buckets R05 and R06 read.
type OutOfOrderNotLoss struct {
	a *lossAnalyzer
}

// NewOutOfOrderNotLoss returns the R07 detector bound to the shared classifier.
func NewOutOfOrderNotLoss(a *lossAnalyzer) *OutOfOrderNotLoss {
	return &OutOfOrderNotLoss{a: a}
}

// Meta describes R07.
func (r *OutOfOrderNotLoss) Meta() Meta {
	return Meta{
		ID:         "R07",
		Name:       "out-of-order-not-loss",
		BaseWeight: 5,
		Summary:    "Segments arrived out of sequence within milliseconds and in original transmission order by IP ID — reordering on the path, not packet loss.",
	}
}

// NewFlow allocates the shared loss-classifier state. R07 is the one detector
// in the loss cluster that does; R05 and R06 read what it classified.
func (r *OutOfOrderNotLoss) NewFlow() any { return r.a.newFlow() }

// OnPacket feeds the shared classifier.
func (r *OutOfOrderNotLoss) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	if s, ok := fs.(*lossFlowState); ok {
		r.a.onPacket(s, fl, p, dir)
	}
}

// OnFlowEnd retires the flow into the classifier's retained tier.
func (r *OutOfOrderNotLoss) OnFlowEnd(fs any, fl *flow.State) {
	if s, ok := fs.(*lossFlowState); ok {
		r.a.onFlowEnd(s, fl)
	}
}

// Emit produces one finding per flow that showed reordering.
func (r *OutOfOrderNotLoss) Emit(pop *Population, out *findings.Store) {
	for _, res := range r.a.sortedResults() {
		reorder := res.totalReorder()
		if reorder == 0 {
			continue
		}

		// Merged across directions: the repetition cap allows one finding per
		// rule per flow, and reordering is a property of the path.
		frames := mergeFrames(res.dir[0].reorderFrames, res.dir[1].reorderFrames)
		first := firstNonZeroMin(res.dir[0].reorderFirst, res.dir[1].reorderFirst)
		worst := res.dir[0].reorderWorst
		maxDelta := res.dir[0].maxReorderDelta
		if res.dir[1].maxReorderDelta > maxDelta {
			maxDelta = res.dir[1].maxReorderDelta
			worst = res.dir[1].reorderWorst
		}
		if worst == 0 {
			worst = first
		}

		// The rate these segments would have been reported as, had they been
		// read as retransmissions — the wrongness this rule prevents.
		var wouldBeRate float64
		if data := res.totalDataSegments(); data > 0 {
			wouldBeRate = float64(reorder) / float64(data)
		}

		a, b := res.key.A.Addr, res.key.B.Addr
		title := fmt.Sprintf("Out-of-order delivery, not packet loss — %s ↔ %s", a, b)

		// Specified wording, parameterised. RULES.md R07:
		//
		//   156 segments arrived out of sequence with sub-millisecond gaps and
		//   consistent IP ID ordering. These were not retransmissions and no
		//   data was lost. Without this reclassification they would appear as
		//   a 2.1% loss rate.
		//
		// "sub-millisecond gaps" is stated only when the gaps measured were;
		// otherwise the observed bound is stated instead, because the sentence
		// must stay true of the capture it describes.
		gapPhrase := "sub-millisecond gaps"
		if maxDelta >= time.Millisecond {
			gapPhrase = fmt.Sprintf("gaps under %s", formatDurationCeil(maxDelta))
		}
		ipidClause := " and consistent IP ID ordering"
		if res.ipv6 {
			// IPv6 has no IP ID field; the claim cannot be made.
			ipidClause = ""
		}
		obs := fmt.Sprintf(
			"%d segment%s arrived out of sequence with %s%s. These were not retransmissions and no data was lost. Without this reclassification they would appear as a %s loss rate.",
			reorder, plural(reorder), gapPhrase, ipidClause, formatPercent(wouldBeRate))

		quality := findings.Confirmed
		basis := ""
		if res.ipv6 {
			quality = findings.Inferred
			basis = "IPv6 carries no IP ID field, so original transmission order is inferred from packet timing alone."
		}

		packets := append(append([]findings.PacketRef(nil),
			res.dir[0].reorderPackets...), res.dir[1].reorderPackets...)
		findings.SortPacketRefs(packets)

		f := &findings.Finding{
			RuleID:       "R07",
			RuleName:     "out-of-order-not-loss",
			ScopeKey:     res.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: fmt.Sprintf("%s ↔ %s", a, b),
			Title:        title,
			Observation:  obs,
			CheckNext:    "usually multipath routing, LACP hashing, or receive-side scaling on the capture host. Not a fault in itself, but it can degrade TCP throughput.",
			Frames:       frames,
			FirstFrame:   first,
			WorstFrame:   worst,
			TotalCount:   reorder,
			Quality:      quality,
			QualityBasis: basis,
			Packets:      finalisePackets(packets, pop.CaptureStart),
			Metrics: map[string]any{
				"reordered_segments":         reorder,
				"data_segments":              res.totalDataSegments(),
				"would_be_loss_rate_percent": round3(wouldBeRate * 100),
				"max_gap_ms":                 millis(maxDelta),
				"ip_id_checked":              !res.ipv6,
				"flow":                       res.key.String(),
			},
			// No time was lost and no peer comparison applies: reordering is
			// reported for what it prevents, not for what it costs. The score
			// lands in the informational band by construction.
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight: 5,
				Scope:      scoring.ScopeFlow,
				PeerGroup:  false,
			}),
		}
		out.Add(f)
	}
}

// mergeFrames combines two representative frame sets under the frame cap.
func mergeFrames(a, b []uint64) []uint64 {
	merged := make([]uint64, 0, len(a)+len(b))
	merged = append(merged, a...)
	merged = append(merged, b...)
	sort.Slice(merged, func(i, j int) bool { return merged[i] < merged[j] })
	// Deduplicate, then cap.
	out := merged[:0]
	var last uint64
	for i, f := range merged {
		if i > 0 && f == last {
			continue
		}
		out = append(out, f)
		last = f
	}
	if len(out) > findings.MaxFrames {
		out = out[:findings.MaxFrames]
	}
	return out
}

// firstNonZeroMin returns the smaller non-zero of two frame numbers.
func firstNonZeroMin(a, b uint64) uint64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}
