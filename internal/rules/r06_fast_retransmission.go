package rules

import (
	"fmt"
	"net/netip"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
	"github.com/Proxy-IT/pcaptriage/internal/stats"
)

// FastRetransmission implements R06 · fast-retransmission.
//
// Retransmissions triggered by three or more duplicate ACKs: packet loss the
// connection recovered from quickly. Deliberately lower-weighted than R05 —
// fast retransmit is TCP working correctly, and a fraction of a percent of it
// is a healthy internet path that must never outrank a real stall.
//
// Like R05, this rule reads the shared loss classifier; segments R07
// reclassified as reordering never reach it.
type FastRetransmission struct {
	a *lossAnalyzer
}

// NewFastRetransmission returns the R06 detector bound to the shared classifier.
func NewFastRetransmission(a *lossAnalyzer) *FastRetransmission {
	return &FastRetransmission{a: a}
}

// Meta describes R06.
func (r *FastRetransmission) Meta() Meta {
	return Meta{
		ID:         "R06",
		Name:       "fast-retransmission",
		BaseWeight: 4,
		Summary:    "Segments were retransmitted after three or more duplicate ACKs — packet loss the connection recovered from quickly.",
	}
}

// NewFlow keeps no state of its own: R07 owns the classifier's packet path.
func (r *FastRetransmission) NewFlow() any { return nil }

// OnPacket does nothing; classification happens once, in the shared classifier.
func (r *FastRetransmission) OnPacket(any, *flow.State, *capture.Packet, flow.Direction) {}

// OnFlowEnd does nothing; the classifier retires its own state.
func (r *FastRetransmission) OnFlowEnd(any, *flow.State) {}

// Emit produces one finding per flow with fast retransmissions.
func (r *FastRetransmission) Emit(pop *Population, out *findings.Store) {
	results := r.a.sortedResults()

	median := stats.MedianWithZeros(r.a.flowFastRates, r.a.flowsWithData)
	peerGroup := r.a.flowsWithData >= 2

	// Scope per RULES.md's table: a single affected flow is flow scope, full
	// stop — a flow has two endpoints, but counting both as "affected hosts"
	// would promote every path condition to multi-host. Host counting only
	// applies once several flows show the condition.
	affectedHosts := make(map[netip.Addr]bool)
	qualifying := 0
	for _, res := range results {
		if res.totalFast() > 0 {
			affectedHosts[res.key.A.Addr] = true
			affectedHosts[res.key.B.Addr] = true
			qualifying++
		}
	}
	scope := scoring.ScopeFlow
	if qualifying > 1 {
		scope = scoring.ScopeFor(len(affectedHosts), qualifying, pop.TotalHosts())
	}

	for _, res := range results {
		fast := res.totalFast()
		if fast == 0 {
			continue
		}

		var rate float64
		if data := res.totalDataSegments(); data > 0 {
			rate = float64(fast) / float64(data)
		}
		cost := res.dir[0].fastTimeCost + res.dir[1].fastTimeCost

		a, b := res.key.A.Addr, res.key.B.Addr

		// Specified wording, parameterised. RULES.md R06:
		//
		//   Packet loss with fast recovery — 10.1.1.5 ↔ 10.3.3.2
		//   210 segments recovered via fast retransmit (0.9% of segments on
		//   this path, against a capture median of 0.1%). Recovery was quick
		//   in each case; total time cost approximately 340ms.
		//   Check next: low-level loss on this path. Worth noting but unlikely
		//   to be the cause of a user-visible problem on its own.
		//
		// The median clause is stated only when a peer group exists to take
		// one from.
		title := fmt.Sprintf("Packet loss with fast recovery — %s ↔ %s", a, b)

		rateClause := fmt.Sprintf("%s of segments on this path", formatPercent(rate))
		if peerGroup {
			rateClause += fmt.Sprintf(", against a capture median of %s", formatPercent(median))
		}
		obs := fmt.Sprintf(
			"%d segment%s recovered via fast retransmit (%s). Recovery was quick in each case; total time cost approximately %s.",
			fast, plural(fast), rateClause, formatDuration(cost))

		quality := findings.Confirmed
		basis := ""
		if pop.Quality.KernelDropsSignificant {
			// R15's gating seam, same as R05: degraded, never suppressed.
			quality = findings.Inferred
			basis = pop.Quality.KernelDropBasis
		}

		frames := mergeFrames(res.dir[0].fastFrames, res.dir[1].fastFrames)
		first := firstNonZeroMin(res.dir[0].fastFirst, res.dir[1].fastFirst)
		worst := res.dir[0].fastWorst
		if res.dir[1].fastTimeCost > res.dir[0].fastTimeCost {
			worst = res.dir[1].fastWorst
		}
		if worst == 0 {
			worst = first
		}

		packets := append(append([]findings.PacketRef(nil),
			res.dir[0].fastPackets...), res.dir[1].fastPackets...)
		findings.SortPacketRefs(packets)

		metrics := map[string]any{
			"segments_fast_retransmitted": fast,
			"fast_rate_percent":           round3(rate * 100),
			"data_segments":               res.totalDataSegments(),
			"time_cost_ms":                millis(cost),
			"flow":                        res.key.String(),
		}
		if peerGroup {
			metrics["capture_median_rate_percent"] = round3(median * 100)
		}

		f := &findings.Finding{
			RuleID:       "R06",
			RuleName:     "fast-retransmission",
			ScopeKey:     res.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: fmt.Sprintf("%s ↔ %s", a, b),
			Title:        title,
			Observation:  obs,
			CheckNext:    "low-level loss on this path. Worth noting but unlikely to be the cause of a user-visible problem on its own.",
			Frames:       frames,
			FirstFrame:   first,
			WorstFrame:   worst,
			TotalCount:   fast,
			Quality:      quality,
			QualityBasis: basis,
			Packets:      finalisePackets(packets, pop.CaptureStart),
			Metrics:      metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       4,
				ImpactSeconds:    cost.Seconds(),
				Scope:            scope,
				Value:            rate,
				PopulationMedian: median,
				PeerGroup:        peerGroup,
				Proximate:        res.proximate,
			}),
		}
		out.Add(f)
	}
}
