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

// RTORetransmission implements R05 · rto-retransmission.
//
// Retransmissions after a timeout rather than in response to duplicate ACKs:
// the sender stalled waiting for a timer, which costs hundreds of milliseconds
// where fast recovery costs one round trip. Scored on time lost to the stall,
// not on count, per the rule.
//
// R05 reads the shared loss classifier and never re-derives sequence state.
// Segments R07 reclassified as reordering are structurally invisible to it —
// that is the suppression RULES.md's interaction order requires.
type RTORetransmission struct {
	a *lossAnalyzer
}

// NewRTORetransmission returns the R05 detector bound to the shared classifier.
func NewRTORetransmission(a *lossAnalyzer) *RTORetransmission {
	return &RTORetransmission{a: a}
}

// Meta describes R05.
func (r *RTORetransmission) Meta() Meta {
	return Meta{
		ID:         "R05",
		Name:       "rto-retransmission",
		BaseWeight: 7,
		Summary:    "Segments were retransmitted after a timer-shaped quiet gap with no duplicate ACKs asking for them — the sender stalled waiting for a timeout.",
	}
}

// NewFlow keeps no state of its own: R07 owns the classifier's packet path.
func (r *RTORetransmission) NewFlow() any { return nil }

// OnPacket does nothing; classification happens once, in the shared classifier.
func (r *RTORetransmission) OnPacket(any, *flow.State, *capture.Packet, flow.Direction) {}

// OnFlowEnd does nothing; the classifier retires its own state.
func (r *RTORetransmission) OnFlowEnd(any, *flow.State) {}

// Emit produces one finding per flow with timeout-driven retransmissions, on
// the direction that lost more time.
func (r *RTORetransmission) Emit(pop *Population, out *findings.Store) {
	results := r.a.sortedResults()

	// Population baseline: per-direction retransmission rates, with every
	// clean direction counted as zero.
	median := stats.MedianWithZeros(r.a.dirRetransRates, r.a.dirsWithData)
	peerGroup := r.a.dirsWithData >= 2

	// Scope needs the affected hosts before any finding is written.
	affectedHosts := make(map[netip.Addr]bool)
	qualifying := 0
	for _, res := range results {
		if d, ok := worstRTODirection(res); ok {
			affectedHosts[res.key.Endpoint(d).Addr] = true
			qualifying++
		}
	}
	scope := scoring.ScopeFor(len(affectedHosts), qualifying, pop.TotalHosts())

	for _, res := range results {
		d, ok := worstRTODirection(res)
		if !ok {
			continue
		}
		dr := &res.dir[d]
		sender := res.key.Endpoint(d).Addr
		receiver := res.key.Endpoint(d.Other()).Addr

		var rate float64
		if dr.dataSegments > 0 {
			rate = float64(dr.retrans) / float64(dr.dataSegments)
		}

		// Specified wording, parameterised. RULES.md R05:
		//
		//   Timeout-driven retransmissions — 10.1.1.5 → 10.3.3.2
		//   34 segments retransmitted after timeout, costing 6.1s of transfer
		//   time. Retry intervals doubled each attempt, indicating the sender
		//   received no acknowledgement at all rather than recovering quickly.
		//   Retransmission rate on this path is 4.2% against a capture-wide
		//   median of 0.1%.
		//   Check next: sustained loss on the path between these hosts. [...]
		//
		// The backoff sentence is stated only when doubling was observed, and
		// the median clause only when a peer group exists to take one from.
		title := fmt.Sprintf("Timeout-driven retransmissions — %s → %s", sender, receiver)

		obs := fmt.Sprintf("%d segment%s retransmitted after timeout, costing %s of transfer time.",
			dr.rto, plural(dr.rto), formatDuration(dr.rtoTimeLost))
		if dr.backoffObserved {
			obs += " Retry intervals doubled each attempt, indicating the sender received no acknowledgement at all rather than recovering quickly."
		}
		if peerGroup {
			obs += fmt.Sprintf(" Retransmission rate on this path is %s against a capture-wide median of %s.",
				formatPercent(rate), formatPercent(median))
		} else {
			obs += fmt.Sprintf(" Retransmission rate on this path is %s; no other conversation in this capture carried data to compare against.",
				formatPercent(rate))
		}

		quality := findings.Confirmed
		basis := ""
		if pop.Quality.KernelDropsSignificant {
			// R15's gating seam: the capture host discarded enough of the
			// capture that apparent loss may be capture loss. The finding is
			// degraded, never suppressed — the loss may well be real.
			quality = findings.Inferred
			basis = pop.Quality.KernelDropBasis
		}

		metrics := map[string]any{
			"segments_retransmitted_after_timeout": dr.rto,
			"time_lost_ms":                         millis(dr.rtoTimeLost),
			"backoff_observed":                     dr.backoffObserved,
			"retrans_rate_percent":                 round3(rate * 100),
			"data_segments_direction":              dr.dataSegments,
			"direction":                            fmt.Sprintf("%s -> %s", sender, receiver),
			"flow":                                 res.key.String(),
		}
		if peerGroup {
			metrics["capture_median_rate_percent"] = round3(median * 100)
		}
		if other := &res.dir[d.Other()]; other.rto > 0 {
			metrics["opposite_direction_timeout_segments"] = other.rto
		}

		f := &findings.Finding{
			RuleID:       "R05",
			RuleName:     "rto-retransmission",
			ScopeKey:     res.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: fmt.Sprintf("%s → %s", sender, receiver),
			Title:        title,
			Observation:  obs,
			CheckNext:    "sustained loss on the path between these hosts. This is more disruptive than the fast-retransmit pattern in R06 — the sender stalled waiting for a timer rather than recovering from duplicate ACKs.",
			Frames:       dr.rtoFrames,
			FirstFrame:   dr.rtoFirst,
			WorstFrame:   dr.rtoWorst,
			TotalCount:   dr.rto,
			Quality:      quality,
			QualityBasis: basis,
			Packets:      finalisePackets(dr.rtoPackets, pop.CaptureStart),
			Metrics:      metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       7,
				ImpactSeconds:    dr.rtoTimeLost.Seconds(),
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

// worstRTODirection picks the direction to report: the one that lost more
// time, ties falling to A→B so the choice is deterministic.
func worstRTODirection(res *lossFlowResult) (flow.Direction, bool) {
	a, b := &res.dir[flow.DirAToB], &res.dir[flow.DirBToA]
	if a.rto == 0 && b.rto == 0 {
		return flow.DirAToB, false
	}
	if b.rto > 0 && (a.rto == 0 || b.rtoTimeLost > a.rtoTimeLost) {
		return flow.DirBToA, true
	}
	return flow.DirAToB, true
}
