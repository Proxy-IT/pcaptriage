package rules

import (
	"fmt"
	"net/netip"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
)

// AsymmetricLoss implements R08 · asymmetric-loss.
//
// Retransmission rate in one direction of a flow exceeding the reverse
// direction by ≥5×, with a minimum of 20 retransmissions to qualify.
// Directionality is disproportionately diagnostic — asymmetric routing, a
// congested uplink, or a one-way policer — and cheap to compute once both
// directions are already tracked, which the loss classifier does.
//
// R08 runs after R05 and R06 per RULES.md's interaction order: it reads the
// classifier's per-direction retransmission totals, which are the same counts
// R05 and R06 already read. Nothing here re-derives sequence state.
type AsymmetricLoss struct {
	a *lossAnalyzer
}

// NewAsymmetricLoss returns the R08 detector bound to the shared classifier.
func NewAsymmetricLoss(a *lossAnalyzer) *AsymmetricLoss {
	return &AsymmetricLoss{a: a}
}

// Meta describes R08.
func (r *AsymmetricLoss) Meta() Meta {
	return Meta{
		ID:         "R08",
		Name:       "asymmetric-loss",
		BaseWeight: 8,
		Summary:    "Retransmission rate on one flow was at least five times higher in one direction than the other, with at least 20 retransmissions — loss is not symmetric.",
	}
}

// NewFlow keeps no state of its own: R07 owns the classifier's packet path.
func (r *AsymmetricLoss) NewFlow() any { return nil }

// OnPacket does nothing; classification happens once, in the shared classifier.
func (r *AsymmetricLoss) OnPacket(any, *flow.State, *capture.Packet, flow.Direction) {}

// OnFlowEnd does nothing; the classifier retires its own state.
func (r *AsymmetricLoss) OnFlowEnd(any, *flow.State) {}

// Emit produces one finding per flow whose loss is asymmetric between
// directions, and an unavailable note per flow where only one direction was
// captured — a common consequence of a one-way SPAN configuration, where the
// comparison this rule makes cannot be performed at all.
func (r *AsymmetricLoss) Emit(pop *Population, out *findings.Store) {
	results := r.a.sortedResults()

	// First pass: which flows qualify, and the scope that follows from how
	// many hosts show it — the same shape R05 uses. Scope answers "how much of
	// the capture does this touch", which is a question about the whole
	// population of qualifying flows, not about any one of them.
	type qualified struct {
		res    *lossFlowResult
		fwd    *lossDirResult
		rev    *lossDirResult
		fwdDir flow.Direction
	}
	var qualifying []qualified
	var oneWayWithRetrans int
	affectedHosts := make(map[netip.Addr]bool)

	for _, res := range results {
		a, b := &res.dir[flow.DirAToB], &res.dir[flow.DirBToA]

		if res.oneWay {
			// Only one direction was captured, so there is no reverse-direction
			// rate to compare against — the comparison this rule makes cannot
			// be performed, not merely that it found nothing.
			if a.retrans+b.retrans > 0 {
				oneWayWithRetrans++
			}
			continue
		}

		fwd, rev, fwdDir, ok := worseDirection(a, b)
		if !ok {
			continue
		}
		qualifying = append(qualifying, qualified{res, fwd, rev, fwdDir})
		affectedHosts[res.key.Endpoint(fwdDir).Addr] = true
	}

	scope := scoring.ScopeFor(len(affectedHosts), len(qualifying), pop.TotalHosts())

	for _, q := range qualifying {
		res, fwd, rev, fwdDir := q.res, q.fwd, q.rev, q.fwdDir
		sender := res.key.Endpoint(fwdDir).Addr
		receiver := res.key.Endpoint(fwdDir.Other()).Addr

		fwdRate := rate(fwd.retrans, fwd.dataSegments)
		revRate := rate(rev.retrans, rev.dataSegments)

		// Specified wording, parameterised. RULES.md R08:
		//
		//   4.1% of segments retransmitted client-to-server, against 0.05%
		//   server-to-client on the same connection. Loss is not symmetric.
		//   Check next: something specific to the forward path — asymmetric
		//   routing, a congested uplink, or a policer applied in one
		//   direction. Symmetric loss would point at the shared path
		//   instead.
		//
		// The role words ("client-to-server") are used only when the
		// handshake or first-data deduction established which side is which
		// — the same basis R01's wording already depends on. A flow with no
		// established server (both sides midstream) states the same numbers
		// by address and direction instead, since "client" and "server" would
		// be a claim the capture cannot support.
		title := fmt.Sprintf("Loss in one direction only — %s → %s", sender, receiver)
		var obs string
		if res.serverKnown {
			fwdRole, revRole := "client-to-server", "server-to-client"
			if fwdDir == res.serverDir {
				fwdRole, revRole = "server-to-client", "client-to-server"
			}
			obs = fmt.Sprintf(
				"%s of segments retransmitted %s, against %s %s on the same connection. Loss is not symmetric.",
				formatPercent(fwdRate), fwdRole, formatPercent(revRate), revRole)
		} else {
			obs = fmt.Sprintf(
				"%s of segments retransmitted %s → %s, against %s %s → %s on the same connection. Loss is not symmetric.",
				formatPercent(fwdRate), sender, receiver,
				formatPercent(revRate), receiver, sender)
		}

		quality := findings.Confirmed
		basis := ""
		if pop.Quality.KernelDropsSignificant {
			quality = findings.Inferred
			basis = pop.Quality.KernelDropBasis
		}

		frames := mergeFrames(directionRetransFrames(fwd), nil)
		first := directionFirstFrame(fwd)
		worst := directionWorstFrame(fwd)
		if worst == 0 {
			worst = first
		}
		packets := directionRetransPackets(fwd)

		f := &findings.Finding{
			RuleID:       "R08",
			RuleName:     "asymmetric-loss",
			ScopeKey:     res.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: fmt.Sprintf("%s → %s", sender, receiver),
			Title:        title,
			Observation:  obs,
			CheckNext:    "something specific to the forward path — asymmetric routing, a congested uplink, or a policer applied in one direction. Symmetric loss would point at the shared path instead.",
			Frames:       frames,
			FirstFrame:   first,
			WorstFrame:   worst,
			TotalCount:   fwd.retrans,
			Quality:      quality,
			QualityBasis: basis,
			Packets:      finalisePackets(packets, pop.CaptureStart),
			Metrics: map[string]any{
				"forward_retrans_rate_percent": round3(fwdRate * 100),
				"reverse_retrans_rate_percent": round3(revRate * 100),
				"forward_retransmissions":      fwd.retrans,
				"reverse_retransmissions":      rev.retrans,
				"forward_direction":            fmt.Sprintf("%s -> %s", sender, receiver),
				"server_direction_known":       res.serverKnown,
				"flow":                         res.key.String(),
			},
			// Deviation here is the ratio the finding is actually reporting —
			// this direction's rate against the reverse direction's, the same
			// ≥5x comparison the rule condition tests. Reusing the population
			// median machinery this way is deliberate: RULES.md's deviation
			// factor already means "ratio to the thing this finding is
			// compared against", and for R08 that thing is stated in the
			// wording itself, not drawn from other flows. A perfectly clean
			// reverse direction (median <= 0) reads as the top of the band,
			// same as every other rule's zero-baseline case.
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       8,
				Scope:            scope,
				Value:            rate(fwd.retrans, fwd.dataSegments),
				PopulationMedian: rate(rev.retrans, rev.dataSegments),
				PeerGroup:        true,
				Proximate:        res.proximate,
			}),
		}
		out.Add(f)
	}

	if oneWayWithRetrans > 0 {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R08",
			Text: fmt.Sprintf(
				"Not assessed: directional loss comparison on %d flow%s captured in one direction only. "+
					"This is a common consequence of a one-way SPAN or mirror configuration; "+
					"asymmetric-loss detection requires both directions of a connection.",
				oneWayWithRetrans, pluralInt(oneWayWithRetrans)),
		})
	}
}

// worseDirection picks which direction is the "forward" one to report:
// whichever direction both qualifies on its own (≥20 retransmissions) and
// exceeds the other by the ratio threshold. Returns ok=false if neither
// direction qualifies.
func worseDirection(a, b *lossDirResult) (worse, better *lossDirResult, dir flow.Direction, ok bool) {
	if qualifiesAsymmetric(a, b) {
		return a, b, flow.DirAToB, true
	}
	if qualifiesAsymmetric(b, a) {
		return b, a, flow.DirBToA, true
	}
	return nil, nil, 0, false
}

// qualifiesAsymmetric reports whether fwd's retransmission count and its
// ratio against rev clear R08's thresholds.
func qualifiesAsymmetric(fwd, rev *lossDirResult) bool {
	if fwd.retrans < uint64(Thresholds.R08MinRetransmissions) {
		return false
	}
	fwdRate := rate(fwd.retrans, fwd.dataSegments)
	revRate := rate(rev.retrans, rev.dataSegments)
	if revRate == 0 {
		// Any retransmission rate against a perfectly clean reverse direction
		// is asymmetric by construction, provided the minimum count is met.
		return fwdRate > 0
	}
	return fwdRate >= revRate*Thresholds.R08MinRatio
}

func rate(n, of uint64) float64 {
	if of == 0 {
		return 0
	}
	return float64(n) / float64(of)
}

// directionRetransFrames, directionFirstFrame, directionWorstFrame and
// directionRetransPackets pool a direction's RTO, fast and unclassified
// evidence into one representative set — R08 is about the rate, not about
// which classification produced it.
func directionRetransFrames(d *lossDirResult) []uint64 {
	return mergeFrames(mergeFrames(d.rtoFrames, d.fastFrames), nil)
}

func directionFirstFrame(d *lossDirResult) uint64 {
	return firstNonZeroMin(d.rtoFirst, d.fastFirst)
}

func directionWorstFrame(d *lossDirResult) uint64 {
	if d.rtoWorst != 0 {
		return d.rtoWorst
	}
	return d.fastWorst
}

func directionRetransPackets(d *lossDirResult) []findings.PacketRef {
	out := append(append([]findings.PacketRef(nil), d.rtoPackets...), d.fastPackets...)
	findings.SortPacketRefs(out)
	return out
}
