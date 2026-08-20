package rules

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
	"github.com/Proxy-IT/pcaptriage/internal/stats"
)

// RTTOutlier implements R10 · rtt-outlier.
//
// One round-trip sample per flow, grouped by the host at the far end, compared
// against the median of every sample in the capture. A host whose latency sits
// far above the rest is reported — not as a fault, because it usually is not
// one, but as a fact about where that host is or what the path to it is doing.
//
// The comparison is capture-against-itself, like every other comparative rule
// here. That is also its main limitation and the wording says so: 200ms is
// unremarkable across an ocean and alarming inside a rack, and this rule has
// no way to know which it is looking at.
//
// Per host rather than per endpoint. RULES.md offers "host or subnet"; a host
// is what its own example reports and what the check-next line sends the
// reader to investigate. Subnet grouping is not built — see the addendum.
type RTTOutlier struct {
	hosts map[netip.Addr]*rttHost
}

// rttHost accumulates the round-trip samples for one far-end host.
//
// Samples are kept individually rather than as a running mean because the
// finding has to say whether latency was steady or variable, and a mean cannot
// answer that. Bounded by the sampler's own decimation, so a host with a
// hundred thousand flows costs the same as one with a thousand.
type rttHost struct {
	addr     netip.Addr
	samples  stats.Sampler
	flows    int
	inferred int
	evidence findings.Evidence
}

// NewRTTOutlier returns the R10 detector.
func NewRTTOutlier() *RTTOutlier {
	return &RTTOutlier{hosts: make(map[netip.Addr]*rttHost)}
}

// Meta describes the rule.
func (r *RTTOutlier) Meta() Meta {
	return Meta{
		ID:         "R10",
		Name:       "rtt-outlier",
		BaseWeight: 6,
		Summary: "Round trips to one host took far longer than to every other host in the " +
			"same capture, which usually reflects distance or a congested link rather than " +
			"anything wrong with the host.",
	}
}

// NewFlow keeps no per-flow state: the round trip is already measured on the
// flow itself, and is read once at close.
func (r *RTTOutlier) NewFlow() any { return nil }

// OnPacket does nothing. flow.State computes the handshake and minimum ACK
// round trips; duplicating that work per rule would be a second implementation
// of a measurement that has to agree with R04's.
func (r *RTTOutlier) OnPacket(any, *flow.State, *capture.Packet, flow.Direction) {}

// OnFlowEnd takes one round-trip sample and files it under the far-end host.
func (r *RTTOutlier) OnFlowEnd(_ any, fl *flow.State) {
	rtt, basis := fl.NetworkRTT()
	if basis == flow.BasisNone || rtt <= 0 {
		return
	}
	server, ok := fl.ServerEndpoint()
	if !ok {
		// Without knowing which end is which there is no far end to attribute
		// the path to, and attributing it to an arbitrary side would put the
		// finding on the wrong host half the time.
		return
	}

	h := r.hosts[server.Addr]
	if h == nil {
		h = &rttHost{addr: server.Addr}
		h.evidence.Mode = findings.ModeWorst
		r.hosts[server.Addr] = h
	}
	h.flows++
	h.samples.Add(rtt.Seconds())
	if basis == flow.BasisInferred {
		h.inferred++
	}
	h.evidence.Record(fl.FirstFrame, fl.FirstSeen, rtt.Seconds())
}

// Emit compares each assessed host against the capture-wide median.
func (r *RTTOutlier) Emit(pop *Population, out *findings.Store) {
	// Every sample in the capture, which is the population an outlier is
	// outlying from. Built from the per-host medians rather than from every
	// raw sample so that one host with thousands of flows cannot become the
	// median on its own.
	var populationMedians []float64
	var assessed []*rttHost
	for _, h := range r.hosts {
		if h.flows < Thresholds.R10MinFlows {
			continue
		}
		assessed = append(assessed, h)
		populationMedians = append(populationMedians, h.samples.Percentile(0.50))
	}
	// Deterministic order: map iteration is randomised and everything below
	// this point feeds a finding.
	sort.Slice(assessed, func(i, j int) bool {
		return assessed[i].addr.Compare(assessed[j].addr) < 0
	})

	if len(assessed) < Thresholds.R10MinPeerHosts {
		if len(r.hosts) > 0 {
			out.AddNote(findings.Note{
				Kind:   "unavailable",
				RuleID: "R10",
				Text: fmt.Sprintf(
					"Not assessed: comparative network latency. %d host%s had at least %d flows with a "+
						"usable round-trip measurement, and this check compares hosts against the others "+
						"in the same capture, so fewer than %d gives it nothing to compare.",
					len(assessed), pluralInt(len(assessed)), Thresholds.R10MinFlows,
					Thresholds.R10MinPeerHosts),
			})
		}
		return
	}

	median := stats.Median(populationMedians)
	if median <= 0 {
		return
	}

	for _, h := range assessed {
		hostMedian := h.samples.Percentile(0.50)
		if hostMedian < median*Thresholds.R10PeerRatio {
			continue
		}

		// Steady or variable. The spread between the fastest and slowest
		// observed round trip, relative to this host's own median — which is
		// the distinction between a long path and a congested one, and the
		// fastest way for a reader to narrow the cause.
		lo := h.samples.Min()
		hi := h.samples.Max()
		var dispersion float64
		if hostMedian > 0 {
			dispersion = (hi - lo) / hostMedian
		}
		steady := dispersion <= Thresholds.R10SteadyDispersion

		consistency := "The elevated latency varies across the %d connections to this host rather than staying consistent."
		checkTail := " Latency that varies rather than staying steady usually indicates congestion rather than path length."
		if steady {
			consistency = "The elevated latency is consistent across all %d connections to this host rather than intermittent."
			checkTail = " Consistent rather than variable latency usually indicates path length rather than congestion."
		}

		obs := fmt.Sprintf(
			"Round-trip time of %s against a capture median of %s across %d hosts. "+consistency,
			formatDuration(seconds(hostMedian)), formatDuration(seconds(median)),
			len(assessed), h.flows)

		quality := findings.Confirmed
		basis := ""
		if h.inferred > 0 {
			// The same fallback R04 degrades for, for the same reason: without
			// a handshake the round trip is the smallest ACK turnaround seen,
			// which is a floor rather than a measurement.
			quality = findings.Inferred
			basis = fmt.Sprintf(
				"Round-trip time was taken from the minimum observed ACK round trip on %d of %d flows to this host, "+
					"because those flows began before the capture started and no handshake was available. "+
					"That approximation is a lower bound, so the true latency may be higher than reported and "+
					"is likely to look steadier than it is.",
				h.inferred, h.flows)
		}

		// Impact is the excess each measured round trip paid over what the
		// rest of the capture manages, accumulated. Elevated latency is not
		// lost time the way a stall is, but it is paid again on every
		// exchange — so the honest denominator is the excess times how often
		// the path was actually traversed. Without this the score is
		// invariant to volume, and a host contacted twice would rank with one
		// contacted ten thousand times.
		excess := hostMedian - median
		if excess < 0 {
			excess = 0
		}
		timeLost := excess * float64(h.flows)

		metrics := map[string]any{
			"rtt_ms":                   millis(seconds(hostMedian)),
			"population_median_rtt_ms": millis(seconds(median)),
			"rtt_ratio":                round3(hostMedian / median),
			"flows":                    h.flows,
			"assessed_hosts":           len(assessed),
			"steady":                   steady,
			"dispersion":               round3(dispersion),
			"excess_seconds_total":     round3(timeLost),
		}

		f := &findings.Finding{
			RuleID:       "R10",
			RuleName:     "rtt-outlier",
			ScopeKey:     h.addr.String(),
			ScopeKind:    findings.ScopeEndpoint,
			SubjectLabel: h.addr.String(),
			Title:        fmt.Sprintf("Higher network latency to one host — %s", h.addr),
			Observation:  obs,
			CheckNext: fmt.Sprintf(
				"the network path to %s — routing, physical distance, or a congested link.%s",
				h.addr, checkTail),
			Frames:       h.evidence.Frames(),
			FirstFrame:   h.evidence.FirstFrame(),
			WorstFrame:   h.evidence.WorstFrame(),
			TotalCount:   uint64(h.flows),
			Quality:      quality,
			QualityBasis: basis,
			Metrics:      metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       r.Meta().BaseWeight,
				ImpactSeconds:    timeLost,
				Scope:            scoring.ScopeFor(1, h.flows, pop.TotalHosts()),
				Value:            hostMedian,
				PopulationMedian: median,
				PeerGroup:        true,
			}),
		}
		out.Add(f)
	}
}
