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

// ServerResponseOutlier implements R04 · server-response-outlier.
//
// Per server:port, application response time is (last request byte → first
// response byte) − network RTT. The rule reports p50, p95 and max, and flags
// where p95 exceeds the capture-wide population median by ≥5×, or exceeds 1s
// absolute where no peer group exists.
//
// This is the "is it us or them" rule. Subtracting network RTT is what makes
// the answer separable: what is left is time spent on the server.
type ServerResponseOutlier struct {
	// servers is the retained per-endpoint aggregate. Response samples have to
	// outlive the flows that produced them, so they live here rather than in
	// the evictable packet-path tier.
	servers map[flow.Endpoint]*srvAgg

	tcpFlows      int
	assessedFlows int
	// disqualified counts flows where request and response did not alternate
	// cleanly, so pairing was not possible.
	disqualified int

	// rttSamples is every flow's network RTT, used to decide whether the
	// closing sentence about a comparable network path can be supported.
	rttSamples []float64
}

// NewServerResponseOutlier returns a fresh R04 detector.
func NewServerResponseOutlier() *ServerResponseOutlier {
	return &ServerResponseOutlier{servers: make(map[flow.Endpoint]*srvAgg)}
}

// Meta describes R04.
func (r *ServerResponseOutlier) Meta() Meta {
	return Meta{
		ID:         "R04",
		Name:       "server-response-outlier",
		BaseWeight: 8,
		Summary:    "A server:port took materially longer to begin responding than its peers in the same capture, with network round-trip time subtracted.",
	}
}

// exchange phases. A clean request/response flow cycles request → response →
// request; anything else is not a shape this rule can measure.
const (
	phaseAwaiting uint8 = iota
	phaseRequest
	phaseResponse
)

type srExchange struct {
	// raw is last request byte → first response byte, before RTT subtraction.
	raw   time.Duration
	frame uint64
	when  time.Time
}

type srFlowState struct {
	phase uint8

	lastRequestTime  time.Time
	lastRequestFrame uint64

	buffer []srExchange

	// disqualified marks a flow whose request/response pairing broke, with the
	// reason. RULES.md restricts v1 to flows where request and response
	// alternate cleanly and requires the rest be reported as unavailable
	// rather than skipped quietly.
	disqualified bool
	reason       string

	lastExchangeTime time.Time
	anyExchange      bool

	// curRequest is a rolling snapshot of the last client data packet, so that
	// when a response finally arrives the request that prompted it can still be
	// shown. Overwritten on every request; only ever kept for the worst one.
	curRequest *findings.PacketRef
	// worstRaw and the two refs below track the slowest exchange on this flow.
	// Within a flow the round trip is constant, so the slowest raw gap is also
	// the slowest once it is subtracted.
	worstRaw      time.Duration
	worstRequest  *findings.PacketRef
	worstResponse *findings.PacketRef
}

// srvAgg is the retained per-server:port aggregate.
type srvAgg struct {
	endpoint flow.Endpoint

	samples  stats.Sampler
	evidence findings.Evidence

	flows int

	// rttObserved counts contributing flows whose RTT came from a handshake;
	// rttInferred counts those that fell back to the minimum observed ACK RTT;
	// rttMissing counts those with no RTT sample at all, where nothing was
	// subtracted.
	rttObserved int
	rttInferred int
	rttMissing  int

	// minRTT is the smallest network RTT observed across contributing flows,
	// used to compare this server's network path against the capture.
	minRTT      time.Duration
	minRTTValid bool

	// The slowest exchange seen for this endpoint across every contributing
	// flow, kept so the finding can show the request and the response it
	// waited for.
	worstDelta    time.Duration
	worstRequest  *findings.PacketRef
	worstResponse *findings.PacketRef

	proximate bool
}

// NewFlow allocates R04's per-flow state.
func (r *ServerResponseOutlier) NewFlow() any {
	s := &srFlowState{phase: phaseAwaiting}
	s.buffer = make([]srExchange, 0, Thresholds.R04FlowExchangeBuffer)
	return s
}

// OnPacket runs the request/response alternation state machine.
//
// Only data segments move it. Which side is the server comes from the
// handshake where it was captured, and otherwise from which side sent data
// first, which is a deduction and is tagged as such on the finding.
func (r *ServerResponseOutlier) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*srFlowState)
	if !ok || s.disqualified {
		return
	}
	if p.PayloadLength == 0 || fl.ServerBasis == flow.BasisNone {
		return
	}

	if dir != fl.ServerDir {
		// Client data. Either it opens a request or it continues one; either
		// way the last request byte moves forward.
		s.lastRequestTime = p.Time
		s.lastRequestFrame = p.Frame
		ref := findings.SnapshotPacket(p, findings.RoleContext, "Last byte of the request")
		s.curRequest = &ref
		s.phase = phaseRequest
		return
	}

	switch s.phase {
	case phaseAwaiting:
		// The server sent data with no preceding client request. That is a
		// server-initiated stream — a protocol banner, server-sent events, or
		// a flow joined partway through a response — and it is not a
		// request/response exchange this rule can measure.
		s.disqualified = true
		s.reason = "the server sent data with no preceding client request"

	case phaseRequest:
		raw := p.Time.Sub(s.lastRequestTime)
		if raw < 0 {
			raw = 0
		}
		if len(s.buffer) >= Thresholds.R04FlowExchangeBuffer {
			r.flush(s, fl, false)
		}
		s.buffer = append(s.buffer, srExchange{raw: raw, frame: p.Frame, when: p.Time})
		s.lastExchangeTime = p.Time
		s.anyExchange = true
		s.phase = phaseResponse

		// Keep the packets for the slowest exchange only. Showing one request
		// and the response it waited for explains the measurement; showing
		// eight response frames with no requests beside them does not.
		if s.worstResponse == nil || raw > s.worstRaw {
			s.worstRaw = raw
			resp := findings.SnapshotPacket(p, findings.RoleFlagged, "")
			s.worstResponse = &resp
			s.worstRequest = s.curRequest
		}

	case phaseResponse:
		// A continuation of the response already being measured. Server-sent
		// events and streaming responses land here, which is why they do not
		// read as a series of very slow responses.
	}
}

// OnFlowEnd flushes the remaining exchanges into the retained aggregate.
func (r *ServerResponseOutlier) OnFlowEnd(fs any, fl *flow.State) {
	r.tcpFlows++

	s, ok := fs.(*srFlowState)
	if !ok {
		return
	}

	if rtt, basis := fl.NetworkRTT(); basis != flow.BasisNone {
		r.rttSamples = append(r.rttSamples, rtt.Seconds())
	}

	if s.disqualified {
		r.disqualified++
		return
	}
	if !s.anyExchange {
		return
	}

	r.assessedFlows++
	r.flush(s, fl, true)
}

// flush moves buffered exchanges into the per-server aggregate, subtracting
// the flow's network RTT.
//
// final reports the flow-end flush, which is the only point at which the
// proximity bonus can be evaluated, since a RST later in the flow would not
// have been seen at an earlier mid-flow flush.
func (r *ServerResponseOutlier) flush(s *srFlowState, fl *flow.State, final bool) {
	if len(s.buffer) == 0 && !final {
		return
	}
	server, ok := fl.ServerEndpoint()
	if !ok {
		s.buffer = s.buffer[:0]
		return
	}

	agg := r.servers[server]
	if agg == nil {
		agg = &srvAgg{endpoint: server}
		// The frames worth citing are the slowest responses, not the first.
		agg.evidence.Mode = findings.ModeWorst
		r.servers[server] = agg
	}
	if final {
		agg.flows++
	}

	rtt, basis := fl.NetworkRTT()
	if final {
		switch basis {
		case flow.BasisObserved:
			agg.rttObserved++
		case flow.BasisInferred:
			agg.rttInferred++
		default:
			agg.rttMissing++
		}
		if basis != flow.BasisNone && (!agg.minRTTValid || rtt < agg.minRTT) {
			agg.minRTT = rtt
			agg.minRTTValid = true
		}
	}

	for _, ex := range s.buffer {
		d := ex.raw - rtt
		if d < 0 {
			d = 0
		}
		agg.samples.Add(d.Seconds())
		agg.evidence.Record(ex.frame, ex.when, d.Seconds())
	}
	s.buffer = s.buffer[:0]

	// Promote this flow's slowest exchange if it beats what the endpoint has.
	// The comparison is on the delta, after each flow's own round trip has been
	// subtracted, so flows on different paths are compared fairly.
	if s.worstResponse != nil {
		d := s.worstRaw - rtt
		if d < 0 {
			d = 0
		}
		if agg.worstResponse == nil || d > agg.worstDelta {
			agg.worstDelta = d
			agg.worstRequest = s.worstRequest
			agg.worstResponse = s.worstResponse
		}
	}

	if final && fl.SawRST && !s.lastExchangeTime.IsZero() {
		gap := fl.RSTTime.Sub(s.lastExchangeTime).Seconds()
		if gap >= 0 && gap <= scoring.ProximityWindowSeconds {
			agg.proximate = true
		}
	}
}

// Emit compares every qualifying server endpoint against the capture-wide
// population and reports the outliers.
func (r *ServerResponseOutlier) Emit(pop *Population, out *findings.Store) {
	endpoints := make([]flow.Endpoint, 0, len(r.servers))
	for e := range r.servers {
		endpoints = append(endpoints, e)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Compare(endpoints[j]) < 0 })

	type srvView struct {
		agg *srvAgg
		p50 float64
		p95 float64
		max float64
	}

	var (
		qualifying []srvView
		tooFew     int
	)
	for _, e := range endpoints {
		agg := r.servers[e]
		if agg.samples.Count() < Thresholds.R04MinExchanges {
			tooFew++
			continue
		}
		qualifying = append(qualifying, srvView{
			agg: agg,
			p50: agg.samples.Percentile(0.50),
			p95: agg.samples.Percentile(0.95),
			max: agg.samples.Max(),
		})
	}

	r.emitNotes(out, tooFew, len(qualifying))

	if len(qualifying) == 0 {
		return
	}

	p95s := make([]float64, len(qualifying))
	p50s := make([]float64, len(qualifying))
	for i, v := range qualifying {
		p95s[i] = v.p95
		p50s[i] = v.p50
	}
	medianP95 := stats.Median(p95s)
	medianP50 := stats.Median(p50s)
	medianRTT := stats.Median(r.rttSamples)

	peerGroup := len(qualifying) >= Thresholds.R04MinPeerGroup

	// Which servers are outliers has to be settled before any finding is
	// built, because both the scope factor and the comparative sentence depend
	// on how many of them there are.
	outlier := make(map[flow.Endpoint]bool, len(qualifying))
	var flags []srvView
	for _, v := range qualifying {
		var isOutlier bool
		if peerGroup {
			isOutlier = medianP95 > 0 && v.p95 >= medianP95*Thresholds.R04PeerRatio
		} else {
			isOutlier = v.p95 > Thresholds.R04AbsoluteP95.Seconds()
		}
		if isOutlier {
			outlier[v.agg.endpoint] = true
			flags = append(flags, v)
		}
	}

	if len(flags) == 0 {
		return
	}

	// "The other N servers" is the population this one stood out from, which
	// is the servers that did not stand out. Including the other outliers
	// would make the comparison say that responses several seconds long are
	// the normal band here, which is the opposite of what the finding means.
	var (
		cleanCount int
		cleanMax   float64
	)
	for _, v := range qualifying {
		if outlier[v.agg.endpoint] {
			continue
		}
		cleanCount++
		if v.p95 > cleanMax {
			cleanMax = v.p95
		}
	}

	scope := scoring.ScopeFor(len(flags), len(flags), len(qualifying))

	for _, v := range flags {
		agg := v.agg

		// Specified wording, parameterised. RULES.md R04:
		//
		//   One server much slower to respond than its peers — 10.2.2.7:443
		//   Responded in 1.8s at p95 (max 4.1s) while the other 41 servers in
		//   this capture are under 40ms at p95. Measured from last request
		//   byte to first response byte, with network round-trip time
		//   subtracted — so this is time spent on the server, not on the
		//   network.
		//   Check next: application or backend dependency latency on 10.2.2.7.
		//   The network path to this host looks comparable to its peers.
		title := fmt.Sprintf("One server much slower to respond than its peers — %s", agg.endpoint)

		obs := fmt.Sprintf("Responded in %s at p95 (max %s)",
			formatDuration(seconds(v.p95)), formatDuration(seconds(v.max)))
		if peerGroup && cleanCount > 0 {
			obs += fmt.Sprintf(" while the other %d server%s in this capture are under %s at p95",
				cleanCount, pluralInt(cleanCount), formatDurationCeil(seconds(cleanMax)))
		}
		obs += ". Measured from last request byte to first response byte, with network round-trip time subtracted — so this is time spent on the server, not on the network."

		if !peerGroup {
			// RULES.md's scoring model requires the report say so where no
			// peer group exists rather than implying a comparison was made.
			obs += fmt.Sprintf(
				" Comparative ranking was unavailable: no other server endpoint in this capture had at least %d completed request/response exchanges, so the %s absolute threshold was used instead.",
				Thresholds.R04MinExchanges, formatDuration(Thresholds.R04AbsoluteP95))
		}

		checkNext := fmt.Sprintf("application or backend dependency latency on %s.", agg.endpoint.Addr)
		// The closing sentence is a claim about the network path, so it is
		// only stated where the measurement supports it.
		networkComparable := peerGroup && agg.minRTTValid && medianRTT > 0 &&
			agg.minRTT.Seconds() < medianRTT*Thresholds.R04NetworkComparableRatio
		if networkComparable {
			checkNext += " The network path to this host looks comparable to its peers."
		}

		quality := findings.Confirmed
		basis := ""
		switch {
		case agg.rttMissing > 0:
			quality = findings.Inferred
			basis = fmt.Sprintf(
				"No network round-trip sample was available on %d of %d contributing flow%s, so nothing was subtracted for those; the figures above are upper bounds for them.",
				agg.rttMissing, agg.flows, pluralInt(agg.flows))
		case agg.rttInferred > 0:
			// RULES.md R04 degradation: RTT subtraction is inferred on
			// midstream flows, since the handshake baseline is unavailable.
			quality = findings.Inferred
			basis = fmt.Sprintf(
				"Network round-trip time was taken from the minimum observed ACK round trip on %d of %d contributing flow%s, because those flows began before the capture started and no handshake was available. That approximation can overestimate the round trip and so understate the server time.",
				agg.rttInferred, agg.flows, pluralInt(agg.flows))
		}

		metrics := map[string]any{
			"exchanges":                agg.samples.Count(),
			"p50_ms":                   millis(seconds(v.p50)),
			"p95_ms":                   millis(seconds(v.p95)),
			"max_ms":                   millis(seconds(v.max)),
			"contributing_flows":       agg.flows,
			"peer_servers":             cleanCount,
			"outlier_servers":          len(flags),
			"assessed_servers":         len(qualifying),
			"population_median_p95_ms": millis(seconds(medianP95)),
			"population_median_p50_ms": millis(seconds(medianP50)),
			"peer_group":               peerGroup,
			"network_rtt_ms":           millis(agg.minRTT),
			"population_median_rtt_ms": millis(seconds(medianRTT)),
			"percentiles_decimated":    agg.samples.Decimated(),
		}
		if peerGroup && medianP95 > 0 {
			metrics["p95_ratio_to_population_median"] = round3(v.p95 / medianP95)
		}
		if cleanCount > 0 {
			metrics["peer_max_p95_ms"] = millis(seconds(cleanMax))
		}

		// Time lost is the excess over what the population manages, across
		// every exchange, which is what the impact factor is scaled on.
		baseline := medianP50
		if !peerGroup {
			baseline = Thresholds.R04AbsoluteP95.Seconds()
		}
		excess := (v.p50 - baseline) * float64(agg.samples.Count())
		if excess < 0 {
			excess = 0
		}

		// The slowest exchange, as two rows: what was asked, and how long the
		// first byte back took. The gap between the timestamps is the
		// measurement the finding is reporting.
		var packets []findings.PacketRef
		if agg.worstResponse != nil {
			resp := *agg.worstResponse
			resp.Note = fmt.Sprintf(
				"First byte of the response — %s after the request, %s once the %s network round trip is subtracted",
				formatDuration(resp.Time.Sub(reqTime(agg))),
				formatDuration(agg.worstDelta),
				formatDuration(agg.minRTT))
			if agg.worstRequest != nil {
				packets = append(packets, *agg.worstRequest)
			}
			packets = append(packets, resp)
			findings.SortPacketRefs(packets)
		}

		out.Add(&findings.Finding{
			RuleID:       "R04",
			RuleName:     "server-response-outlier",
			ScopeKey:     agg.endpoint.String(),
			ScopeKind:    findings.ScopeEndpoint,
			SubjectLabel: agg.endpoint.String(),
			Title:        title,
			Observation:  obs,
			CheckNext:    checkNext,
			Frames:       agg.evidence.Frames(),
			FirstFrame:   agg.evidence.FirstFrame(),
			WorstFrame:   agg.evidence.WorstFrame(),
			TotalCount:   agg.samples.Count(),
			Quality:      quality,
			QualityBasis: basis,
			Packets:      finalisePackets(packets, pop.CaptureStart),
			Metrics:      metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       8,
				ImpactSeconds:    excess,
				Scope:            scope,
				Value:            v.p95,
				PopulationMedian: medianP95,
				PeerGroup:        peerGroup,
				Proximate:        agg.proximate,
			}),
		})
	}
}

// emitNotes records what this rule could not assess. These are rendered in the
// report rather than dropped: a report that looks clean because half the
// checks never ran will close a ticket on a fault that is still live.
func (r *ServerResponseOutlier) emitNotes(out *findings.Store, tooFew, qualifying int) {
	if r.disqualified > 0 {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R04",
			Text: fmt.Sprintf(
				"Not assessed: server response time on %d of %d TCP flow%s. Request and response did not alternate cleanly on those flows — the server sent data with no preceding client request — so request/response pairing was not possible. Server-sent events, protocol banners and flows joined partway through a response all take this shape.",
				r.disqualified, r.tcpFlows, pluralInt(r.tcpFlows)),
		})
	}
	if tooFew > 0 {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R04",
			Text: fmt.Sprintf(
				"Not assessed: server response time for %d server endpoint%s with fewer than %d completed request/response exchanges. Percentiles over that few samples would not describe a distribution.",
				tooFew, pluralInt(tooFew), Thresholds.R04MinExchanges),
		})
	}
	if qualifying > 0 && qualifying < Thresholds.R04MinPeerGroup {
		out.AddNote(findings.Note{
			Kind:   "info",
			RuleID: "R04",
			Text: fmt.Sprintf(
				"Comparative ranking was unavailable for server response time: %d server endpoint had enough exchanges to assess, which is not a peer group. The %s absolute threshold was used instead of a comparison against the capture.",
				qualifying, formatDuration(Thresholds.R04AbsoluteP95)),
		})
	}
}

// reqTime returns the timestamp of the request behind the slowest exchange,
// falling back to the response's own time where the request was not captured
// so the rendered gap is zero rather than nonsense.
func reqTime(agg *srvAgg) time.Time {
	if agg.worstRequest != nil {
		return agg.worstRequest.Time
	}
	if agg.worstResponse != nil {
		return agg.worstResponse.Time
	}
	return time.Time{}
}

// seconds converts a float64 count of seconds back to a Duration for
// formatting.
func seconds(v float64) time.Duration {
	return time.Duration(v * float64(time.Second))
}
