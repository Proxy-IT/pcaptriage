package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
	"github.com/Proxy-IT/pcaptriage/internal/stats"
)

// ConnectionChurn implements R14 · connection-churn.
//
// Many short connections to the same server:port from the same client, where
// each one pays the handshake cost afresh instead of reusing an open
// connection. Functionally working; the overhead is what the finding is about.
//
// Lifetime is measured from handshake to close, so a flow already established
// when the capture began cannot contribute one. Those are excluded and the
// proportion is reported, the same midstream-awareness R01 and R04 apply.
type ConnectionChurn struct {
	// endpoints is the retained per-server:port aggregate.
	endpoints map[flow.Endpoint]*churnAgg
}

// NewConnectionChurn returns a fresh R14 detector.
func NewConnectionChurn() *ConnectionChurn {
	return &ConnectionChurn{endpoints: make(map[flow.Endpoint]*churnAgg)}
}

// Meta describes R14.
func (r *ConnectionChurn) Meta() Meta {
	return Meta{
		ID:         "R14",
		Name:       "connection-churn",
		BaseWeight: 5,
		Summary:    "The same client opened and closed many short-lived connections to one server:port instead of reusing them, paying the handshake cost each time.",
	}
}

// churnFlowState is R14's per-flow packet-path state.
type churnFlowState struct {
	// sawHandshake marks a connection whose opening was observed, which is
	// what makes its lifetime measurable at all.
	sawHandshake bool
	synTime      time.Time
	synFrame     uint64
	initiator    flow.Direction
	haveInit     bool
	synRef       *findings.PacketRef

	handshakeRTT      time.Duration
	handshakeRTTValid bool
}

// churnConn is one completed short connection.
type churnConn struct {
	lifetime time.Duration
	frame    uint64
	when     time.Time
}

// churnAgg is the retained per-server:port aggregate.
type churnAgg struct {
	endpoint flow.Endpoint

	// lifetimes are the observed connection lifetimes, sampled rather than
	// kept whole: a capture with a hundred thousand short connections must not
	// grow this without bound, and a median only needs a representative
	// sample.
	lifetimes stats.Sampler
	conns     uint64
	clients   map[netip.Addr]bool

	// midstream counts connections to this endpoint whose opening was not
	// observed, so their lifetime could not be measured.
	midstream uint64

	// setupCost is the mean observed handshake round trip, which is what the
	// wording quantifies as per-request overhead.
	setupTotal time.Duration
	setupCount uint64

	first, last time.Time
	evidence    findings.Evidence
	packets     []findings.PacketRef
}

// NewFlow allocates R14's per-flow state.
func (r *ConnectionChurn) NewFlow() any { return &churnFlowState{} }

// OnPacket folds one packet into the churn state.
func (r *ConnectionChurn) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*churnFlowState)
	if !ok {
		return
	}

	syn := p.AnyFlag(capture.FlagSYN)
	ack := p.AnyFlag(capture.FlagACK)

	if syn && !ack && !s.haveInit {
		s.haveInit = true
		s.initiator = dir
		s.sawHandshake = true
		s.synTime = p.Time
		s.synFrame = p.Frame
		ref := findings.SnapshotPacket(p, findings.RoleFlagged,
			"Connection opened", "TCP SYN")
		s.synRef = &ref
	}
}

// OnFlowEnd folds a completed connection into its server endpoint's aggregate.
func (r *ConnectionChurn) OnFlowEnd(fs any, fl *flow.State) {
	s, ok := fs.(*churnFlowState)
	if !ok {
		return
	}

	// Which side is the server: the handshake says so when it was observed,
	// and the flow's own deduction covers the rest.
	var server, client flow.Endpoint
	if s.haveInit {
		server = fl.Key.Endpoint(s.initiator.Other())
		client = fl.Key.Endpoint(s.initiator)
	} else if ep, known := fl.ServerEndpoint(); known {
		server = ep
		client = fl.Key.Endpoint(0)
		if client == server {
			client = fl.Key.Endpoint(1)
		}
	} else {
		return
	}

	agg := r.endpoints[server]
	if agg == nil {
		agg = &churnAgg{endpoint: server, clients: make(map[netip.Addr]bool)}
		agg.evidence.Mode = findings.ModeFirst
		r.endpoints[server] = agg
	}
	agg.clients[client.Addr] = true

	if !s.sawHandshake {
		// Established before the capture began: its lifetime started somewhere
		// this file cannot see, so it cannot be measured — only counted, and
		// disclosed.
		agg.midstream++
		return
	}

	lifetime := fl.LastSeen.Sub(s.synTime)
	if lifetime < 0 {
		return
	}

	agg.conns++
	agg.lifetimes.Add(lifetime.Seconds())
	agg.evidence.Record(s.synFrame, s.synTime, 0)

	if rtt, basis := fl.NetworkRTT(); basis == flow.BasisObserved {
		agg.setupTotal += rtt
		agg.setupCount++
	}

	if agg.first.IsZero() || s.synTime.Before(agg.first) {
		agg.first = s.synTime
	}
	if fl.LastSeen.After(agg.last) {
		agg.last = fl.LastSeen
	}

	if len(agg.packets) < findings.MaxFrames && s.synRef != nil {
		agg.packets = append(agg.packets, *s.synRef)
	}
}

// Emit produces one finding per server:port showing connection churn.
func (r *ConnectionChurn) Emit(pop *Population, out *findings.Store) {
	eps := make([]flow.Endpoint, 0, len(r.endpoints))
	for e := range r.endpoints {
		eps = append(eps, e)
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].Compare(eps[j]) < 0 })

	// Endpoints whose connections were mostly established before the capture
	// began cannot be assessed, and say so rather than being dropped.
	var unassessable []string

	type candidate struct {
		ep     flow.Endpoint
		agg    *churnAgg
		median float64
	}
	var qualifying []candidate
	hosts := make(map[netip.Addr]bool)

	for _, e := range eps {
		agg := r.endpoints[e]

		if agg.conns < uint64(Thresholds.R14MinConnections) {
			// Not enough measurable connections. If that is because most were
			// already open when the capture started, the check could not run
			// rather than having run and found nothing — a distinction the
			// report has to keep.
			if agg.midstream+agg.conns >= uint64(Thresholds.R14MinConnections) {
				unassessable = append(unassessable, fmt.Sprintf(
					"%s (%d of %d connections were already open when the capture began)",
					e, agg.midstream, agg.midstream+agg.conns))
			}
			continue
		}

		median := agg.lifetimes.Percentile(50)
		if median >= Thresholds.R14MaxMedianLifetime.Seconds() {
			continue
		}
		qualifying = append(qualifying, candidate{e, agg, median})
		hosts[e.Addr] = true
	}

	if len(unassessable) > 0 {
		sort.Strings(unassessable)
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R14",
			Text: fmt.Sprintf(
				"Not assessed: connection reuse for %s. Measuring how long a connection lasts needs its "+
					"opening handshake, which is not in this capture for those flows.",
				joinList(unassessable)),
		})
	}

	scope := scoring.ScopeFor(len(hosts), len(qualifying), pop.TotalHosts())

	for _, c := range qualifying {
		agg := c.agg
		medianDur := time.Duration(c.median * float64(time.Second))
		span := agg.last.Sub(agg.first)

		// Specified wording, parameterised. RULES.md R14:
		//
		//   Rapid connection cycling — 10.1.1.5 → 10.2.2.7:5432
		//   412 connections opened and closed in 90s, median lifetime 210ms.
		//   Each connection completed a full handshake and teardown, adding
		//   roughly 12ms of setup overhead per request.
		//   Check next: connection pooling configuration on the client, or an
		//   idle timeout closing pooled connections sooner than expected.
		//   Functionally working, but the handshake overhead is measurable at
		//   this rate.
		client := "several clients"
		if len(agg.clients) == 1 {
			for a := range agg.clients {
				client = a.String()
			}
		}
		title := fmt.Sprintf("Rapid connection cycling — %s → %s", client, c.ep)

		obs := fmt.Sprintf("%d connections opened and closed in %s, median lifetime %s.",
			agg.conns, formatDuration(span), formatDuration(medianDur))

		// The overhead figure is only stated when handshakes were actually
		// timed; without an observed round trip there is no measurement to
		// quote and the sentence would be inventing one.
		if agg.setupCount > 0 {
			perRequest := agg.setupTotal / time.Duration(agg.setupCount)
			obs += fmt.Sprintf(
				" Each connection completed a full handshake and teardown, adding roughly %s of setup overhead per request.",
				formatDuration(perRequest))
		}
		// Midstream flows to the same endpoint were not counted, and saying so
		// keeps the connection count from reading as the whole picture.
		if agg.midstream > 0 {
			obs += fmt.Sprintf(
				" A further %d connection%s to this endpoint began before the capture started and could not be measured.",
				agg.midstream, plural(agg.midstream))
		}

		metrics := map[string]any{
			"connections":        agg.conns,
			"median_lifetime_ms": millis(medianDur),
			"span_ms":            millis(span),
			"distinct_clients":   uint64(len(agg.clients)),
			"midstream_excluded": agg.midstream,
			"server":             c.ep.String(),
		}
		if agg.setupCount > 0 {
			metrics["setup_overhead_ms"] = millis(agg.setupTotal / time.Duration(agg.setupCount))
		}

		f := &findings.Finding{
			RuleID:       "R14",
			RuleName:     "connection-churn",
			ScopeKey:     c.ep.String(),
			ScopeKind:    findings.ScopeEndpoint,
			SubjectLabel: c.ep.String(),
			Title:        title,
			Observation:  obs,
			CheckNext:    "connection pooling configuration on the client, or an idle timeout closing pooled connections sooner than expected. Functionally working, but the handshake overhead is measurable at this rate.",
			Frames:       agg.evidence.Frames(),
			FirstFrame:   agg.evidence.FirstFrame(),
			WorstFrame:   agg.evidence.WorstFrame(),
			TotalCount:   agg.conns,
			Quality:      findings.Confirmed,
			Packets:      finalisePackets(agg.packets, pop.CaptureStart),
			Metrics:      metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight: 5,
				// The cost is the accumulated setup overhead: one handshake
				// per connection, none of which had to be paid.
				ImpactSeconds: (agg.setupTotal.Seconds() / maxFloat(float64(agg.setupCount), 1)) * float64(agg.conns),
				Scope:         scope,
				PeerGroup:     false,
			}),
		}
		out.Add(f)
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// joinList renders a list of phrases as prose rather than as a bare
// comma-separated run.
func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	out := ""
	for i, it := range items {
		switch {
		case i == len(items)-1:
			out += ", and " + it
		case i > 0:
			out += ", " + it
		default:
			out = it
		}
	}
	return out
}
