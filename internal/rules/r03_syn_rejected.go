package rules

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/scoring"
)

// SynRejected implements R03 · syn-rejected.
//
// A SYN answered by RST rather than SYN/ACK: the host is reachable and
// answering, and it said no. This is the counterpart to R02's silence, and
// the distinction is the finding's whole value — a refusal proves something
// was home.
//
// Reported per server:port rather than per flow. The specified wording counts
// attempts and distinct clients across the capture ("47 connection attempts
// from 3 clients"), which is a statement about the endpoint, not about any one
// connection to it.
type SynRejected struct {
	// endpoints is the retained per-server:port aggregate. Refusals have to
	// outlive the flows that produced them, so they live here rather than in
	// the evictable packet-path tier.
	endpoints map[flow.Endpoint]*rejAgg

	// hostTTL is the TTL seen from each address on traffic that is not a
	// refusal — the "established traffic" RULES.md compares a reset against.
	//
	// Per host rather than per flow, and resolved at Emit rather than as the
	// refusal is seen, because a refused connection carries nothing else from
	// that host by definition: the baseline has to come from its other
	// conversations, which may not have been read yet when the reset arrives.
	//
	// Keyed observations rather than bare values so the winner is the earliest
	// frame, not the first flow to close. Close order is an eviction-policy
	// detail, and a baseline that depended on it would make this rule's output
	// vary with the flow cap — the one thing constraint 5 forbids. Frame
	// numbers are globally ordered, so this resolves identically on every run.
	hostTTL map[netip.Addr]ttlObservation
}

// ttlObservation is one host's TTL and the frame it was read from.
type ttlObservation struct {
	ttl   uint8
	frame uint64
}

// NewSynRejected returns a fresh R03 detector.
func NewSynRejected() *SynRejected {
	return &SynRejected{
		endpoints: make(map[flow.Endpoint]*rejAgg),
		hostTTL:   make(map[netip.Addr]ttlObservation),
	}
}

// Meta describes R03.
func (r *SynRejected) Meta() Meta {
	return Meta{
		ID: "R03",
		// [RULES.md] 4, revised down from 7 with evidence — see the addendum.
		// Ordering-only: the severity a reader sees was informational at every
		// weight from 3 to 7, because a refusal costs no measurable time and
		// has no peer group, so the scoring model was already holding this
		// rule down. What the lower weight buys is rank: a finding that
		// restates the error the application already showed should sit below
		// one telling the reader something new.
		BaseWeight: 4,
		Name:       "syn-rejected",
		Summary:    "A connection attempt was answered with a refusal rather than an acceptance — the host is reachable, and nothing is listening on that port.",
	}
}

// rejFlowState is R03's per-flow packet-path state.
type rejFlowState struct {
	sawSYN    bool
	synFrame  uint64
	initiator flow.Direction

	// refused marks a SYN answered by RST from the other side.
	refused    bool
	rstFrame   uint64
	rstTTL     uint8
	rstTTLSeen bool
	rstRef     *findings.PacketRef
	synRef     *findings.PacketRef

	// ttlByDir is the first TTL seen from each side on a segment that is not
	// a reset, with the frame it came from. Reported at flow end as that
	// host's ordinary traffic.
	ttlByDir  [2]uint8
	ttlFrame  [2]uint64
	ttlSeen   [2]bool
	hasAnyTTL bool
}

// rejAgg is the retained per-server:port aggregate.
type rejAgg struct {
	endpoint flow.Endpoint

	attempts uint64
	clients  map[netip.Addr]bool

	evidence findings.Evidence
	packets  []findings.PacketRef

	// rstTTL is the TTL the refusals arrived with, compared at Emit against
	// the same host's ordinary traffic — the middlebox-forgery hint.
	rstTTL     uint8
	rstTTLSeen bool
}

// NewFlow allocates R03's per-flow state.
func (r *SynRejected) NewFlow() any { return &rejFlowState{} }

// OnPacket folds one packet into the refusal state.
func (r *SynRejected) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*rejFlowState)
	if !ok {
		return
	}

	syn := p.AnyFlag(capture.FlagSYN)
	ack := p.AnyFlag(capture.FlagACK)
	rst := p.AnyFlag(capture.FlagRST)

	switch {
	case syn && !ack && !rst:
		if !s.sawSYN {
			s.sawSYN = true
			s.initiator = dir
			s.synFrame = p.Frame
			ref := findings.SnapshotPacket(p, findings.RoleContext,
				"Connection attempt", "TCP SYN")
			s.synRef = &ref
		}

	case rst:
		// Only a refusal if it answers this side's opening request and the
		// connection was never established. A RST later in a conversation is
		// R09's business, not this rule's.
		if s.sawSYN && dir != s.initiator && !s.refused && !fl.HasPayload() {
			s.refused = true
			s.rstFrame = p.Frame
			s.rstTTL, s.rstTTLSeen = p.TTL, p.TTL != 0
			ref := findings.SnapshotPacket(p, findings.RoleFlagged,
				"Refused — the host answered the connection attempt with a reset", "TCP RST")
			s.rstRef = &ref
		}

	}

	// Every non-reset segment contributes its sender's ordinary TTL. Collected
	// on all flows, not only refused ones, because the baseline a refusal is
	// judged against comes from that host's other conversations.
	if !rst && p.TTL != 0 && !s.ttlSeen[dir] {
		s.ttlByDir[dir], s.ttlFrame[dir], s.ttlSeen[dir] = p.TTL, p.Frame, true
		s.hasAnyTTL = true
	}
}

// OnFlowEnd folds a refused flow into its server endpoint's aggregate, and
// contributes whatever ordinary TTLs this flow observed to the per-host
// baseline.
func (r *SynRejected) OnFlowEnd(fs any, fl *flow.State) {
	s, ok := fs.(*rejFlowState)
	if !ok {
		return
	}

	if s.hasAnyTTL {
		for d := flow.Direction(0); d < 2; d++ {
			if !s.ttlSeen[d] {
				continue
			}
			addr := fl.Key.Endpoint(d).Addr
			obs := ttlObservation{ttl: s.ttlByDir[d], frame: s.ttlFrame[d]}
			// Earliest frame wins, not earliest close: see the field comment.
			if prior, seen := r.hostTTL[addr]; !seen || obs.frame < prior.frame {
				r.hostTTL[addr] = obs
			}
		}
	}

	if !s.refused {
		return
	}

	server := fl.Key.Endpoint(s.initiator.Other())
	client := fl.Key.Endpoint(s.initiator)

	agg := r.endpoints[server]
	if agg == nil {
		agg = &rejAgg{endpoint: server, clients: make(map[netip.Addr]bool)}
		agg.evidence.Mode = findings.ModeFirst
		r.endpoints[server] = agg
	}

	agg.attempts++
	agg.clients[client.Addr] = true
	agg.evidence.Record(s.rstFrame, fl.LastSeen, 0)

	// Keep the attempt and its refusal together in the packet view: a reset on
	// its own does not show what it was answering.
	if len(agg.packets) < 2*findings.MaxFrames {
		if s.synRef != nil {
			agg.packets = append(agg.packets, *s.synRef)
		}
		if s.rstRef != nil {
			agg.packets = append(agg.packets, *s.rstRef)
		}
	}

	// The reset's own TTL, kept for the middlebox-forgery comparison. The
	// baseline it is judged against is not known until every flow has been
	// read, so the comparison itself happens at Emit.
	if s.rstTTLSeen && !agg.rstTTLSeen {
		agg.rstTTL, agg.rstTTLSeen = s.rstTTL, true
	}
}

// Emit produces one finding per server:port that refused connections.
func (r *SynRejected) Emit(pop *Population, out *findings.Store) {
	eps := make([]flow.Endpoint, 0, len(r.endpoints))
	for e := range r.endpoints {
		eps = append(eps, e)
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].Compare(eps[j]) < 0 })

	hosts := make(map[netip.Addr]bool, len(eps))
	for _, e := range eps {
		hosts[e.Addr] = true
	}
	scope := scoring.ScopeFor(len(hosts), len(eps), pop.TotalHosts())

	for _, e := range eps {
		agg := r.endpoints[e]

		// Specified wording, parameterised. RULES.md R03:
		//
		//   Connections actively refused — 10.4.4.9:8443
		//   47 connection attempts from 3 clients answered with RST. The host is
		//   reachable and responding; nothing is listening on that port.
		//   Check next: whether the service is running and bound to the expected
		//   port and address. Distinct from R02 — the host itself is up and
		//   answering.
		title := fmt.Sprintf("Connections actively refused — %s", e)

		clients := uint64(len(agg.clients))
		obs := fmt.Sprintf(
			"%d connection attempt%s from %d client%s answered with RST. The host is reachable and responding; nothing is listening on that port.",
			agg.attempts, plural(agg.attempts), clients, plural(clients))

		// The middlebox-forgery hint. A reset manufactured on the host's
		// behalf by a device nearer the capture point has crossed fewer
		// routers than the host's own traffic, so it arrives with a visibly
		// different TTL.
		hostObs, haveBaseline := r.hostTTL[e.Addr]
		baseline := hostObs.ttl
		mismatch := false
		if agg.rstTTLSeen && haveBaseline {
			if diff := int(agg.rstTTL) - int(baseline); diff > int(Thresholds.R03TTLTolerance) ||
				diff < -int(Thresholds.R03TTLTolerance) {
				mismatch = true
			}
		}

		quality := findings.Confirmed
		basis := ""
		if mismatch {
			// Not a suppression: the refusal was observed either way. What is
			// in doubt is who sent it, so the finding is degraded and says so
			// rather than dropping the observation or asserting forgery.
			quality = findings.Inferred
			basis = fmt.Sprintf(
				"The reset arrived with a TTL of %d while this host's other traffic arrived with %d. "+
					"A difference that large can mean a device on the path sent the reset on the host's behalf "+
					"rather than the host itself.",
				agg.rstTTL, baseline)
		}

		metrics := map[string]any{
			"refused_attempts": agg.attempts,
			"distinct_clients": clients,
			"server":           e.String(),
			"ttl_mismatch":     mismatch,
		}
		if mismatch {
			metrics["reset_ttl"] = agg.rstTTL
			metrics["peer_traffic_ttl"] = baseline
		}

		packets := append([]findings.PacketRef(nil), agg.packets...)
		findings.SortPacketRefs(packets)

		f := &findings.Finding{
			RuleID:       "R03",
			RuleName:     "syn-rejected",
			ScopeKey:     e.String(),
			ScopeKind:    findings.ScopeEndpoint,
			SubjectLabel: e.String(),
			Title:        title,
			Observation:  obs,
			CheckNext:    "whether the service is running and bound to the expected port and address. Distinct from R02 — the host itself is up and answering.",
			Frames:       agg.evidence.Frames(),
			FirstFrame:   agg.evidence.FirstFrame(),
			WorstFrame:   agg.evidence.WorstFrame(),
			TotalCount:   agg.attempts,
			Quality:      quality,
			QualityBasis: basis,
			Packets:      finalisePackets(packets, pop.CaptureStart),
			Metrics:      metrics,
			// No time is lost to a refusal — it arrives at once, which is
			// precisely what distinguishes it from R02's silence. Impact is
			// left at its floor.
			//
			// A consequence worth knowing: significance is therefore invariant
			// to attempt count, so forty-seven refusals rank exactly where two
			// do. That is a property of the scoring model rather than of this
			// weight, and is recorded in docs/ENGINEERING-NOTES.md rather than
			// worked around here.
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight: 4,
				Scope:      scope,
				PeerGroup:  false,
			}),
		}
		out.Add(f)
	}
}
