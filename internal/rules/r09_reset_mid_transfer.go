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
)

// ResetMidTransfer implements R09 · reset-mid-transfer.
//
// A connection ended by RST while data was still moving, as distinct from a
// reset after a long idle period and from a reset standing in for a clean FIN
// at the natural end of a transfer. The distinction is the rule: an abrupt
// ending is only interesting when something was interrupted.
//
// Reported per resetting host rather than per flow. The specified wording
// counts connections and averages the bytes they carried ("12 connections
// terminated by RST ... averaging 340KB"), which is a statement about a host's
// behaviour across the capture.
type ResetMidTransfer struct {
	// hosts is the retained per-resetting-host aggregate.
	hosts map[flow.Endpoint]*resetAgg

	// closedCleanly counts flows that ended with FIN, capture-wide. It is what
	// licenses the "the remaining N connections closed normally" sentence, and
	// what the uniformity check reads: a host that resets everything is
	// exhibiting a habit, not a fault.
	closedCleanly int
	totalClosed   int
}

// NewResetMidTransfer returns a fresh R09 detector.
func NewResetMidTransfer() *ResetMidTransfer {
	return &ResetMidTransfer{hosts: make(map[flow.Endpoint]*resetAgg)}
}

// Meta describes R09.
func (r *ResetMidTransfer) Meta() Meta {
	return Meta{
		ID:         "R09",
		Name:       "reset-mid-transfer",
		BaseWeight: 7,
		Summary:    "A connection was terminated by reset while data was still moving, rather than closed cleanly once both sides were done.",
	}
}

// rstFlowState is R09's per-flow packet-path state.
type rstFlowState struct {
	lastDataTime  time.Time
	lastDataValid bool
	firstDataTime time.Time
	bytes         uint64

	// sentEnd is the highest sequence number each side has sent, and ackedTo
	// the highest its peer has acknowledged. The difference is data in
	// flight — sent, not yet confirmed — which is what tells an interrupted
	// transfer from one that had finished.
	sentEnd  [2]uint32
	sentAny  [2]bool
	ackedTo  [2]uint32
	ackedAny [2]bool

	// resetter is the side that sent the RST, and inFlight records whether
	// data was still moving when it arrived.
	sawReset  bool
	resetter  flow.Direction
	resetTime time.Time
	inFlight  bool
	sinceData time.Duration
	resetRef  *findings.PacketRef
	dataRef   *findings.PacketRef
	resetTTL  uint8
	peerTTL   uint8
	ttlSeen   bool
}

// resetAgg is the retained per-host aggregate.
type resetAgg struct {
	host flow.Endpoint

	connections uint64
	totalBytes  uint64
	evidence    findings.Evidence
	packets     []findings.PacketRef

	// interrupted is the time these connections spent transferring before
	// they were cut off — work that has to be done again, and the only
	// seconds-denominated cost a reset actually has. See Emit for why this is
	// dropped entirely when the resets turn out to be a habit.
	interrupted time.Duration

	// ttlConsistent records whether the resets matched the same host's other
	// traffic. The specified wording states this either way, because "these
	// appear to come from the host" is as useful to a reader as its opposite.
	ttlChecked    bool
	ttlConsistent bool

	// cleanCloses counts this host's own connections that ended with FIN. A
	// host with none is resetting everything, which RULES.md calls a pattern
	// rather than a fault.
	cleanCloses uint64

	proximate bool
}

// NewFlow allocates R09's per-flow state.
func (r *ResetMidTransfer) NewFlow() any { return &rstFlowState{} }

// OnPacket folds one packet into the reset state.
func (r *ResetMidTransfer) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*rstFlowState)
	if !ok {
		return
	}

	// Acknowledgements advance what the sender knows arrived, in either
	// direction, and are tracked before the data branch returns.
	if p.AnyFlag(capture.FlagACK) {
		other := dir.Other()
		if !s.ackedAny[other] || capture.SeqLT(s.ackedTo[other], p.Ack) {
			s.ackedTo[other], s.ackedAny[other] = p.Ack, true
		}
	}

	if p.PayloadLength > 0 {
		if !s.lastDataValid {
			s.firstDataTime = p.Time
		}
		s.lastDataTime = p.Time
		s.lastDataValid = true
		s.bytes += uint64(p.PayloadLength)
		if end := p.SeqEnd(); !s.sentAny[dir] || capture.SeqLT(s.sentEnd[dir], end) {
			s.sentEnd[dir], s.sentAny[dir] = end, true
		}
		ref := findings.SnapshotPacket(p, findings.RoleContext,
			"Data still moving on this connection", "")
		s.dataRef = &ref
		if p.TTL != 0 {
			s.peerTTL = p.TTL
		}
		return
	}

	if p.AnyFlag(capture.FlagRST) && !s.sawReset {
		s.sawReset = true
		s.resetter = dir
		s.resetTime = p.Time
		s.resetTTL = p.TTL
		if s.lastDataValid {
			s.sinceData = p.Time.Sub(s.lastDataTime)
			// Both halves of RULES.md's condition, and the carve-out beside
			// it. Recency alone cannot tell an interrupted transfer from one
			// that finished and was then closed abruptly — the reset lands
			// moments after the last data segment either way. What separates
			// them is whether anything was still outstanding: a transfer that
			// had completed has had its last byte acknowledged, and a reset
			// after that point is a way of closing, which the specification
			// puts outside this rule. Uniformity remains the backstop for
			// habitual resets that do land with data still unconfirmed.
			s.inFlight = s.sinceData <= Thresholds.R09DataRecencyWindow && s.dataOutstanding()
		}
		note := "Connection reset"
		if s.inFlight {
			note = fmt.Sprintf("Reset %s after the last data segment — the transfer was still active",
				formatDuration(s.sinceData))
		}
		ref := findings.SnapshotPacket(p, findings.RoleFlagged, note, "TCP RST")
		s.resetRef = &ref
	}
}

// dataOutstanding reports whether either side had sent data its peer had not
// yet acknowledged — data genuinely in flight.
func (s *rstFlowState) dataOutstanding() bool {
	for d := flow.Direction(0); d < 2; d++ {
		if !s.sentAny[d] {
			continue
		}
		// Never acknowledged at all: everything that side sent is outstanding.
		if !s.ackedAny[d] {
			return true
		}
		if capture.SeqLT(s.ackedTo[d], s.sentEnd[d]) {
			return true
		}
	}
	return false
}

// OnFlowEnd folds a reset flow into its sender's aggregate.
func (r *ResetMidTransfer) OnFlowEnd(fs any, fl *flow.State) {
	s, ok := fs.(*rstFlowState)
	if !ok {
		return
	}

	// A flow that never carried data was never a transfer, so it cannot have
	// been interrupted mid-transfer. Refused connections land here and belong
	// to R03.
	if !fl.HasPayload() {
		return
	}

	r.totalClosed++
	if !s.sawReset {
		r.closedCleanly++
		// Attribute the clean close to both ends: either could have been the
		// host that habitually resets, and this is what proves it does not.
		for d := flow.Direction(0); d < 2; d++ {
			if agg := r.hosts[fl.Key.Endpoint(d)]; agg != nil {
				agg.cleanCloses++
			}
		}
		return
	}

	// A reset well after the last data segment ended an idle connection, not
	// an active transfer. RULES.md puts that case outside this rule.
	if !s.inFlight {
		return
	}

	host := fl.Key.Endpoint(s.resetter)
	agg := r.hosts[host]
	if agg == nil {
		agg = &resetAgg{host: host}
		agg.evidence.Mode = findings.ModeFirst
		r.hosts[host] = agg
	}

	agg.connections++
	agg.totalBytes += s.bytes
	agg.evidence.Record(fl.RSTFrame, s.resetTime, 0)
	if !s.firstDataTime.IsZero() {
		if d := s.resetTime.Sub(s.firstDataTime); d > 0 {
			agg.interrupted += d
		}
	}

	if !agg.ttlChecked && s.resetTTL != 0 && s.peerTTL != 0 {
		agg.ttlChecked = true
		diff := int(s.resetTTL) - int(s.peerTTL)
		agg.ttlConsistent = diff <= int(Thresholds.R03TTLTolerance) &&
			diff >= -int(Thresholds.R03TTLTolerance)
	}

	if len(agg.packets) < 2*findings.MaxFrames {
		if s.dataRef != nil {
			agg.packets = append(agg.packets, *s.dataRef)
		}
		if s.resetRef != nil {
			agg.packets = append(agg.packets, *s.resetRef)
		}
	}
}

// Emit produces one finding per host that reset connections mid-transfer.
func (r *ResetMidTransfer) Emit(pop *Population, out *findings.Store) {
	hosts := make([]flow.Endpoint, 0, len(r.hosts))
	for h := range r.hosts {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Compare(hosts[j]) < 0 })

	addrs := make(map[netip.Addr]bool, len(hosts))
	for _, h := range hosts {
		addrs[h.Addr] = true
	}
	scope := scoring.ScopeFor(len(addrs), len(hosts), pop.TotalHosts())

	for _, h := range hosts {
		agg := r.hosts[h]

		// RULES.md's false-positive trap. Some applications close with RST
		// deliberately, to skip TIME_WAIT; a host that does it to every
		// connection is exhibiting a habit rather than failing. The finding is
		// still reported — the resets happened — but as context rather than as
		// a fault, which is what "downgrade to informational" means here.
		uniform := agg.cleanCloses == 0 && agg.connections >= uint64(Thresholds.R09UniformityMinConnections)

		var avgBytes uint64
		if agg.connections > 0 {
			avgBytes = agg.totalBytes / agg.connections
		}

		// Specified wording, parameterised. RULES.md R09:
		//
		//   Connections reset during active transfer — 10.2.2.7 → 10.1.1.5
		//   12 connections terminated by RST while data was still in flight,
		//   averaging 340KB transferred before the reset. The remaining 380
		//   connections in this capture closed normally with FIN.
		//   Check next: an application-side abort, a resource limit, or a
		//   stateful device on the path dropping the session. The TTL on these
		//   resets matches the peer's other traffic, so they appear to
		//   originate from the host rather than a middlebox.
		title := fmt.Sprintf("Connections reset during active transfer — %s", h.Addr)

		obs := fmt.Sprintf(
			"%d connection%s terminated by RST while data was still in flight, averaging %s transferred before the reset.",
			agg.connections, plural(agg.connections), formatBytes(avgBytes))

		// Stated only when there were other connections to compare against —
		// a capture where nothing closed normally cannot claim a remainder.
		if remaining := r.closedCleanly; remaining > 0 {
			obs += fmt.Sprintf(" The remaining %d connection%s in this capture closed normally with FIN.",
				remaining, pluralInt(remaining))
		}
		if uniform {
			obs += " Every connection this host closed in this capture ended the same way, with no clean FIN close anywhere — a consistent habit rather than something that went wrong on particular connections."
		}

		checkNext := "an application-side abort, a resource limit, or a stateful device on the path dropping the session."
		// The TTL sentence is stated only when the comparison was actually
		// made, and says which way it came out — both directions are useful.
		if agg.ttlChecked {
			if agg.ttlConsistent {
				checkNext += " The TTL on these resets matches the peer's other traffic, so they appear to originate from the host rather than a middlebox."
			} else {
				checkNext += " The TTL on these resets differs from the peer's other traffic, which can mean a device on the path sent them rather than the host itself."
			}
		}

		metrics := map[string]any{
			"connections_reset":     agg.connections,
			"average_bytes":         avgBytes,
			"total_bytes":           agg.totalBytes,
			"clean_closes_capture":  r.closedCleanly,
			"clean_closes_for_host": agg.cleanCloses,
			"uniform_reset_habit":   uniform,
			"resetting_host":        h.String(),
		}
		if agg.ttlChecked {
			metrics["reset_ttl_matches_peer"] = agg.ttlConsistent
		}

		packets := append([]findings.PacketRef(nil), agg.packets...)
		findings.SortPacketRefs(packets)

		// The downgrade runs through the score, so it reaches the reader
		// through the same severity mapping every other finding uses rather
		// than as a second, parallel severity mechanism.
		//
		// Both factors move, and the impact one is the substantive half. A
		// host that ends every connection this way did not interrupt those
		// transfers: they finished, and the close was merely abrupt. So there
		// is no discarded work to count, and the seconds that would otherwise
		// be charged against this finding are not real. Collapsing the scope
		// as well keeps a habit from outranking a fault on breadth alone.
		effectiveScope := scope
		interrupted := agg.interrupted.Seconds()
		if uniform {
			effectiveScope = scoring.ScopeFlow
			interrupted = 0
		}

		f := &findings.Finding{
			RuleID:       "R09",
			RuleName:     "reset-mid-transfer",
			ScopeKey:     h.String(),
			ScopeKind:    findings.ScopeEndpoint,
			SubjectLabel: h.Addr.String(),
			Title:        title,
			Observation:  obs,
			CheckNext:    checkNext,
			Frames:       agg.evidence.Frames(),
			FirstFrame:   agg.evidence.FirstFrame(),
			WorstFrame:   agg.evidence.WorstFrame(),
			TotalCount:   agg.connections,
			Quality:      findings.Confirmed,
			Packets:      finalisePackets(packets, pop.CaptureStart),
			Metrics:      metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:    7,
				ImpactSeconds: interrupted,
				Scope:         effectiveScope,
				PeerGroup:     false,
				Proximate:     agg.proximate,
			}),
		}
		out.Add(f)
	}
}

// formatBytes renders a byte count the way the rule wordings do — "340KB",
// "1.2MB" — rather than as a raw figure a reader has to scale themselves.
func formatBytes(n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1024*1024:
		return fmt.Sprintf("%dKB", n/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.1fGB", float64(n)/(1024*1024*1024))
}
