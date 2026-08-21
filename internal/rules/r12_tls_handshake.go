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

// tlsAppData is the record type carrying encrypted application data. Its
// arrival is what tells this rule a handshake finished, since the completion
// messages themselves are encrypted and cannot be read.
const tlsAppData uint8 = 23

// TLSHandshakeFailure implements R12 · tls-handshake-failure.
//
// Three things, which RULES.md groups and the guide content deliberately
// separates: negotiations that failed, negotiations that succeeded slowly, and
// certificates close to expiry. They are different conditions with different
// costs, and the finding says which of them it saw.
//
// The certificate half is the one that most needs care. Modern TLS encrypts
// the handshake after ServerHello, so a certificate is frequently not visible
// at all — and the guide commits this rule to saying so, because "no
// certificate findings" must never be read as "the certificates are fine".
type TLSHandshakeFailure struct {
	servers map[flow.Endpoint]*tlsServer
	now     time.Time
}

// tlsFlowState tracks one connection's negotiation.
type tlsFlowState struct {
	started    bool
	startTime  time.Time
	startFrame uint64

	sawServerHello bool
	version        uint16
	certNotAfter   int64

	completed   bool
	completedAt time.Time

	fatalAlert bool
	alertDesc  uint8
	alertFrame uint64
	alertTime  time.Time
}

type tlsServer struct {
	endpoint flow.Endpoint

	handshakes int
	failed     int
	// clients that saw a failure here. A server refusing negotiations affects
	// the machines trying to reach it, which is what scope is measured on.
	clients map[string]struct{}

	durations  stats.Sampler
	slow       int
	slowExcess float64

	// Certificate observation. inspected counts handshakes where a date was
	// actually read; opaque counts the ones where the handshake was encrypted
	// or the message did not fit in a captured segment.
	// alertDesc is the description on the most recent fatal alert, which in
	// practice is the same one throughout: a server that refuses negotiations
	// refuses them for one reason.
	alertDesc uint8

	inspected      int
	opaque         int
	earliestExpiry int64

	evidence findings.Evidence
}

// NewTLSHandshakeFailure returns the R12 detector.
func NewTLSHandshakeFailure() *TLSHandshakeFailure {
	return &TLSHandshakeFailure{servers: make(map[flow.Endpoint]*tlsServer)}
}

// Meta describes the rule.
func (r *TLSHandshakeFailure) Meta() Meta {
	return Meta{
		ID:         "R12",
		Name:       "tls-handshake-failure",
		BaseWeight: 6,
		Summary: "Encrypted connections failed to negotiate, took an unusually long time to set up, " +
			"or presented a certificate close to expiry. A negotiation happens before any application " +
			"data moves, so a failure here is not the application's fault.",
	}
}

// NewFlow allocates the per-connection negotiation state.
func (r *TLSHandshakeFailure) NewFlow() any { return &tlsFlowState{} }

// OnPacket follows one connection's negotiation.
func (r *TLSHandshakeFailure) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*tlsFlowState)
	if !ok || !p.TLSPresent {
		return
	}

	switch p.TLSRecordType {
	case capture.TLSRecordHandshake:
		if p.TLSHandshakeType == capture.TLSHandshakeClientHello && !s.started {
			s.started = true
			s.startTime = p.Time
			s.startFrame = p.Frame
		}
		if p.TLSHandshakeType == capture.TLSHandshakeServerHello {
			s.sawServerHello = true
			s.version = p.TLSVersion
		}
		if p.TLSCertNotAfter != 0 {
			s.certNotAfter = p.TLSCertNotAfter
		}
	case capture.TLSRecordAlert:
		// A fatal alert during negotiation ends it. Warning-level alerts are
		// routine and say nothing about whether the connection worked.
		if p.TLSAlertLevel == capture.TLSAlertFatal && !s.completed {
			s.fatalAlert = true
			s.alertDesc = p.TLSAlertDesc
			s.alertFrame = p.Frame
			s.alertTime = p.Time
		}
	case tlsAppData:
		// Encrypted application data means the negotiation finished. The
		// messages that conclude a handshake are themselves encrypted, so
		// their arrival cannot be observed directly — this is the earliest
		// point a capture can honestly say the handshake succeeded.
		if s.started && !s.completed {
			s.completed = true
			s.completedAt = p.Time
		}
	}
}

// OnFlowEnd files this connection's outcome under its server.
func (r *TLSHandshakeFailure) OnFlowEnd(fs any, fl *flow.State) {
	s, ok := fs.(*tlsFlowState)
	if !ok || !s.started {
		return
	}
	server, ok := fl.ServerEndpoint()
	if !ok {
		return
	}

	srv := r.servers[server]
	if srv == nil {
		srv = &tlsServer{endpoint: server, clients: make(map[string]struct{})}
		srv.evidence.Mode = findings.ModeWorst
		r.servers[server] = srv
	}
	srv.handshakes++

	client, _ := fl.ClientEndpoint()

	switch {
	case s.fatalAlert:
		srv.failed++
		srv.alertDesc = s.alertDesc
		srv.clients[client.Addr.String()] = struct{}{}
		srv.evidence.Record(s.alertFrame, s.alertTime, 1)
	case s.completed:
		took := s.completedAt.Sub(s.startTime)
		if took > 0 {
			srv.durations.Add(took.Seconds())
		}
		if took > Thresholds.R12SlowHandshake {
			srv.slow++
			srv.slowExcess += (took - Thresholds.R12SlowHandshake).Seconds()
			srv.clients[client.Addr.String()] = struct{}{}
			srv.evidence.Record(s.startFrame, s.startTime, took.Seconds())
		}
	}

	// Certificate visibility, recorded per handshake whatever the outcome.
	if s.certNotAfter != 0 {
		srv.inspected++
		if srv.earliestExpiry == 0 || s.certNotAfter < srv.earliestExpiry {
			srv.earliestExpiry = s.certNotAfter
		}
	} else if s.sawServerHello {
		srv.opaque++
	}
}

// Emit reports each server whose negotiations failed, dragged, or presented a
// certificate near expiry.
func (r *TLSHandshakeFailure) Emit(pop *Population, out *findings.Store) {
	r.now = pop.CaptureEnd

	var assessed []*tlsServer
	for _, s := range r.servers {
		assessed = append(assessed, s)
	}
	sort.Slice(assessed, func(i, j int) bool {
		return assessed[i].endpoint.String() < assessed[j].endpoint.String()
	})
	if len(assessed) == 0 {
		return
	}

	r.noteOpaqueCertificates(assessed, out)

	peerGroup := len(assessed) >= Thresholds.R12MinPeerServers
	var rates []float64
	for _, s := range assessed {
		rates = append(rates, s.failureRate())
	}
	populationRate := stats.Median(rates)

	// The cost of a negotiation that worked, across the whole capture. This
	// is what prices the ones that did not — Option C's unit. Taken capture-
	// wide rather than per server, because a server whose every handshake
	// failed has no working one of its own to measure.
	var allDurations []float64
	for _, s := range assessed {
		if s.durations.Count() > 0 {
			allDurations = append(allDurations, s.durations.Percentile(0.50))
		}
	}
	captureUnit := stats.Median(allDurations)

	for _, s := range assessed {
		expiring := s.expiringSoon(r.now)
		if s.failed == 0 && s.slow == 0 && !expiring {
			continue
		}
		out.Add(s.finding(r.now, pop, peerGroup, populationRate, captureUnit, expiring))
	}
}

func (s *tlsServer) failureRate() float64 {
	if s.handshakes == 0 {
		return 0
	}
	return float64(s.failed) / float64(s.handshakes)
}

// expiringSoon reports a certificate already elapsed or inside the window.
func (s *tlsServer) expiringSoon(now time.Time) bool {
	if s.earliestExpiry == 0 || now.IsZero() {
		return false
	}
	return time.Unix(s.earliestExpiry, 0).Sub(now) < Thresholds.R12CertExpiryWindow
}

// noteOpaqueCertificates is the degradation RULES.md specifies, and the
// promise the guide content makes.
//
// An absence of certificate findings is not a statement that the certificates
// are fine. Where a handshake was encrypted past ServerHello — or its
// certificate message simply did not fit in a captured segment — this build
// saw no dates, and says so rather than letting silence be read as approval.
func (r *TLSHandshakeFailure) noteOpaqueCertificates(assessed []*tlsServer, out *findings.Store) {
	var opaque, servers int
	for _, s := range assessed {
		if s.opaque > 0 {
			opaque += s.opaque
			servers++
		}
	}
	if opaque == 0 {
		return
	}
	out.AddNote(findings.Note{
		Kind:   "unavailable",
		RuleID: "R12",
		Text: fmt.Sprintf(
			"Not assessed: certificate validity on %s negotiation%s to %d server%s. Modern TLS encrypts "+
				"the handshake after the server's first message, so no certificate was visible in those "+
				"exchanges; a certificate message split across frames is not read either, since this "+
				"build does not reassemble them. Expiry was not checked for these, and the absence of a "+
				"certificate finding is not a statement that they are valid.",
			formatCount(uint64(opaque)), plural(uint64(opaque)), servers, pluralInt(servers)),
	})
}

// finding builds the report for one server.
func (s *tlsServer) finding(now time.Time, pop *Population, peerGroup bool,
	populationRate, captureUnit float64, expiring bool) *findings.Finding {

	var parts []string
	if s.failed > 0 {
		parts = append(parts, fmt.Sprintf("%d handshake%s terminated by fatal alert (%s) before completion",
			s.failed, plural(uint64(s.failed)), tlsAlertName(s.alertDesc)))
	}
	if s.slow > 0 {
		parts = append(parts, fmt.Sprintf("%d took longer than %s to negotiate",
			s.slow, formatDuration(Thresholds.R12SlowHandshake)))
	}
	obs := joinParts(parts)
	if obs != "" {
		obs += "."
	}

	if s.durations.Count() > 0 {
		obs += fmt.Sprintf(" Successful handshakes to this server took %s at the median",
			formatDuration(seconds(s.durations.Percentile(0.50))))
		// The comparison, where there is a population to make it against. It is
		// what separates "this server is slow to negotiate" from "negotiation
		// takes this long here", and the rule has no business implying the
		// first without it.
		if captureUnit > 0 && peerGroup {
			obs += fmt.Sprintf(" against a capture median of %s",
				formatDuration(seconds(captureUnit)))
		}
		obs += "."
	}

	if expiring {
		exp := time.Unix(s.earliestExpiry, 0).UTC()
		if !now.IsZero() && exp.Before(now) {
			obs += fmt.Sprintf(" The presented certificate expired %s before the capture ended.",
				formatSpan(now.Sub(exp)))
		} else if !now.IsZero() {
			obs += fmt.Sprintf(" The presented certificate expires %s after the capture ended.",
				formatSpan(exp.Sub(now)))
		}
	}

	// Option C. The failures are priced at what a working negotiation costs,
	// which states wasted work rather than elapsed time — a fatal alert
	// arrives faster than a success, and what it cost is a connection that
	// never opened.
	unit := captureUnit
	if s.durations.Count() > 0 {
		unit = s.durations.Percentile(0.50)
	}
	failedWork := float64(s.failed) * unit
	if unit == 0 && s.failed > 0 {
		// Nothing anywhere in the capture negotiated successfully, so there is
		// no measured cost of a working handshake. The finding reports the
		// failures and declines to price them.
		obs += " No handshake in this capture completed, so how long one normally takes could not be measured."
	}
	timeLost := failedWork + s.slowExcess

	clients := len(s.clients)
	scope := scoring.ScopeFor(clients, s.handshakes, pop.TotalHosts())

	return &findings.Finding{
		RuleID:       "R12",
		RuleName:     "tls-handshake-failure",
		ScopeKey:     s.endpoint.String(),
		ScopeKind:    findings.ScopeEndpoint,
		SubjectLabel: s.endpoint.String(),
		Title:        fmt.Sprintf("TLS handshakes failing — %s", s.endpoint),
		Observation:  trimLead(obs),
		CheckNext: "certificate validity and cipher suite compatibility between these clients and " +
			"the server. A certificate expiry is worth resolving regardless of whether it caused these " +
			"particular failures.",
		Frames:     s.evidence.Frames(),
		FirstFrame: s.evidence.FirstFrame(),
		WorstFrame: s.evidence.WorstFrame(),
		TotalCount: uint64(s.failed + s.slow),
		Quality:    findings.Confirmed,
		Metrics: map[string]any{
			"handshakes":               s.handshakes,
			"failed":                   s.failed,
			"slow":                     s.slow,
			"clients_affected":         clients,
			"failure_rate":             round3(s.failureRate()),
			"certificates_inspected":   s.inspected,
			"certificates_not_visible": s.opaque,
			"wasted_work_s":            round3(timeLost),
		},
		Significance: scoring.Significance(scoring.Inputs{
			BaseWeight:       6,
			ImpactSeconds:    timeLost,
			Scope:            scope,
			Value:            s.failureRate(),
			PopulationMedian: populationRate,
			PeerGroup:        peerGroup,
		}),
	}
}

// tlsAlertName gives the standard name for the alert descriptions a reader is
// likely to meet, and falls back to the number for the rest.
//
// Named rather than numbered because the name is what appears in every other
// tool and every search result — "handshake_failure" is findable and "40" is
// not. Only the ones a failing negotiation actually produces are listed;
// inventing names for codes this build has never seen would be padding.
func tlsAlertName(desc uint8) string {
	switch desc {
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 43:
		return "unsupported_certificate"
	case 44:
		return "certificate_revoked"
	case 45:
		return "certificate_expired"
	case 46:
		return "certificate_unknown"
	case 47:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 49:
		return "access_denied"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 112:
		return "unrecognized_name"
	}
	return fmt.Sprintf("alert %d", desc)
}
