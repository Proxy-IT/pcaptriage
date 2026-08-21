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

// DNSFailure implements R11 · dns-failure.
//
// Weighted highly for its size, and RULES.md says why: a name lookup happens
// before the connection it enables, so a slow or failing one delays everything
// behind it — and because the delay lands before any application traffic, it
// is very frequently blamed on the application instead.
//
// This rule reads UDP rather than a TCP flow, so it takes packets through
// RawObserver instead of the per-flow hooks. It keeps no flow state and is
// never offered one.
type DNSFailure struct {
	resolvers map[netip.AddrPort]*dnsResolver
	// dotSeen records encrypted resolver traffic, which this build cannot read
	// and must say so about rather than letting an encrypted resolver look
	// like a silent one.
	dotSeen  map[netip.Addr]int
	lastSeen time.Time
}

// dnsPending is a query waiting for its answer.
type dnsPending struct {
	client netip.AddrPort
	id     uint16
	at     time.Time
	frame  uint64
}

type dnsResolver struct {
	addr netip.AddrPort

	pending []dnsPending
	// clients is every client that saw a failure here, which is what the
	// finding's scope is measured on: a resolver returning errors affects the
	// machines asking it, not itself.
	clients map[netip.Addr]struct{}

	queries     int
	answered    int
	unanswered  int
	servfail    int
	nxdomain    int
	slow        int
	unansweredS float64
	slowExcessS float64
	// success holds response times for lookups that worked, which is both the
	// slow-response population and the unit cost of a lookup that did not.
	success  stats.Sampler
	evidence findings.Evidence
}

// NewDNSFailure returns the R11 detector.
func NewDNSFailure() *DNSFailure {
	return &DNSFailure{
		resolvers: make(map[netip.AddrPort]*dnsResolver),
		dotSeen:   make(map[netip.Addr]int),
	}
}

// Meta describes the rule.
func (r *DNSFailure) Meta() Meta {
	return Meta{
		ID:         "R11",
		Name:       "dns-failure",
		BaseWeight: 8,
		Summary: "Name lookups went unanswered, came back as errors, or took a long time. A lookup " +
			"happens before the connection it enables, so a slow one delays everything behind it and " +
			"is often mistaken for application slowness.",
	}
}

// NewFlow, OnPacket and OnFlowEnd are the per-flow hooks R11 does not use: it
// reads UDP, which the flow machinery does not track. See OnRawPacket.
func (r *DNSFailure) NewFlow() any                                               { return nil }
func (r *DNSFailure) OnPacket(any, *flow.State, *capture.Packet, flow.Direction) {}
func (r *DNSFailure) OnFlowEnd(any, *flow.State)                                 {}

// OnRawPacket folds in one packet, DNS or otherwise.
func (r *DNSFailure) OnRawPacket(p *capture.Packet) {
	if p.Time.After(r.lastSeen) {
		r.lastSeen = p.Time
	}

	// Encrypted resolver traffic. Port 853 is DNS over TLS and is
	// recognisable; DoH is HTTPS to a web port and is not distinguishable
	// from ordinary web traffic here, which the note says rather than
	// implying this build ruled it out.
	if p.SrcPort == 853 || p.DstPort == 853 {
		addr := p.Dst
		if p.SrcPort == 853 {
			addr = p.Src
		}
		r.dotSeen[addr]++
		return
	}

	if !p.DNSPresent {
		return
	}

	if !p.DNSIsResponse {
		r.query(p)
		return
	}
	r.response(p)
}

func (r *DNSFailure) resolverFor(ap netip.AddrPort) *dnsResolver {
	res := r.resolvers[ap]
	if res == nil {
		res = &dnsResolver{addr: ap, clients: make(map[netip.Addr]struct{})}
		res.evidence.Mode = findings.ModeWorst
		r.resolvers[ap] = res
	}
	return res
}

func (r *DNSFailure) query(p *capture.Packet) {
	res := r.resolverFor(netip.AddrPortFrom(p.Dst, p.DstPort))
	res.queries++
	if len(res.pending) >= Thresholds.R11PendingCap {
		// The oldest outstanding query is resolved as unanswered here rather
		// than dropped: it has been waiting longer than everything behind it,
		// so if anything in this window went unanswered it did.
		res.resolveUnanswered(res.pending[0], r.lastSeen)
		res.pending = res.pending[1:]
	}
	res.pending = append(res.pending, dnsPending{
		client: netip.AddrPortFrom(p.Src, p.SrcPort),
		id:     p.DNSID, at: p.Time, frame: p.Frame,
	})
}

func (r *DNSFailure) response(p *capture.Packet) {
	res := r.resolverFor(netip.AddrPortFrom(p.Src, p.SrcPort))
	client := netip.AddrPortFrom(p.Dst, p.DstPort)

	for i := range res.pending {
		q := res.pending[i]
		if q.id != p.DNSID || q.client != client {
			continue
		}
		res.pending = append(res.pending[:i], res.pending[i+1:]...)

		took := p.Time.Sub(q.at)
		if took < 0 {
			took = 0
		}
		res.answered++

		switch p.DNSRcode {
		case capture.DNSRcodeServFail:
			res.servfail++
			res.clients[client.Addr()] = struct{}{}
			res.evidence.Record(p.Frame, p.Time, took.Seconds())
		case capture.DNSRcodeNXDomain:
			res.nxdomain++
			res.clients[client.Addr()] = struct{}{}
			res.evidence.Record(p.Frame, p.Time, took.Seconds())
		default:
			// A working lookup. Its time is both the slow-response population
			// and the unit cost of one that failed.
			res.success.Add(took.Seconds())
			if took > Thresholds.R11SlowResponse {
				res.slow++
				res.slowExcessS += (took - Thresholds.R11SlowResponse).Seconds()
				res.clients[client.Addr()] = struct{}{}
				res.evidence.Record(p.Frame, p.Time, took.Seconds())
			}
		}
		return
	}
}

// resolveUnanswered books a query that never got a reply.
func (d *dnsResolver) resolveUnanswered(q dnsPending, until time.Time) {
	waited := until.Sub(q.at)
	if waited > Thresholds.R11UnansweredWindow {
		waited = Thresholds.R11UnansweredWindow
	}
	if waited <= 0 {
		return
	}
	d.unanswered++
	d.unansweredS += waited.Seconds()
	d.clients[q.client.Addr()] = struct{}{}
	d.evidence.Record(q.frame, q.at, waited.Seconds())
}

// Emit reports each resolver that failed or delayed lookups.
func (r *DNSFailure) Emit(pop *Population, out *findings.Store) {
	// Queries still outstanding when the capture ended. Only those that had
	// the full window to be answered count: a query sent a tenth of a second
	// before the last frame was not ignored, the capture simply stopped.
	for _, res := range r.resolvers {
		for _, q := range res.pending {
			if r.lastSeen.Sub(q.at) >= Thresholds.R11UnansweredWindow {
				res.resolveUnanswered(q, r.lastSeen)
			}
		}
		res.pending = nil
	}

	r.noteEncrypted(out)

	var assessed []*dnsResolver
	for _, res := range r.resolvers {
		if res.queries > 0 {
			assessed = append(assessed, res)
		}
	}
	sort.Slice(assessed, func(i, j int) bool {
		return assessed[i].addr.String() < assessed[j].addr.String()
	})
	if len(assessed) == 0 {
		return
	}

	// The population: the failure rate of every resolver seen. A resolver is
	// unusual relative to the others in the same capture, and with only one
	// there is nothing to be unusual against — deviation stays neutral and the
	// finding rests on what it observed rather than on a comparison it cannot
	// make.
	peerGroup := len(assessed) >= Thresholds.R11MinPeerResolvers
	var rates []float64
	for _, res := range assessed {
		rates = append(rates, res.failureRate())
	}
	populationRate := stats.Median(rates)

	for _, res := range assessed {
		failed := res.unanswered + res.servfail + res.nxdomain
		if failed == 0 && res.slow == 0 {
			continue
		}

		f := res.finding(r, pop, peerGroup, populationRate)
		out.Add(f)
	}
}

func (d *dnsResolver) failureRate() float64 {
	if d.queries == 0 {
		return 0
	}
	return float64(d.unanswered+d.servfail+d.nxdomain) / float64(d.queries)
}

// noteEncrypted states what could not be read.
func (r *DNSFailure) noteEncrypted(out *findings.Store) {
	if len(r.dotSeen) == 0 {
		return
	}
	addrs := make([]netip.Addr, 0, len(r.dotSeen))
	for a := range r.dotSeen {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })

	var total int
	for _, n := range r.dotSeen {
		total += n
	}
	out.AddNote(findings.Note{
		Kind:   "unavailable",
		RuleID: "R11",
		Text: fmt.Sprintf(
			"Not assessed: name lookups carried over an encrypted channel. %s frame%s of DNS over TLS "+
				"were seen to %d host%s, and their contents cannot be read from a capture. Lookups sent "+
				"that way were not checked for failures or slow responses. DNS over HTTPS cannot be "+
				"distinguished from ordinary web traffic here at all, so this count is a floor rather "+
				"than a total.",
			formatCount(uint64(total)), plural(uint64(total)), len(addrs), pluralInt(len(addrs))),
	})
}

// finding builds the report for one resolver.
func (d *dnsResolver) finding(r *DNSFailure, pop *Population, peerGroup bool, populationRate float64) *findings.Finding {
	var parts []string
	if d.unanswered > 0 {
		parts = append(parts, fmt.Sprintf("%d quer%s received no response within %s",
			d.unanswered, pluralY(d.unanswered), formatDuration(Thresholds.R11UnansweredWindow)))
	}
	if d.servfail > 0 {
		parts = append(parts, fmt.Sprintf("%d returned SERVFAIL", d.servfail))
	}
	if d.nxdomain > 0 {
		parts = append(parts, fmt.Sprintf("%d returned NXDOMAIN", d.nxdomain))
	}
	obs := joinParts(parts) + "."
	if obs == "." {
		obs = ""
	}

	if d.success.Count() > 0 {
		med := d.success.Percentile(0.50)
		obs += fmt.Sprintf(" Successful lookups to the same resolver took %s at the median.",
			formatDuration(seconds(med)))
	}
	if d.slow > 0 {
		obs += fmt.Sprintf(" %d of them exceeded %s.", d.slow,
			formatDuration(Thresholds.R11SlowResponse))
	}

	// Option C. Work that was performed and yielded nothing, measured in the
	// unit that work takes when it succeeds — not a claim that the failures
	// took that long. An error response returns fast; what it cost is a lookup
	// that has to happen again or a connection that never opens.
	unitCost := d.success.Percentile(0.50)
	if d.success.Count() == 0 {
		unitCost = 0
	}
	errorWork := float64(d.servfail+d.nxdomain) * unitCost
	timeLost := d.unansweredS + d.slowExcessS + errorWork

	if d.servfail+d.nxdomain > 0 && d.success.Count() == 0 {
		// Nothing succeeded here, so there is no measured cost of a working
		// lookup to price the failures against. The finding still reports
		// them; it declines to price them rather than substituting a guess.
		obs += " No lookup to this resolver succeeded, so how long one normally takes could not be measured here."
	}

	clients := len(d.clients)
	scope := scoring.ScopeFor(clients, d.queries, pop.TotalHosts())

	return &findings.Finding{
		RuleID:       "R11",
		RuleName:     "dns-failure",
		ScopeKey:     d.addr.String(),
		ScopeKind:    findings.ScopeEndpoint,
		SubjectLabel: d.addr.Addr().String(),
		Title:        fmt.Sprintf("DNS queries failing or slow — resolver %s", d.addr.Addr()),
		Observation:  trimLead(obs),
		CheckNext: "resolver health and reachability. DNS delay of this magnitude will present to " +
			"users as general application slowness, and often gets attributed to the application instead.",
		Frames:     d.evidence.Frames(),
		FirstFrame: d.evidence.FirstFrame(),
		WorstFrame: d.evidence.WorstFrame(),
		TotalCount: uint64(d.unanswered + d.servfail + d.nxdomain + d.slow),
		Quality:    findings.Confirmed,
		Metrics: map[string]any{
			"queries":            d.queries,
			"unanswered":         d.unanswered,
			"servfail":           d.servfail,
			"nxdomain":           d.nxdomain,
			"slow_responses":     d.slow,
			"clients_affected":   clients,
			"failure_rate":       round3(d.failureRate()),
			"median_response_ms": millis(seconds(unitCost)),
			"wasted_work_s":      round3(timeLost),
		},
		Significance: scoring.Significance(scoring.Inputs{
			BaseWeight:       8,
			ImpactSeconds:    timeLost,
			Scope:            scope,
			Value:            d.failureRate(),
			PopulationMedian: populationRate,
			PeerGroup:        peerGroup,
		}),
	}
}

// pluralY gives the "-y/-ies" ending for counts of queries.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// joinParts renders a list as "a, b and c".
func joinParts(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	head := parts[:len(parts)-1]
	out := ""
	for i, p := range head {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out + " and " + parts[len(parts)-1]
}

// trimLead removes a leading space left by an observation whose first clause
// was absent.
func trimLead(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	return s
}
