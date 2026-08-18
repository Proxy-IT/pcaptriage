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

// SynUnanswered implements R02 · syn-unanswered.
//
// A SYN with no SYN/ACK and no RST within the flow's observation window: the
// connecting side asked, and nothing came back at all. Silence is a different
// answer from refusal — R03's RST proves something was reachable and chose to
// say no, while silence usually means the request never reached anything able
// to respond.
//
// Retry SYNs are counted rather than treated as separate attempts: one flow
// that retried four times is one finding with a count of four, per the
// repetition cap.
type SynUnanswered struct {
	// retained holds one entry per flow whose SYNs went unanswered.
	retained map[flow.Key]*synFlowResult

	// respondingServers records addresses that answered a handshake somewhere
	// in the capture — SYN/ACK or RST, since either proves something is home.
	// It is what licenses the "other services on this host responded normally"
	// sentence, which must not be said about a host that answered nothing.
	respondingServers map[netip.Addr]int
	// attemptedServers counts flows that tried each address, so "other
	// services" can be distinguished from "this was the only one tried".
	attemptedServers map[netip.Addr]int

	// independentOneWay counts one-way flows that are NOT this rule's own
	// candidates.
	//
	// An unanswered connection attempt is one-way by construction — that is
	// the condition being reported. Counting it as evidence of asymmetric
	// routing would let the finding cite itself as the reason to doubt itself,
	// so the asymmetry caveat is licensed only by flows R02 is not reporting.
	independentOneWay int
}

// NewSynUnanswered returns a fresh R02 detector.
func NewSynUnanswered() *SynUnanswered {
	return &SynUnanswered{
		retained:          make(map[flow.Key]*synFlowResult),
		respondingServers: make(map[netip.Addr]int),
		attemptedServers:  make(map[netip.Addr]int),
	}
}

// Meta describes R02.
func (r *SynUnanswered) Meta() Meta {
	return Meta{
		ID:         "R02",
		Name:       "syn-unanswered",
		BaseWeight: 9,
		Summary:    "A connection attempt received no answer at all — no acceptance and no refusal — despite the client retrying.",
	}
}

// synFlowState is R02's per-flow packet-path state.
type synFlowState struct {
	// synCount counts SYNs sent by the initiating side, retries included.
	synCount uint64
	// firstSYN and lastSYN bound the attempt window.
	firstSYN, lastSYN time.Time
	initiator         flow.Direction
	haveInitiator     bool

	// gaps are the intervals between successive SYNs, for the backoff check.
	// Bounded: the shape is established within a handful of retries and a
	// pathological flow must not grow this without limit.
	gaps []time.Duration

	// answered marks a SYN/ACK or RST arriving from the other side — either
	// ends R02's interest in the flow.
	answered bool

	// dataSeen marks payload in either direction. A flow that carried data is
	// established by definition, whatever this rule saw of its handshake.
	dataSeen bool

	evidence findings.Evidence
}

// maxSYNGaps bounds the retained retry intervals.
const maxSYNGaps = 8

// synFlowResult is the per-flow summary moved into the retained tier.
type synFlowResult struct {
	key       flow.Key
	client    flow.Endpoint
	server    flow.Endpoint
	attempts  uint64
	firstSYN  time.Time
	lastSYN   time.Time
	span      time.Duration
	backoff   bool
	frames    []uint64
	first     uint64
	worst     uint64
	packets   []findings.PacketRef
	truncated bool
}

// NewFlow allocates R02's per-flow state.
func (r *SynUnanswered) NewFlow() any {
	s := &synFlowState{}
	s.evidence.Mode = findings.ModeFirst
	return s
}

// OnPacket folds one packet into the handshake state.
func (r *SynUnanswered) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*synFlowState)
	if !ok {
		return
	}

	syn := p.AnyFlag(capture.FlagSYN)
	ack := p.AnyFlag(capture.FlagACK)

	switch {
	case syn && !ack:
		// A bare SYN. The side sending it is the initiator; a SYN from the
		// other direction afterwards is a simultaneous open, which is not this
		// rule's business and is left to fall through as "answered".
		if !s.haveInitiator {
			s.haveInitiator = true
			s.initiator = dir
			s.firstSYN = p.Time
		} else if dir != s.initiator {
			s.answered = true
			return
		} else if len(s.gaps) < maxSYNGaps {
			s.gaps = append(s.gaps, p.Time.Sub(s.lastSYN))
		}
		s.synCount++
		s.lastSYN = p.Time
		s.evidence.RecordPacket(p.Frame, p.Time, 0, func() findings.PacketRef {
			note := "Connection attempt"
			if s.synCount > 1 {
				note = fmt.Sprintf("Retry %d, %s after the previous attempt",
					s.synCount-1, formatDuration(p.Time.Sub(s.firstSYN)))
			}
			return findings.SnapshotPacket(p, findings.RoleFlagged, note, "TCP SYN")
		})

	case syn && ack:
		s.answered = true

	case p.AnyFlag(capture.FlagRST):
		// A refusal is an answer. R03 owns that case; R02 must not also
		// report it, or one refused connection would produce two findings
		// saying different things about the same frames.
		s.answered = true
	}

	if p.PayloadLength > 0 {
		s.dataSeen = true
	}
}

// OnFlowEnd moves the per-flow summary into the retained tier.
func (r *SynUnanswered) OnFlowEnd(fs any, fl *flow.State) {
	s, ok := fs.(*synFlowState)
	if !ok || !s.haveInitiator {
		return
	}

	server := fl.Key.Endpoint(s.initiator.Other())
	r.attemptedServers[server.Addr]++
	if s.answered || s.dataSeen {
		r.respondingServers[server.Addr]++
		if fl.OneWay() {
			// One-way despite having been answered: genuine evidence that this
			// capture point sees only one side of some conversations.
			r.independentOneWay++
		}
		return
	}
	if s.synCount == 0 {
		return
	}

	res := &synFlowResult{
		key:      fl.Key,
		client:   fl.Key.Endpoint(s.initiator),
		server:   server,
		attempts: s.synCount,
		firstSYN: s.firstSYN,
		lastSYN:  s.lastSYN,
		span:     s.lastSYN.Sub(s.firstSYN),
		backoff:  backoffObserved(s.gaps),
		frames:   s.evidence.Frames(),
		first:    s.evidence.FirstFrame(),
		worst:    s.evidence.WorstFrame(),
		packets:  s.evidence.Packets(),
	}
	if res.worst == 0 {
		res.worst = res.first
	}
	r.retained[fl.Key] = res
}

// backoffObserved reports whether successive retry intervals grew, which is
// what "the client retried with standard backoff" claims.
//
// Growth rather than exact doubling: the specified pattern is 1s, 2s, 4s, 8s,
// but timers jitter and a capture's timestamps are not the client's clock, so
// demanding exact ratios would miss real backoff. A single retry cannot
// establish a pattern and is not called one.
func backoffObserved(gaps []time.Duration) bool {
	if len(gaps) < 2 {
		return false
	}
	for i := 1; i < len(gaps); i++ {
		if float64(gaps[i]) < float64(gaps[i-1])*Thresholds.R02BackoffMinRatio {
			return false
		}
	}
	return true
}

// Emit produces one finding per flow whose connection attempts went
// unanswered.
func (r *SynUnanswered) Emit(pop *Population, out *findings.Store) {
	keys := make([]flow.Key, 0, len(r.retained))
	for k := range r.retained {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Compare(keys[j]) < 0 })

	// A capture that stopped while a handshake was still in flight has not
	// observed silence — it has stopped watching. RULES.md suppresses SYNs
	// within 2s of capture end for exactly this reason.
	var truncated int
	qualifying := make([]*synFlowResult, 0, len(keys))
	affectedHosts := make(map[netip.Addr]bool)
	for _, k := range keys {
		res := r.retained[k]
		if !pop.CaptureEnd.IsZero() &&
			pop.CaptureEnd.Sub(res.lastSYN) < Thresholds.R02CaptureEndSuppression {
			truncated++
			continue
		}
		qualifying = append(qualifying, res)
		affectedHosts[res.server.Addr] = true
	}

	if truncated > 0 {
		out.AddNote(findings.Note{
			Kind:   "info",
			RuleID: "R02",
			Text: fmt.Sprintf(
				"%d connection attempt%s had not been answered when the capture ended, within %s of the last frame. "+
					"A reply may have arrived after the capture stopped, so these are not reported as unanswered.",
				truncated, pluralInt(truncated), formatDuration(Thresholds.R02CaptureEndSuppression)),
		})
	}

	if len(qualifying) == 0 {
		return
	}

	scope := scoring.ScopeFor(len(affectedHosts), len(qualifying), pop.TotalHosts())

	// One-way flows mean this capture point sees only one direction of some
	// conversations, so a reply may exist on a path it never observes. That is
	// the asymmetric-routing trap, and it is stated only when the capture
	// shows the asymmetry somewhere other than in the findings themselves —
	// see independentOneWay.
	asymmetric := r.independentOneWay > 0

	for _, res := range qualifying {
		// Specified wording, parameterised. RULES.md R02:
		//
		//   Connection attempts received no response — 10.1.1.5 → 10.4.4.9:8443
		//   4 SYN attempts over 15s, no SYN/ACK and no RST returned. The client
		//   retried with standard backoff. Other services on 10.4.4.9 responded
		//   normally.
		//   Check next: a silent drop, not a closed port — a closed port returns
		//   RST. Look at firewall or security group rules on the path, or whether
		//   the listener is bound to a different interface.
		title := fmt.Sprintf("Connection attempts received no response — %s → %s",
			res.client.Addr, res.server)

		obs := fmt.Sprintf("%d SYN attempt%s over %s, no SYN/ACK and no RST returned.",
			res.attempts, plural(res.attempts), formatDuration(res.span))
		if res.backoff {
			obs += " The client retried with standard backoff."
		}
		// Only said when this host answered something else. A host that
		// answered nothing at all is a different situation, and claiming its
		// other services were fine would be inventing evidence.
		if others := r.respondingServers[res.server.Addr]; others > 0 {
			obs += fmt.Sprintf(" Other services on %s responded normally.", res.server.Addr)
		}
		if asymmetric {
			obs += fmt.Sprintf(
				" %d other flow%s in this capture %s seen in one direction only, so a reply on a path this capture point does not observe cannot be ruled out.",
				r.independentOneWay, pluralInt(r.independentOneWay), wasWere(r.independentOneWay))
		}

		metrics := map[string]any{
			"syn_attempts":     res.attempts,
			"attempt_span_ms":  millis(res.span),
			"backoff_observed": res.backoff,
			"server":           res.server.String(),
			"client":           res.client.String(),
			"flow":             res.key.String(),
		}
		if others := r.respondingServers[res.server.Addr]; others > 0 {
			metrics["other_responding_flows_to_host"] = others
		}

		f := &findings.Finding{
			RuleID:       "R02",
			RuleName:     "syn-unanswered",
			ScopeKey:     res.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: fmt.Sprintf("%s → %s", res.client.Addr, res.server),
			Title:        title,
			Observation:  obs,
			CheckNext:    "a silent drop, not a closed port — a closed port returns RST. Look at firewall or security group rules on the path, or whether the listener is bound to a different interface.",
			Frames:       res.frames,
			FirstFrame:   res.first,
			WorstFrame:   res.worst,
			TotalCount:   res.attempts,
			// Directly observed: the absence of a reply is as visible as a
			// reply would have been, given the capture covers the window.
			Quality: findings.Confirmed,
			Packets: finalisePackets(res.packets, pop.CaptureStart),
			Metrics: metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight: 9,
				// The time the connecting side spent waiting is the cost:
				// nothing moved for the whole attempt window.
				ImpactSeconds: res.span.Seconds(),
				Scope:         scope,
				PeerGroup:     false,
			}),
		}
		out.Add(f)
	}
}
