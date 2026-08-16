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

// ZeroWindowStall implements R01 · zero-window-stall.
//
// A peer advertises a window of 0 having previously advertised non-zero, and
// the sender is blocked from transmitting new data until a window update
// arrives. The interval is measured from the zero-window advertisement to the
// window update, or to the end of the flow if no update arrives.
//
// The rule reports cumulative and maximum stall duration, not event count, and
// works fully on midstream captures: zero multiplied by any window scale
// factor is still zero.
type ZeroWindowStall struct {
	// retained holds one entry per flow that showed a zero-window stall. This
	// is the retained tier — flow state is gone by the time Emit runs.
	retained map[flow.Key]*zwFlowResult

	// flowsObserved counts every TCP flow, including the clean ones. The
	// comparative baseline needs the peers that showed nothing, otherwise a
	// condition isolated to one flow would look like the population norm.
	flowsObserved int
}

// NewZeroWindowStall returns a fresh R01 detector.
func NewZeroWindowStall() *ZeroWindowStall {
	return &ZeroWindowStall{retained: make(map[flow.Key]*zwFlowResult)}
}

// Meta describes R01.
func (r *ZeroWindowStall) Meta() Meta {
	return Meta{
		ID:         "R01",
		Name:       "zero-window-stall",
		BaseWeight: 9,
		Summary:    "A receiver advertised a zero window having previously advertised non-zero, blocking the sender until a window update arrived.",
	}
}

// zwSide tracks the zero-window behaviour of one side of a flow.
type zwSide struct {
	// seenNonZero gates the whole rule: a window of zero only means the
	// receiver stopped accepting data if it was accepting data before.
	// Midstream flows whose first observed window is zero do not qualify.
	seenNonZero bool

	inStall    bool
	stallStart time.Time
	stallFrame uint64

	zeroCount  uint64
	stalls     uint64
	cumulative time.Duration
	maxStall   time.Duration
	maxFrame   uint64

	lastZeroTime time.Time
	evidence     findings.Evidence

	// lastNonZero is the most recent non-zero window advertisement from this
	// side. When a stall opens it becomes the "before" row: a run of Win=0
	// frames does not read as a receiver that stopped accepting data until you
	// can see the window it stopped from.
	lastNonZero    *findings.PacketRef
	openingContext *findings.PacketRef
	// closingContexts are the window updates that ended each stall.
	//
	// Every one of them is kept, not just the longest, because a table that
	// showed only the final recovery would read as one unbroken stall spanning
	// every flagged frame. The recoveries in between are what make it a series
	// of stalls rather than a single long one.
	closingContexts []findings.PacketRef
}

// maxClosingContexts bounds the recovery rows kept per flow, in the same
// spirit as the frame cap: enough to show the shape, not one per event.
const maxClosingContexts = 4

type zwFlowState struct {
	side [2]zwSide
}

// zwFlowResult is the per-flow summary moved into the retained tier when the
// flow ends.
type zwFlowResult struct {
	key flow.Key

	// advertiser is the endpoint that advertised the zero window — the
	// receiver that stopped accepting data.
	advertiser flow.Endpoint
	// peer is the other end, the sender that was blocked.
	peer flow.Endpoint

	zeroCount  uint64
	cumulative time.Duration
	maxStall   time.Duration
	stalls     uint64

	// otherDirCumulative is the same metric for the opposite direction, where
	// both ends stalled. The repetition cap allows one finding per rule per
	// flow, so the worse direction is reported and this is carried as a metric.
	otherDirCumulative time.Duration

	// unresolved reports that the flow ended while still stalled, so the final
	// stall was measured to the end of the flow rather than to a window update.
	unresolved bool

	// proximate reports a zero-window advertisement within the proximity
	// window of a RST on this flow.
	proximate bool

	frames     []uint64
	firstFrame uint64
	worstFrame uint64
	packets    []findings.PacketRef
}

// NewFlow allocates R01's per-flow state.
func (r *ZeroWindowStall) NewFlow() any {
	s := &zwFlowState{}
	s.side[flow.DirAToB].evidence.Mode = findings.ModeFirst
	s.side[flow.DirBToA].evidence.Mode = findings.ModeFirst
	return s
}

// OnPacket folds one packet into the zero-window state of the side that sent
// it. The window field belongs to the sender: it is what that side is willing
// to receive.
func (r *ZeroWindowStall) OnPacket(fs any, fl *flow.State, p *capture.Packet, dir flow.Direction) {
	s, ok := fs.(*zwFlowState)
	if !ok {
		return
	}
	side := &s.side[dir]

	// A RST carries no meaningful window, and a bare SYN's window is the
	// initial offer rather than an update.
	if p.AnyFlag(capture.FlagRST) {
		return
	}

	if p.Window > 0 {
		side.seenNonZero = true
		if side.inStall {
			// Window update: the sender is unblocked. Snapshot it before
			// closing, so the longest stall can keep the frame that ended it.
			ref := findings.SnapshotPacket(p, findings.RoleContext,
				"Window update — the sender can send again", "TCP Window Update")
			r.closeStall(side, p.Time, &ref)
			return
		}
		if p.AnyFlag(capture.FlagACK) {
			ref := findings.SnapshotPacket(p, findings.RoleContext,
				"Still accepting data at this point", "")
			ref.Markers = nil
			side.lastNonZero = &ref
		}
		return
	}

	// Window is zero. Only an acknowledgement carries a meaningful window
	// update, and only after the side has advertised non-zero at least once.
	if !p.AnyFlag(capture.FlagACK) || p.AnyFlag(capture.FlagSYN) {
		return
	}
	if !side.seenNonZero {
		return
	}

	side.zeroCount++
	side.lastZeroTime = p.Time

	opening := !side.inStall
	note := "Sender still blocked"
	if opening {
		note = "Stall starts here"
	}
	// Snapshotting is deferred: only the frames this finding will actually
	// cite are ever turned into a header record.
	side.evidence.RecordPacket(p.Frame, p.Time, 0, func() findings.PacketRef {
		return findings.SnapshotPacket(p, findings.RoleFlagged, note, "TCP ZeroWindow")
	})

	if opening {
		side.inStall = true
		side.stallStart = p.Time
		side.stallFrame = p.Frame
		if side.openingContext == nil && side.lastNonZero != nil {
			side.openingContext = side.lastNonZero
		}
	}
}

func (r *ZeroWindowStall) closeStall(side *zwSide, at time.Time, update *findings.PacketRef) {
	d := at.Sub(side.stallStart)
	if d < 0 {
		d = 0
	}
	side.cumulative += d
	side.stalls++
	if update != nil && len(side.closingContexts) < maxClosingContexts {
		u := *update
		u.Note = fmt.Sprintf("Window update — the sender can send again after %s", formatDuration(d))
		side.closingContexts = append(side.closingContexts, u)
	}
	if d > side.maxStall {
		side.maxStall = d
		side.maxFrame = side.stallFrame
		// The worst occurrence is the advertisement that opened the longest
		// stall, so the frame list always points at the interesting one. The
		// duration is only known now, which is why this is a Note and not a
		// second Record.
		side.evidence.Note(side.stallFrame, side.stallStart, d.Seconds())
	}
	side.inStall = false
}

// OnFlowEnd closes any open stall and moves the summary into the retained
// tier. A stall still open when the flow ends is measured to the end of the
// flow, per the rule condition.
func (r *ZeroWindowStall) OnFlowEnd(fs any, fl *flow.State) {
	r.flowsObserved++

	s, ok := fs.(*zwFlowState)
	if !ok {
		return
	}

	var unresolved [2]bool
	for d := range s.side {
		side := &s.side[d]
		if side.inStall {
			unresolved[d] = true
			// The rule condition measures to the end of the flow where no
			// window update ever arrives.
			// No window update ever arrived, so there is no closing frame to
			// show; the stall is measured to the end of the flow.
			r.closeStall(side, fl.LastSeen, nil)
		}
	}

	if s.side[flow.DirAToB].zeroCount == 0 && s.side[flow.DirBToA].zeroCount == 0 {
		return
	}

	// Both ends can stall, but the repetition cap allows one finding per rule
	// per flow. The direction with the greater cumulative stall is reported
	// and the other is carried as a metric. Ties fall to A→B so the choice is
	// deterministic.
	worst := flow.DirAToB
	a, b := &s.side[flow.DirAToB], &s.side[flow.DirBToA]
	if b.cumulative > a.cumulative || (b.cumulative == a.cumulative && a.zeroCount == 0) {
		worst = flow.DirBToA
	}

	side := &s.side[worst]

	res := &zwFlowResult{
		key:                fl.Key,
		advertiser:         fl.Key.Endpoint(worst),
		peer:               fl.Key.Endpoint(worst.Other()),
		zeroCount:          side.zeroCount,
		stalls:             side.stalls,
		cumulative:         side.cumulative,
		maxStall:           side.maxStall,
		otherDirCumulative: s.side[worst.Other()].cumulative,
		unresolved:         unresolved[worst],
		frames:             side.evidence.Frames(),
		firstFrame:         side.evidence.FirstFrame(),
		worstFrame:         side.maxFrame,
	}
	if res.worstFrame == 0 {
		res.worstFrame = side.evidence.WorstFrame()
	}

	// The frames the reader should look at: the window before it closed, the
	// zero-window advertisements themselves, and the update that reopened it.
	// The middle rows say what was flagged; the outer two say why it stood out.
	res.packets = append(res.packets, side.evidence.Packets()...)
	if side.openingContext != nil {
		res.packets = append(res.packets, *side.openingContext)
	}
	res.packets = append(res.packets, side.closingContexts...)
	findings.SortPacketRefs(res.packets)

	// Proximity: a zero-window advertisement within the window of a RST on
	// this flow outranks the same condition during steady state.
	if fl.SawRST && !side.lastZeroTime.IsZero() {
		gap := fl.RSTTime.Sub(side.lastZeroTime).Seconds()
		if gap >= 0 && gap <= scoring.ProximityWindowSeconds {
			res.proximate = true
		}
	}

	r.retained[fl.Key] = res
}

// Emit produces one finding per qualifying flow.
func (r *ZeroWindowStall) Emit(pop *Population, out *findings.Store) {
	keys := make([]flow.Key, 0, len(r.retained))
	for k := range r.retained {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Compare(keys[j]) < 0 })

	// First pass: which flows clear the suppression floor, and the population
	// the survivors are ranked against.
	qualifying := make([]*zwFlowResult, 0, len(keys))
	suppressed := 0
	nonZeroCumulative := make([]float64, 0, len(keys))
	affectedHosts := make(map[netip.Addr]bool)

	for _, k := range keys {
		res := r.retained[k]
		nonZeroCumulative = append(nonZeroCumulative, res.cumulative.Seconds())
		if res.cumulative < Thresholds.R01ZeroWindowMinCumulative {
			suppressed++
			continue
		}
		qualifying = append(qualifying, res)
		affectedHosts[res.advertiser.Addr] = true
	}

	if suppressed > 0 {
		out.AddNote(findings.Note{
			Kind:   "info",
			RuleID: "R01",
			Text: fmt.Sprintf(
				"%d flow%s advertised a zero receive window but stalled the sender for less than %s in total, and were not reported. Duration is the signal for this check, not occurrence.",
				suppressed, pluralInt(suppressed), formatDuration(Thresholds.R01ZeroWindowMinCumulative)),
		})
	}

	if len(qualifying) == 0 {
		return
	}

	// The population is every TCP flow in the capture, with the clean ones
	// counted as zero. A condition present uniformly is background; a
	// condition isolated to one flow while its peers are clean is the thing
	// worth reading first.
	populationMedian := stats.MedianWithZeros(nonZeroCumulative, pop.TCPFlows)
	peerGroup := pop.TCPFlows >= 2

	// Whether the peer hosts are clean decides whether the comparative
	// sentence in the specified wording can be stated at all.
	totalHosts := pop.TotalHosts()
	hostsAffected := len(affectedHosts)
	scope := scoring.ScopeFor(hostsAffected, len(qualifying), totalHosts)

	for _, res := range qualifying {
		otherHosts := totalHosts - 1
		if otherHosts < 0 {
			otherHosts = 0
		}
		peersClean := hostsAffected == 1 && otherHosts > 0

		// Specified wording, parameterised. RULES.md R01:
		//
		//   Receiver stopped accepting data — 10.2.2.7:5432
		//   Advertised a zero receive window 6 times, stalling the sender for
		//   4.2s total (longest single stall 2.9s). The other 12 hosts in this
		//   capture show no zero window events.
		//   Check next: the receiving application on 10.2.2.7 — a zero window
		//   means the application is not reading from its socket buffer fast
		//   enough. Look at CPU, blocked threads, or a downstream dependency
		//   on that host.
		title := fmt.Sprintf("Receiver stopped accepting data — %s", res.advertiser)

		obs := fmt.Sprintf(
			"Advertised a zero receive window %d time%s, stalling the sender for %s total (longest single stall %s).",
			res.zeroCount, plural(res.zeroCount),
			formatDuration(res.cumulative), formatDuration(res.maxStall))

		if peersClean {
			obs += fmt.Sprintf(
				" The other %d host%s in this capture show no zero window events.",
				otherHosts, pluralInt(otherHosts))
		}

		checkNext := fmt.Sprintf(
			"the receiving application on %s — a zero window means the application is not reading from its socket buffer fast enough. Look at CPU, blocked threads, or a downstream dependency on that host.",
			res.advertiser.Addr)

		metrics := map[string]any{
			"zero_window_advertisements":   res.zeroCount,
			"stall_episodes":               res.stalls,
			"cumulative_stall_ms":          millis(res.cumulative),
			"max_stall_ms":                 millis(res.maxStall),
			"flow":                         res.key.String(),
			"blocked_sender":               res.peer.String(),
			"hosts_with_zero_window":       hostsAffected,
			"hosts_total":                  totalHosts,
			"stall_unresolved_at_flow_end": res.unresolved,
		}
		if res.otherDirCumulative > 0 {
			metrics["opposite_direction_cumulative_stall_ms"] = millis(res.otherDirCumulative)
		}

		f := &findings.Finding{
			RuleID:       "R01",
			RuleName:     "zero-window-stall",
			ScopeKey:     res.key.String(),
			ScopeKind:    findings.ScopeFlow,
			SubjectLabel: res.advertiser.String(),
			Title:        title,
			Observation:  obs,
			CheckNext:    checkNext,
			Frames:       res.frames,
			FirstFrame:   res.firstFrame,
			WorstFrame:   res.worstFrame,
			TotalCount:   res.zeroCount,
			// R01 degrades in no way: zero multiplied by any window scale
			// factor is still zero, so the detection is directly observed even
			// on midstream flows.
			Quality: findings.Confirmed,
			Packets: finalisePackets(res.packets, pop.CaptureStart),
			Metrics: metrics,
			Significance: scoring.Significance(scoring.Inputs{
				BaseWeight:       9,
				ImpactSeconds:    res.cumulative.Seconds(),
				Scope:            scope,
				Value:            res.cumulative.Seconds(),
				PopulationMedian: populationMedian,
				PeerGroup:        peerGroup,
				Proximate:        res.proximate,
			}),
		}
		out.Add(f)
	}
}
