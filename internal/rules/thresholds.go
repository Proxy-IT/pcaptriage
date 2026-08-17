package rules

import "time"

// Thresholds are collected here rather than scattered through detector code,
// because they will be recalibrated repeatedly against real captures.
//
// Every value below is a STARTING POINT, not a validated constant.
// Environments differ by orders of magnitude: 200 ms RTT is catastrophic in a
// datacenter and normal on satellite. Where a comparative path and an absolute
// path both exist, the comparative one is primary and the absolute one is the
// fallback for captures with no usable peer group.
//
// Provenance is marked on each value:
//
//	[RULES.md]  stated in the rule specification
//	[chosen]    not in the specification; picked here and open to change
var Thresholds = struct {
	// R01ZeroWindowMinCumulative suppresses zero-window findings below this
	// cumulative stall. Duration is the signal, not occurrence: sub-50ms zero
	// windows during normal operation are common and meaningless.
	// [RULES.md] "Suppress below 100 ms cumulative."
	R01ZeroWindowMinCumulative time.Duration

	// R04MinExchanges is how many completed request/response exchanges a
	// server endpoint needs before its percentiles are reported. Below this a
	// p95 is not a distribution, it is one slow request.
	// [chosen] RULES.md states no minimum. Five is low enough not to
	// over-suppress and high enough that p95 is not simply the maximum of two
	// samples. Endpoints below it are reported as not assessed, never
	// silently dropped.
	R04MinExchanges uint64

	// R04PeerRatio flags a server whose p95 exceeds the capture-wide
	// population median by at least this factor.
	// [RULES.md] "exceeds the capture-wide population median by ≥5×"
	R04PeerRatio float64

	// R04AbsoluteP95 flags a server whose p95 exceeds this, used only where no
	// peer group exists.
	// [RULES.md] "or exceeds 1s absolute where no peer group exists"
	R04AbsoluteP95 time.Duration

	// R04MinPeerGroup is how many qualifying server endpoints constitute a
	// peer group. Below it, comparative ranking is reported as unavailable and
	// the absolute threshold is used.
	// [chosen] Two is the smallest number that permits a comparison at all.
	R04MinPeerGroup int

	// R04NetworkComparableRatio gates the closing sentence of the R04 wording,
	// "The network path to this host looks comparable to its peers." The
	// sentence is only emitted when this server's network RTT is below this
	// multiple of the capture-wide median RTT — otherwise the claim is not
	// supported and the sentence is omitted.
	// [chosen] Mirrors R10's ≥4× RTT outlier threshold so the two rules agree
	// about what counts as elevated latency.
	R04NetworkComparableRatio float64

	// R04FlowExchangeBuffer bounds the per-flow exchange buffer on the packet
	// path. When it fills, exchanges are flushed to the retained per-server
	// aggregate using the RTT known at that moment.
	// [chosen] Keeps per-flow state around a kilobyte so the flow cap
	// translates to a predictable memory ceiling.
	R04FlowExchangeBuffer int

	// SeveritySignificantFloor and SeverityWorthNotingFloor split the
	// significance score into the three words a card shows.
	//
	// These are presentation calibration only. They do not change ranking, they
	// do not suppress anything, and nothing is hidden below the lower one —
	// there is no display floor (see the BACKLOG P4 note and the RULES.md
	// addendum). Every emitted finding is shown; these decide which word it
	// carries.
	//
	// [chosen] Anchored on three reference findings rather than picked to make
	// the current fixtures look varied:
	//
	//   40.4  a mid-weight rule (base 7) reporting one second of lost time,
	//         isolated to one host while its peers are clean
	//   18.1  R06 fast retransmit at 0.9% against a 0.1% capture median,
	//         costing 340ms — the example in RULES.md whose own wording is
	//         "worth noting but unlikely to be the cause of a user-visible
	//         problem on its own"
	//    5.0  R06 at a healthy 0.3% spread uniformly across the capture, which
	//         RULES.md calls "a healthy internet path"
	//
	// The middle anchor is the load-bearing one: the rule set already describes
	// that case in the words this vocabulary uses, so the boundary is read off
	// the specification rather than guessed.
	SeveritySignificantFloor float64
	SeverityWorthNotingFloor float64

	// CoverageStrongRequiresNoGaps and CoverageStrongRequiresCompleteRuleSet
	// are the conditions under which the clean-capture banner may go green.
	//
	// Green is a visual all-clear, and the clean screen's wording is tested
	// against claiming one. Colour must not say what the words are forbidden
	// from saying, so it is withheld unless the coverage genuinely supports it.
	//
	// [chosen] Both are required. Gaps mean checks could not run on this
	// capture; an incomplete rule set means checks do not exist to run at all.
	// Either one makes "all clear" an overstatement, and at the current 2-of-15
	// build state the second is always true — so the banner is neutral today,
	// by design rather than by accident.
	CoverageStrongRequiresNoGaps          bool
	CoverageStrongRequiresCompleteRuleSet bool

	// R07ReorderMaxDelta is the inter-arrival window inside which a segment
	// below the high-water mark reads as reordering rather than retransmission,
	// provided IP ID ordering agrees.
	// [RULES.md] "the inter-arrival delta is under 3 ms"
	R07ReorderMaxDelta time.Duration

	// R06DupAckMin is how many duplicate ACKs must precede a retransmission
	// for it to read as fast recovery.
	// [RULES.md] "preceded by ≥3 duplicate ACKs"
	R06DupAckMin int

	// R05MinRTOGap is the minimum quiet gap before a retransmission that reads
	// as a timer expiry rather than fast-path timing.
	// [chosen] RULES.md says "approximating an RTO interval" without a figure.
	// 200ms is Linux's minimum RTO (RFC 6298 specifies 1s, but no deployed
	// stack waits that long); below it a gap is delayed-ACK territory, not a
	// timer. Wants calibration against real captures.
	R05MinRTOGap time.Duration

	// R05BackoffMinRatio is how much successive retry intervals for the same
	// segment must grow before "retry intervals doubled each attempt" is
	// stated. Backoff doubles in theory; jitter and timestamp resolution mean
	// demanding exactly 2× would miss real backoff.
	// [chosen] 1.5 is above any plausible jitter and below every doubling.
	R05BackoffMinRatio float64

	// R08MinRatio is how many times higher one direction's retransmission
	// rate must be than the reverse direction's before loss is asymmetric.
	// [RULES.md] "exceeding the reverse direction by ≥5×"
	R08MinRatio float64

	// R08MinRetransmissions is the minimum retransmission count the worse
	// direction must reach before R08 considers the flow at all.
	// [RULES.md] "a minimum of 20 retransmissions to qualify"
	R08MinRetransmissions int

	// R15KernelDropRatio is the share of the capture the capture host must have
	// dropped before loss findings are treated as ambiguous.
	//
	// Packets the capture host discarded are indistinguishable from packets
	// lost on the wire, so above this figure a reported loss rate might be
	// describing the capture rather than the network.
	//
	// [chosen] RULES.md gives no figure. 0.1% is the order of magnitude the
	// loss rules themselves work at — R06's own example contrasts a 0.9% rate
	// against a 0.1% capture median — so below it capture loss cannot plausibly
	// account for a rate a rule would flag, and above it, it can. Wants
	// calibration against real captures like every other threshold here.
	R15KernelDropRatio float64
}{
	R01ZeroWindowMinCumulative: 100 * time.Millisecond,

	R04MinExchanges:           5,
	R04PeerRatio:              5.0,
	R04AbsoluteP95:            1 * time.Second,
	R04MinPeerGroup:           2,
	R04NetworkComparableRatio: 4.0,
	R04FlowExchangeBuffer:     32,

	SeveritySignificantFloor: 40,
	SeverityWorthNotingFloor: 15,

	CoverageStrongRequiresNoGaps:          true,
	CoverageStrongRequiresCompleteRuleSet: true,

	R07ReorderMaxDelta: 3 * time.Millisecond,
	R06DupAckMin:       3,
	R05MinRTOGap:       200 * time.Millisecond,
	R05BackoffMinRatio: 1.5,

	R08MinRatio:           5.0,
	R08MinRetransmissions: 20,

	R15KernelDropRatio: 0.001, // 0.1% of packets read
}
