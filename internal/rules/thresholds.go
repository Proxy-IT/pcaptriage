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

	// R10PeerRatio flags a host whose network round-trip time exceeds the
	// capture-wide median by this multiple.
	// [RULES.md] "exceeding the capture-wide median by ≥4×"
	R10PeerRatio float64

	// R10MinFlows is how many flows to a host are needed before its latency is
	// assessed.
	// [chosen] RULES.md states no minimum. Three is the smallest number that
	// can show whether latency is steady or variable at all — the distinction
	// the finding reports, and the one that separates distance from
	// congestion. Two samples have a spread but no shape.
	R10MinFlows int

	// R10MinPeerHosts is how many other assessed hosts constitute a population
	// to compare against.
	// [chosen] Mirrors R04MinPeerGroup for the same reason: two is the
	// smallest number that permits a comparison, and below it the finding
	// would be a claim about a host with nothing to be elevated relative to.
	R10MinPeerHosts int

	// R10SteadyDispersion separates "steady" latency from "variable" in the
	// R10 wording. It is the ratio of the spread between a host's slowest and
	// fastest observed round trip to its median.
	// [chosen] RULES.md's example calls 22 connections "consistent rather than
	// intermittent" without giving a figure. 0.5 means the spread has to stay
	// inside half the median before the finding will call latency steady,
	// which keeps the stronger claim — distance rather than congestion — the
	// one that needs the tighter evidence.
	R10SteadyDispersion float64

	// R13MinLargeRetransmits is how many retransmissions of over-threshold
	// segments a flow needs before the blackhole pattern is reported.
	// [chosen] RULES.md says "repeated" without a figure. Three is enough to
	// separate a pattern from a coincidence, and matches the retry count a
	// sender typically reaches before giving up on a segment.
	R13MinLargeRetransmits int

	// R13MinSmallDelivered is how many smaller segments must have been
	// acknowledged on the same flow for the contrast to mean anything.
	// [chosen] The signal is "large fails while small succeeds", so the small
	// side needs enough successes to be a control rather than an anecdote.
	// Three mirrors the large side.
	R13MinSmallDelivered int

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

	// R02CaptureEndSuppression is how close to the end of a capture an
	// unanswered SYN may be before R02 declines to report it. A capture that
	// stopped mid-handshake has not observed silence, it has stopped watching.
	// [RULES.md] "Suppress for SYNs within 2s of capture end."
	R02CaptureEndSuppression time.Duration

	// R02BackoffMinRatio is how much each retry interval must grow over the
	// previous one before "the client retried with standard backoff" is
	// stated. RULES.md gives the pattern (1s, 2s, 4s, 8s) but timers jitter
	// and capture timestamps are not the client's clock.
	// [chosen] Mirrors R05BackoffMinRatio, for the same reason and at the
	// same value: demanding exact doubling would miss real backoff.
	R02BackoffMinRatio float64

	// R03TTLTolerance is how far a refusal's TTL may differ from the same
	// host's other traffic before the finding notes that a device on the path
	// may have sent it on the host's behalf.
	// [RULES.md] "Flag when TTL differs by more than 2 from the same peer's
	// established traffic."
	R03TTLTolerance uint8

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

	// R09DataRecencyWindow is how soon after a data segment a reset must
	// arrive to count as interrupting an active transfer, rather than ending
	// a connection that had already gone quiet.
	// [RULES.md] "RST sent on a flow with data in flight or within 1 s of a
	// data segment."
	R09DataRecencyWindow time.Duration

	// R09UniformityMinConnections is how many connections a host must have
	// reset — with no clean close anywhere — before the behaviour is treated
	// as a habit rather than a fault.
	// [chosen] RULES.md says to detect uniformity but gives no minimum. Below
	// a handful, "every connection" is too small a sample to call a habit: one
	// or two resets with no clean close is as easily a fault that happened to
	// hit every connection there was.
	R09UniformityMinConnections int

	// R14MinConnections is how many measurable connections to one server:port
	// are needed before connection reuse is assessed.
	// [RULES.md] "More than 50 connections to the same server:port."
	R14MinConnections int

	// R14MaxMedianLifetime is the median connection lifetime below which
	// connections are treated as cycling rather than being reused.
	// [RULES.md] "with a median lifetime under 1 s".
	R14MaxMedianLifetime time.Duration

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

	R10PeerRatio:        4.0,
	R10MinFlows:         3,
	R10MinPeerHosts:     2,
	R10SteadyDispersion: 0.5,

	R13MinLargeRetransmits: 3,
	R13MinSmallDelivered:   3,

	SeveritySignificantFloor: 40,
	SeverityWorthNotingFloor: 15,

	CoverageStrongRequiresNoGaps:          true,
	CoverageStrongRequiresCompleteRuleSet: true,

	R02CaptureEndSuppression: 2 * time.Second,
	R02BackoffMinRatio:       1.5,
	R03TTLTolerance:          2,

	R07ReorderMaxDelta: 3 * time.Millisecond,
	R06DupAckMin:       3,
	R05MinRTOGap:       200 * time.Millisecond,
	R05BackoffMinRatio: 1.5,

	R08MinRatio:           5.0,
	R08MinRetransmissions: 20,

	R09DataRecencyWindow:        1 * time.Second,
	R09UniformityMinConnections: 5,
	R14MinConnections:           50,
	R14MaxMedianLifetime:        1 * time.Second,

	R15KernelDropRatio: 0.001, // 0.1% of packets read
}
