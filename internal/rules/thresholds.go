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
}{
	R01ZeroWindowMinCumulative: 100 * time.Millisecond,

	R04MinExchanges:           5,
	R04PeerRatio:              5.0,
	R04AbsoluteP95:            1 * time.Second,
	R04MinPeerGroup:           2,
	R04NetworkComparableRatio: 4.0,
	R04FlowExchangeBuffer:     32,
}
