package rules

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
)

// The classifier is the suppression seam, so it is tested directly: packets
// go in, exactly one bucket fills. The fixtures exercise the same paths
// end-to-end; these tests are where a misclassification is cheapest to
// diagnose.

var lossT0 = time.Date(2024, 3, 14, 9, 0, 0, 0, time.UTC)

type lossHarness struct {
	a  *lossAnalyzer
	s  *lossFlowState
	fl *flow.State
}

func newLossHarness() *lossHarness {
	a := newLossAnalyzer()
	key, _ := flow.MakeKey(capture.ProtoTCP,
		flow.Endpoint{Addr: netip.MustParseAddr("10.0.0.1"), Port: 10001},
		flow.Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 443})
	return &lossHarness{a: a, s: a.newFlow(), fl: &flow.State{Key: key}}
}

// seg feeds one data segment; ipid mimics the synthesizer's derivation when
// zero is passed, so tests only state an IP ID when the test is about it.
func (h *lossHarness) seg(dir flow.Direction, at time.Duration, seq uint32, n int, ipid uint16) {
	if ipid == 0 {
		ipid = uint16(seq >> 8)
	}
	p := &capture.Packet{
		Time: lossT0.Add(at), IPVersion: 4, IPID: ipid,
		Seq: seq, Flags: capture.FlagACK | capture.FlagPSH, Window: 65535, PayloadLength: n,
	}
	h.fl.DataSegments[dir]++
	h.fl.Packets[dir]++
	h.a.onPacket(h.s, h.fl, p, dir)
}

// ack feeds one pure ACK.
func (h *lossHarness) ack(dir flow.Direction, at time.Duration, ack uint32, win uint16) {
	p := &capture.Packet{
		Time: lossT0.Add(at), IPVersion: 4,
		Ack: ack, Flags: capture.FlagACK, Window: win,
	}
	h.fl.Packets[dir]++
	h.a.onPacket(h.s, h.fl, p, dir)
}

func (h *lossHarness) counts(dir flow.Direction) (reorder, fast, rto, unclassified uint64) {
	d := &h.s.dir[dir]
	return d.reorder, d.fast, d.rto, d.unclassified
}

// TestSeamReclassifiesReorderingDespiteDupAckRun is the suppression seam's
// core property: a segment matching the fast-retransmit trigger — three
// duplicate ACKs asking for exactly it — still lands in the reorder bucket
// when it arrived within the reorder window with sane IP ID ordering. R05 and
// R06 read buckets it never enters, so there is no finding to suppress after
// the fact.
func TestSeamReclassifiesReorderingDespiteDupAckRun(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	h.seg(d, 0, 1000, 1000, 0) // in order
	h.ack(d.Other(), 1*time.Millisecond, 2000, 65535)
	// The next-later segment overtakes its predecessor...
	h.seg(d, 10*time.Millisecond, 3000, 1000, 0)
	// ...the receiver asks for the missing one three times...
	h.ack(d.Other(), 10100*time.Microsecond, 2000, 65535)
	h.ack(d.Other(), 10200*time.Microsecond, 2000, 65535)
	h.ack(d.Other(), 10300*time.Microsecond, 2000, 65535)
	// ...and it arrives 0.4ms behind the data that overtook it, with the
	// lower IP ID it was originally sent with.
	h.seg(d, 10400*time.Microsecond, 2000, 1000, 0)

	reorder, fast, rto, un := h.counts(d)
	if reorder != 1 || fast != 0 || rto != 0 || un != 0 {
		t.Errorf("reorder=%d fast=%d rto=%d unclassified=%d; want exactly one reorder", reorder, fast, rto, un)
	}
}

// TestSeamFastRetransmitOutsideReorderWindow is the same trigger without the
// reorder shape: the retransmission arrives well after the reorder window, so
// the duplicate-ACK run decides and the segment is fast recovery.
func TestSeamFastRetransmitOutsideReorderWindow(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	h.seg(d, 0, 1000, 1000, 0)
	h.ack(d.Other(), 1*time.Millisecond, 2000, 65535)
	h.seg(d, 10*time.Millisecond, 3000, 1000, 0)
	h.ack(d.Other(), 11*time.Millisecond, 2000, 65535)
	h.ack(d.Other(), 12*time.Millisecond, 2000, 65535)
	h.ack(d.Other(), 13*time.Millisecond, 2000, 65535)
	h.seg(d, 25*time.Millisecond, 2000, 1000, 0) // 15ms after the overtaker

	reorder, fast, rto, un := h.counts(d)
	if fast != 1 || reorder != 0 || rto != 0 || un != 0 {
		t.Errorf("reorder=%d fast=%d rto=%d unclassified=%d; want exactly one fast", reorder, fast, rto, un)
	}
	if h.s.dir[d].fastTimeCost <= 0 {
		t.Error("fast recovery recorded no time cost")
	}
}

// TestSeamRTOWithBackoff: two retransmissions of the same range after
// timer-shaped gaps, the second twice the first. Both count, both gaps are
// time lost, and the doubling is recorded — it is what licenses the "retry
// intervals doubled" sentence.
func TestSeamRTOWithBackoff(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	h.seg(d, 0, 1000, 1000, 0)
	h.seg(d, 1000*time.Millisecond, 1000, 1000, 0)
	h.seg(d, 3000*time.Millisecond, 1000, 1000, 0)

	_, fast, rto, un := h.counts(d)
	if rto != 2 || fast != 0 || un != 0 {
		t.Errorf("rto=%d fast=%d unclassified=%d; want two rto", rto, fast, un)
	}
	if got := h.s.dir[d].rtoTimeLost; got != 3000*time.Millisecond {
		t.Errorf("rtoTimeLost = %v, want 3s (1s + 2s)", got)
	}
	if !h.s.dir[d].backoffObserved {
		t.Error("a doubled retry interval was not recorded as backoff")
	}
}

// TestSeamRTOEpisodeCountsWithoutDoubleChargingTime: segments retransmitted
// in the wake of a timeout, before new data flows, are timeout-driven too —
// but only the opening gap is time lost.
func TestSeamRTOEpisodeCountsWithoutDoubleChargingTime(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	h.seg(d, 0, 1000, 1000, 0)
	h.seg(d, 10*time.Millisecond, 2000, 1000, 0)
	h.seg(d, 20*time.Millisecond, 3000, 1000, 0)
	// Timer expiry, then the rest of the window follows immediately.
	h.seg(d, 1020*time.Millisecond, 1000, 1000, 0)
	h.seg(d, 1025*time.Millisecond, 2000, 1000, 0)
	h.seg(d, 1030*time.Millisecond, 3000, 1000, 0)

	_, _, rto, _ := h.counts(d)
	if rto != 3 {
		t.Errorf("rto = %d, want 3 (the expiry and its two followers)", rto)
	}
	if got := h.s.dir[d].rtoTimeLost; got != 1000*time.Millisecond {
		t.Errorf("rtoTimeLost = %v, want exactly the opening gap", got)
	}
}

// TestSeamIgnoresZeroWindowProbesAndKeepAlives: flow-control machinery
// re-occupies old sequence space without being loss. The R01 fixtures are
// full of both shapes, and a classifier that miscounted them would light up
// R05 on every zero-window stall.
func TestSeamIgnoresZeroWindowProbesAndKeepAlives(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	h.seg(d, 0, 1000, 1000, 0)
	// Peer closes its window; sender probes with one byte, twice, slowly.
	h.ack(d.Other(), 5*time.Millisecond, 2000, 0)
	h.seg(d, 500*time.Millisecond, 2000, 1, 0)
	h.seg(d, 1500*time.Millisecond, 2000, 1, 0)

	// Window reopens; after a long idle, a keep-alive: one byte just below
	// the high-water mark, which the first probe advanced to 2001.
	h.ack(d.Other(), 2000*time.Millisecond, 2000, 65535)
	h.seg(d, 12*time.Second, 2000, 1, 0)

	reorder, fast, rto, un := h.counts(d)
	if reorder+fast+rto+un != 0 {
		t.Errorf("reorder=%d fast=%d rto=%d unclassified=%d; probes and keep-alives must classify as nothing",
			reorder, fast, rto, un)
	}
}

// TestSeamInsaneIPIDIsNotReordering: the timing fits reordering but the IP ID
// says the segment was created after the data it trails — that is not a late
// original, and the reorder claim cannot be made.
func TestSeamInsaneIPIDIsNotReordering(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	h.seg(d, 0, 1000, 1000, 900)
	h.seg(d, 10*time.Millisecond, 3000, 1000, 901)
	// Arrives inside the reorder window, but with an IP ID after the
	// overtaker's: sent later, so this is a genuine retransmission shape.
	h.seg(d, 10400*time.Microsecond, 2000, 1000, 950)

	reorder, _, _, un := h.counts(d)
	if reorder != 0 {
		t.Error("a segment with an implausible IP ID was reclassified as reordering")
	}
	if un != 1 {
		t.Errorf("unclassified = %d, want 1 (fast trigger absent, gap not timer-shaped)", un)
	}
}

// TestSeamIPv6FallsBackToTimingAlone: no IP ID exists to check, so timing
// decides and the flow is marked so the finding can lower its confidence.
func TestSeamIPv6FallsBackToTimingAlone(t *testing.T) {
	h := newLossHarness()
	d := flow.DirAToB

	v6seg := func(at time.Duration, seq uint32, n int) {
		p := &capture.Packet{
			Time: lossT0.Add(at), IPVersion: 6,
			Seq: seq, Flags: capture.FlagACK | capture.FlagPSH, Window: 65535, PayloadLength: n,
		}
		h.fl.DataSegments[d]++
		h.a.onPacket(h.s, h.fl, p, d)
	}
	v6seg(0, 1000, 1000)
	v6seg(10*time.Millisecond, 3000, 1000)
	v6seg(10500*time.Microsecond, 2000, 1000)

	reorder, _, _, _ := h.counts(d)
	if reorder != 1 {
		t.Errorf("reorder = %d, want 1 via the timing-only path", reorder)
	}
	if !h.s.ipv6 {
		t.Error("the flow was not marked IPv6, so the finding could not lower its confidence")
	}
}

// TestSeamDupAckRunRules: window updates are not duplicates, zero-window ACKs
// are flow control, and a changed acknowledgement resets the run.
func TestSeamDupAckRunRules(t *testing.T) {
	h := newLossHarness()
	recv := flow.DirBToA

	h.seg(flow.DirAToB, 0, 1000, 1000, 0)
	h.ack(recv, 1*time.Millisecond, 2000, 65535) // baseline
	h.ack(recv, 2*time.Millisecond, 2000, 65535) // dup 1
	h.ack(recv, 3*time.Millisecond, 2000, 32000) // window update: not a dup
	h.ack(recv, 4*time.Millisecond, 2000, 32000) // dup 2
	h.ack(recv, 5*time.Millisecond, 2000, 0)     // zero window: flow control, not a dup
	if run := h.s.ack[recv].dupRun; run != 2 {
		t.Errorf("dupRun = %d, want 2 — window updates and zero-window ACKs must not count", run)
	}
	h.ack(recv, 6*time.Millisecond, 3000, 32000) // new ack: run resets
	if run := h.s.ack[recv].dupRun; run != 0 {
		t.Errorf("dupRun = %d after a new acknowledgement, want 0", run)
	}
}
