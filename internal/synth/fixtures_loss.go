package synth

import (
	"fmt"
	"time"
)

// The Batch 1 loss fixtures. Each models one shape from the loss cluster —
// timeout recovery, fast recovery, reordering — with clean peer conversations
// so the rates the rules report are measured against a population.

// buildR05Positive is the R05 fixture: three timeout-driven retransmissions
// across two recovery episodes, costing 4.5s, with exponential backoff
// observed in the first episode. Eight clean peer conversations give the
// capture a population against which an 11% retransmission rate on one path
// is an outlier rather than background.
func buildR05Positive() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "10.1.1.5:44300", Server: "10.3.3.2:445",
		ClientISN: 40000, ServerISN: 90000,
	})
	c.HandshakeWithOptions(0, 10*ms, 1460, true)

	// Twenty clean segments, each acknowledged promptly.
	t := 30 * ms
	for i := 0; i < 20; i++ {
		c.ClientData(t, 1000)
		c.ServerAck(t+5*ms, 64000)
		t += 15 * ms
	}

	// First episode: a segment goes unacknowledged, the retransmission timer
	// expires after 1.0s, and the retry itself is lost too — the second
	// attempt waits 2.0s, which is the doubling the wording reports.
	t1 := t + 20*ms
	c.ClientData(t1, 1000)
	seq1 := c.cseq - 1000
	c.ClientSegmentAt(t1+1000*ms, seq1, 1000)
	c.ClientSegmentAt(t1+3000*ms, seq1, 1000)
	c.ServerAck(t1+3010*ms, 64000)

	// Five clean segments between episodes, so the two stalls read as
	// distinct events rather than one long outage.
	t = t1 + 3100*ms
	for i := 0; i < 5; i++ {
		c.ClientData(t, 1000)
		c.ServerAck(t+5*ms, 64000)
		t += 15 * ms
	}

	// Second episode: one timer expiry, 1.5s.
	t2 := t + 20*ms
	c.ClientData(t2, 1000)
	seq2 := c.cseq - 1000
	c.ClientSegmentAt(t2+1500*ms, seq2, 1000)
	c.ServerAck(t2+1510*ms, 64000)

	c.FinClose(t2+1600*ms, 5*ms)

	// Clean peer conversations on other hosts.
	for i := 0; i < 8; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.30:%d", 47000+i),
			Server:    fmt.Sprintf("10.4.4.%d:443", 10+i),
			ClientISN: uint32(220000 + i*1000),
			ServerISN: uint32(670000 + i*1000),
		})
		start := 100*ms + time.Duration(i)*600*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}

// buildR06Positive is the R06 fixture: two loss events on a server-to-client
// stream, each recovered by fast retransmit after three duplicate ACKs. The
// capture point sits on the client side of the loss, so the lost original
// never appears in the file — only the hole, the duplicate ACKs asking for
// it, and the retransmission that fills it.
func buildR06Positive() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "10.6.6.5:52100", Server: "10.7.7.2:443",
		ClientISN: 60000, ServerISN: 160000,
	})
	c.HandshakeWithOptions(0, 10*ms, 1460, true)
	c.ClientData(25*ms, 120) // the request the stream answers

	stream := func(t time.Duration, n int) time.Duration {
		for i := 0; i < n; i++ {
			c.ServerData(t, 1000)
			c.ClientAck(t+3*ms, 65535)
			t += 8 * ms
		}
		return t
	}

	// lossEvent models one segment lost before the capture point: three
	// in-flight segments arrive beyond the hole, the client repeats its
	// acknowledgement three times, and the server retransmits the missing
	// segment well outside the reordering window.
	lossEvent := func(t time.Duration) time.Duration {
		hole := c.sseq
		c.ServerSegmentAt(t, hole+1000, 1000)
		c.ClientAckAt(t+3*ms, hole)
		c.ServerSegmentAt(t+8*ms, hole+2000, 1000)
		c.ClientAckAt(t+11*ms, hole)
		c.ServerSegmentAt(t+16*ms, hole+3000, 1000)
		c.ClientAckAt(t+19*ms, hole)
		c.ServerSegmentAt(t+30*ms, hole, 1000) // fast retransmission
		c.ServerAdvance(4000)
		c.ClientAck(t+35*ms, 65535)
		return t + 45*ms
	}

	t := stream(40*ms, 30)
	t = lossEvent(t)
	t = stream(t, 20)
	t = lossEvent(t)
	t = stream(t, 8)
	c.FinClose(t, 5*ms)

	// Clean peers, so the rate on this path is measured against a population.
	for i := 0; i < 6; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.6.7.5:%d", 48000+i),
			Server:    fmt.Sprintf("10.6.8.%d:443", 10+i),
			ClientISN: uint32(320000 + i*1000),
			ServerISN: uint32(770000 + i*1000),
		})
		start := 60*ms + time.Duration(i)*120*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}

// buildR07Positive is the R07 fixture, and the negative case for R05 and R06
// at the same time: five pairs of segments delivered out of order with
// sub-millisecond gaps and IP IDs in original transmission order. One of the
// swaps arrives after a full run of duplicate ACKs — the exact shape a fast
// retransmission trigger looks for — and must still be reclassified as
// reordering, which is the suppression seam doing its work.
func buildR07Positive() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "10.8.8.5:53000", Server: "10.9.9.2:8080",
		ClientISN: 80000, ServerISN: 180000,
	})
	c.HandshakeWithOptions(0, 10*ms, 1460, true)
	c.ClientData(25*ms, 90)

	t := 40 * ms
	// swap emits two consecutive segments in reversed arrival order: the
	// later-sent segment first, the earlier-sent one 0.4ms behind it. The
	// earlier segment's IP ID is derived from its lower sequence number, so
	// it carries the evidence of original order a real NIC would.
	swap := func(withDupAcks bool) {
		first := c.sseq
		c.ServerSegmentAt(t, first+1000, 1000)
		if withDupAcks {
			c.ClientAckAt(t+100*time.Microsecond, first)
			c.ClientAckAt(t+200*time.Microsecond, first)
			c.ClientAckAt(t+300*time.Microsecond, first)
		}
		c.ServerSegmentAt(t+400*time.Microsecond, first, 1000)
		c.ServerAdvance(2000)
		c.ClientAck(t+3*ms, 65535)
		t += 10 * ms
	}
	plain := func(n int) {
		for i := 0; i < n; i++ {
			c.ServerData(t, 1000)
			c.ClientAck(t+3*ms, 65535)
			t += 10 * ms
		}
	}

	plain(5)
	swap(false)
	plain(4)
	swap(false)
	plain(4)
	swap(true) // reordering under a duplicate-ACK run: R07 must win
	plain(4)
	swap(false)
	plain(3)
	swap(false)
	plain(3)
	c.FinClose(t, 5*ms)

	// Clean peers for population.
	for i := 0; i < 4; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.8.9.5:%d", 49000+i),
			Server:    fmt.Sprintf("10.8.10.%d:443", 10+i),
			ClientISN: uint32(420000 + i*1000),
			ServerISN: uint32(870000 + i*1000),
		})
		start := 55*ms + time.Duration(i)*90*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}

// buildR07PositiveV6 is the same reordering pattern over IPv6, which has no
// IP ID field: the reclassification must fall back to timing alone and the
// finding must carry lowered confidence saying so.
func buildR07PositiveV6() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "[2001:db8:1::5]:53100", Server: "[2001:db8:2::2]:8443",
		ClientISN: 82000, ServerISN: 182000,
	})
	c.HandshakeWithOptions(0, 10*ms, 1440, true)
	c.ClientData(25*ms, 90)

	t := 40 * ms
	swap := func() {
		first := c.sseq
		c.ServerSegmentAt(t, first+1000, 1000)
		c.ServerSegmentAt(t+500*time.Microsecond, first, 1000)
		c.ServerAdvance(2000)
		c.ClientAck(t+3*ms, 65535)
		t += 10 * ms
	}
	plain := func(n int) {
		for i := 0; i < n; i++ {
			c.ServerData(t, 1000)
			c.ClientAck(t+3*ms, 65535)
			t += 10 * ms
		}
	}

	plain(6)
	swap()
	plain(5)
	swap()
	plain(4)
	swap()
	plain(3)
	c.FinClose(t, 5*ms)

	// Two clean IPv4 peers: a capture is rarely single-stack, and the
	// population accounting must not care which family a flow used.
	for i := 0; i < 2; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.8.11.5:%d", 50000+i),
			Server:    fmt.Sprintf("10.8.12.%d:443", 10+i),
			ClientISN: uint32(520000 + i*1000),
			ServerISN: uint32(970000 + i*1000),
		})
		start := 60*ms + time.Duration(i)*80*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}

// buildR08Positive is the R08 fixture: client-to-server retransmits at a high
// rate (22 timer-driven retransmissions), server-to-client at a low rate (2),
// on the same connection — asymmetric loss with both directions present, so
// the comparison this rule makes is the two directions of one flow, not a
// comparison against peers.
func buildR08Positive() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "10.11.11.5:54100", Server: "10.12.12.2:445",
		ClientISN: 90000, ServerISN: 190000,
	})
	c.HandshakeWithOptions(0, 10*ms, 1460, true)

	// rtoEvent emits one segment, waits past the RTO gap in silence on this
	// direction, then retransmits the same range — the shape R05's classifier
	// reads as a timeout, reused here purely for retransmission volume.
	rtoEventClient := func(t time.Duration) time.Duration {
		seq := c.cseq
		c.ClientSegmentAt(t, seq, 200)
		c.ClientAdvance(200)
		c.ClientSegmentAt(t+250*ms, seq, 200)
		c.ServerAck(t+255*ms, 64000)
		return t + 270*ms
	}
	rtoEventServer := func(t time.Duration) time.Duration {
		seq := c.sseq
		c.ServerSegmentAt(t, seq, 200)
		c.ServerAdvance(200)
		c.ServerSegmentAt(t+250*ms, seq, 200)
		c.ClientAck(t+255*ms, 64000)
		return t + 270*ms
	}

	t := 30 * ms
	// Twenty clean segments each direction, establishing a data population
	// before either side shows loss.
	for i := 0; i < 20; i++ {
		c.ClientData(t, 200)
		c.ServerAck(t+5*ms, 64000)
		t += 15 * ms
	}
	for i := 0; i < 20; i++ {
		c.ServerData(t, 200)
		c.ClientAck(t+5*ms, 64000)
		t += 15 * ms
	}

	// Client-to-server: 22 timer-driven retransmissions — comfortably over
	// R08's 20-retransmission minimum, and at a rate (roughly a third of
	// forward segments) that towers over the reverse direction's.
	for i := 0; i < 22; i++ {
		t = rtoEventClient(t)
	}

	// Server-to-client: two retransmissions against a much larger clean
	// population, so the reverse rate is low but not exactly zero — the
	// general ratio comparison, not the "reverse direction perfectly clean"
	// special case.
	for i := 0; i < 140; i++ {
		c.ServerData(t, 200)
		c.ClientAck(t+3*ms, 64000)
		t += 8 * ms
	}
	t = rtoEventServer(t)
	for i := 0; i < 20; i++ {
		c.ServerData(t, 200)
		c.ClientAck(t+3*ms, 64000)
		t += 8 * ms
	}
	t = rtoEventServer(t)

	c.FinClose(t+20*ms, 5*ms)

	// Clean peers, for population context alongside the other loss fixtures.
	for i := 0; i < 4; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.11.13.5:%d", 51000+i),
			Server:    fmt.Sprintf("10.11.14.%d:443", 10+i),
			ClientISN: uint32(620000 + i*1000),
			ServerISN: uint32(970000 + i*1000),
		})
		start := 40*ms + time.Duration(i)*160*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}

// buildR08OneWay models a flow captured in one direction only — the common
// consequence of a one-way SPAN or mirror port. No handshake, and no client
// packet of any kind: the reverse direction has zero packets, not merely zero
// retransmissions, so R08 cannot make the comparison this rule depends on and
// must say so rather than silently finding nothing.
func buildR08OneWay() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "10.13.13.5:55200", Server: "10.14.14.2:1521",
		ClientISN: 100000, ServerISN: 200000,
	})

	t := 20 * ms
	for i := 0; i < 15; i++ {
		c.ServerData(t, 300)
		t += 12 * ms
	}
	// Three timer-shaped retransmissions on the only direction this capture
	// point could see.
	for i := 0; i < 3; i++ {
		seq := c.sseq
		c.ServerSegmentAt(t, seq, 300)
		c.ServerAdvance(300)
		c.ServerSegmentAt(t+260*ms, seq, 300)
		t += 280 * ms
	}

	// A couple of ordinary bidirectional peers, so the capture is not
	// entirely one-way and the note reads as describing one flow, not the
	// whole file.
	for i := 0; i < 3; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.13.15.5:%d", 52000+i),
			Server:    fmt.Sprintf("10.13.16.%d:443", 10+i),
			ClientISN: uint32(720000 + i*1000),
			ServerISN: uint32(270000 + i*1000),
		})
		start := 30*ms + time.Duration(i)*140*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}
