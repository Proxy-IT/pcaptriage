package synth

import (
	"fmt"
	"time"
)

// The Batch 2 connection-lifecycle fixtures for R02 and R03: attempts that
// were never answered, and attempts that were refused.

// buildR02Positive is the R02 fixture from RULES.md's example wording: four
// SYN attempts over 15s with standard backoff, nothing returned, against a
// host whose other services answer normally.
func buildR02Positive() *Builder {
	b := New()

	// The unanswered attempt. Four SYNs at 1s, 2s, 4s and 8s intervals — the
	// backoff pattern the wording reports — spanning 15s in total.
	dead := b.NewConn(ConnOpts{
		Client: "10.1.1.5:51000", Server: "10.4.4.9:8443",
		ClientISN: 700000,
	})
	for _, at := range []time.Duration{100 * ms, 1100 * ms, 3100 * ms, 7100 * ms, 15100 * ms} {
		dead.ClientSYN(at)
	}

	// The same host answering on another port, which is what licenses the
	// "other services responded normally" sentence. Without this the fixture
	// would silently exercise a different branch of the wording.
	ok := b.NewConn(ConnOpts{
		Client: "10.1.1.5:51001", Server: "10.4.4.9:443",
		ClientISN: 710000, ServerISN: 810000,
	})
	ok.Handshake(200*ms, 10*ms)
	end := exchanges(ok, 240*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
	ok.FinClose(end, 5*ms)

	// Unrelated peers, so the capture has a population and the finding is not
	// the only thing in it.
	for i := 0; i < 4; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.6:%d", 52000+i),
			Server:    fmt.Sprintf("10.5.5.%d:443", 10+i),
			ClientISN: uint32(720000 + i*1000),
			ServerISN: uint32(820000 + i*1000),
		})
		start := 300*ms + time.Duration(i)*120*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		p.FinClose(e, 5*ms)
	}

	// A quiet tail so the last SYN is well clear of the capture end and the
	// suppression window is not what this fixture is testing.
	tail := b.NewConn(ConnOpts{
		Client: "10.1.1.6:52900", Server: "10.5.5.20:443",
		ClientISN: 730000, ServerISN: 830000,
	})
	tail.Handshake(20000*ms, 10*ms)
	tailEnd := exchanges(tail, 20040*ms, evenDeltas(2, 20*ms, 2*ms), 10*ms, 25*ms)
	tail.FinClose(tailEnd, 5*ms)

	return b
}

// buildR02Negative is the answered case: the same shape of opening attempt,
// but a SYN/ACK arrives and the connection proceeds normally. Nothing here
// may produce an R02 finding.
func buildR02Negative() *Builder {
	b := New()

	for i := 0; i < 6; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.2.2.5:%d", 53000+i),
			Server:    fmt.Sprintf("10.6.6.%d:443", 10+i),
			ClientISN: uint32(740000 + i*1000),
			ServerISN: uint32(840000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*150*ms
		// A retransmitted SYN that IS eventually answered: the client tried
		// twice before the handshake completed, which is not R02's condition.
		if i == 0 {
			c.ClientSYN(start)
			start += 1000 * ms
		}
		c.Handshake(start, 10*ms)
		e := exchanges(c, start+40*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
		c.FinClose(e, 5*ms)
	}

	return b
}

// buildR02Truncated is RULES.md's suppression case: an unanswered SYN whose
// last attempt lands inside the capture-end window. The capture stopped while
// the handshake was still in flight, so silence was never observed — only the
// capture ending. This must produce no finding.
func buildR02Truncated() *Builder {
	b := New()

	// Ordinary traffic establishing the capture's timeline.
	for i := 0; i < 4; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.3.3.5:%d", 54000+i),
			Server:    fmt.Sprintf("10.7.7.%d:443", 10+i),
			ClientISN: uint32(750000 + i*1000),
			ServerISN: uint32(850000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*200*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		p.FinClose(e, 5*ms)
	}

	// Two attempts, the last one 500ms before the final frame — well inside
	// the 2s suppression window.
	late := b.NewConn(ConnOpts{
		Client: "10.3.3.5:54900", Server: "10.7.7.99:9000",
		ClientISN: 760000,
	})
	late.ClientSYN(900 * ms)
	late.ClientSYN(1400 * ms)

	return b
}

// buildR03Positive is the R03 fixture from RULES.md's example wording:
// connection attempts from several clients answered with RST on one port,
// while the same host answers normally on another.
func buildR03Positive() *Builder {
	b := New()

	// Three clients, refused on the same port. The wording counts both the
	// attempts and the distinct clients, so both have to vary.
	attempts := []struct {
		client   string
		isn      uint32
		attempts int
	}{
		{"10.1.1.5", 900000, 4},
		{"10.1.1.6", 910000, 3},
		{"10.1.1.7", 920000, 2},
	}
	var t time.Duration = 100 * ms
	for i, a := range attempts {
		for n := 0; n < a.attempts; n++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("%s:%d", a.client, 55000+i*100+n),
				Server:    "10.4.4.9:8443",
				ClientISN: a.isn + uint32(n*10),
			})
			c.ClientSYN(t)
			c.ServerRefuse(t + 5*ms)
			t += 120 * ms
		}
	}

	// The same host, answering normally elsewhere: the refusal is about one
	// port, not the host being down.
	ok := b.NewConn(ConnOpts{
		Client: "10.1.1.5:56000", Server: "10.4.4.9:443",
		ClientISN: 930000, ServerISN: 830000,
	})
	ok.Handshake(200*ms, 10*ms)
	end := exchanges(ok, 240*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
	ok.FinClose(end, 5*ms)

	return b
}

// buildR03Negative is the accepted case: the same clients and host, with the
// handshake completing normally. Nothing here may produce an R03 finding.
func buildR03Negative() *Builder {
	b := New()

	for i := 0; i < 6; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.2.2.5:%d", 57000+i),
			Server:    "10.8.8.9:8443",
			ClientISN: uint32(940000 + i*1000),
			ServerISN: uint32(860000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*150*ms
		c.Handshake(start, 10*ms)
		e := exchanges(c, start+40*ms, evenDeltas(4, 20*ms, 2*ms), 10*ms, 30*ms)
		// A reset at the very end of a completed conversation is a normal way
		// to close, not a refusal — and must not be read as one.
		if i == 5 {
			c.ServerReset(e + 10*ms)
			continue
		}
		c.FinClose(e, 5*ms)
	}

	return b
}

// buildR03ForgedReset is RULES.md's false-positive trap: the refusal's TTL
// disagrees with the same host's ordinary traffic by far more than the
// tolerance, which is the signature of a device on the path answering on the
// host's behalf.
//
// The real host is twelve hops away, so its traffic arrives with TTL 52. The
// resets arrive with TTL 62 — two hops — because whatever sent them is much
// closer to the capture point than the host it claims to speak for.
func buildR03ForgedReset() *Builder {
	b := New()

	// The host's ordinary traffic, establishing what its TTL looks like from
	// here. This is the baseline the resets are judged against, and it has to
	// exist on a different connection: a refused attempt carries nothing else
	// from that host by definition.
	real := b.NewConn(ConnOpts{
		Client: "10.9.9.5:58000", Server: "10.10.10.9:443",
		ClientISN: 950000, ServerISN: 870000,
	})
	real.HandshakeWithTTL(100*ms, 10*ms, 52)
	real.ClientData(150*ms, 200)
	real.ServerDataWithTTL(180*ms, 800, 52)
	real.ClientAck(190*ms, 65535)
	real.FinClose(220*ms, 5*ms)

	// The refused port, answered by something two hops away.
	var t time.Duration = 300 * ms
	for n := 0; n < 5; n++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.9.9.5:%d", 58100+n),
			Server:    "10.10.10.9:8443",
			ClientISN: uint32(960000 + n*10),
		})
		c.ClientSYN(t)
		c.ServerRefuseWithTTL(t+5*ms, 62)
		t += 150 * ms
	}

	return b
}
