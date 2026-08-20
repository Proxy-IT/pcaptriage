package synth

import (
	"fmt"
	"time"
)

const (
	ms = time.Millisecond
	s  = time.Second
)

// Fixture is a named synthetic capture.
type Fixture struct {
	// Name is the base filename, without extension.
	Name string
	// Purpose says what the fixture is for, in one line.
	Purpose string
	// Build renders the frames.
	Build func() *Builder
	// FormatsDiffer marks a fixture whose pcap and pcapng renderings are not
	// expected to analyse identically, because it exercises something only one
	// format can carry — capture-host drop counters, which classic pcap has no
	// field for. The equivalence test skips these rather than being weakened
	// for every other fixture.
	FormatsDiffer bool
}

// Fixtures is every fixture in the suite. Each rule has a positive fixture
// that must trigger it and a negative fixture that must not, drawn from the
// false-positive traps listed under the rule in RULES.md.
func Fixtures() []Fixture {
	return []Fixture{
		{
			Name:    "r01-zero-window-stall",
			Purpose: "R01 positive: a receiver stalls a sender for 4.2s across two episodes, against twelve clean peer hosts.",
			Build:   buildR01Positive,
		},
		{
			Name:    "r01-brief-zero-windows",
			Purpose: "R01 negative: brief zero windows below the cumulative floor, plus a midstream flow whose first observed window is zero.",
			Build:   buildR01Negative,
		},
		{
			Name:    "r04-server-response-outlier",
			Purpose: "R04 positive: one server at 1.8s p95 against twelve peers under 40ms.",
			Build:   buildR04Positive,
		},
		{
			Name:    "r04-midstream",
			Purpose: "R04 inferred: the same slow server measured only by flows that were already open, so RTT comes from the minimum observed ACK round trip and the finding degrades.",
			Build:   buildR04Midstream,
		},
		{
			Name:    "r04-server-push",
			Purpose: "R04 negative: server-sent events and a protocol banner, neither of which is a slow response.",
			Build:   buildR04Negative,
		},
		{
			Name:    "mixed-findings",
			Purpose: "Determinism and ranking: five findings across both rules, several hosts, and a proximity bonus.",
			Build:   buildMixed,
		},
		{
			Name:    "clean-capture",
			Purpose: "Clean-capture state: ordinary handshakes, transfers and closes, uniform response times, nothing for any rule to report.",
			Build:   buildClean,
		},
		{
			Name:          "r15-kernel-drops",
			Purpose:       "R15 positive: pcapng whose interface statistics report the capture host dropping 2% of the traffic it saw.",
			Build:         buildKernelDrops,
			FormatsDiffer: true,
		},
		{
			Name:          "r15-no-kernel-drops",
			Purpose:       "R15 negative: pcapng whose interface statistics report zero drops, so loss found here is loss on the wire.",
			Build:         buildNoKernelDrops,
			FormatsDiffer: true,
		},
		{
			Name:    "r05-rto-burst",
			Purpose: "R05 positive: three timeout retransmissions across two episodes costing 4.5s, with exponential backoff, against eight clean peers.",
			Build:   buildR05Positive,
		},
		{
			Name:    "r06-fast-retransmit",
			Purpose: "R06 positive: two loss events recovered by fast retransmit after duplicate ACKs, at a rate that renders informational.",
			Build:   buildR06Positive,
		},
		{
			Name:    "r07-reordering",
			Purpose: "R07 positive and R05/R06 negative: five reordered segment pairs with sane IP IDs, one under a duplicate-ACK run, producing no loss findings.",
			Build:   buildR07Positive,
		},
		{
			Name:    "r07-reordering-v6",
			Purpose: "R07 degraded path: the same reordering over IPv6, where no IP ID exists and the reclassification is timing-only and inferred.",
			Build:   buildR07PositiveV6,
		},
		{
			Name:    "r08-asymmetric-loss",
			Purpose: "R08 positive: 22 timer-driven retransmissions client-to-server against 2 server-to-client on the same connection, well over the 5x ratio and 20-count minimums.",
			Build:   buildR08Positive,
		},
		{
			Name:    "r08-one-way",
			Purpose: "R08 unavailable: a flow captured in one direction only, with retransmissions on the visible side, so the directional comparison cannot be made.",
			Build:   buildR08OneWay,
		},
		{
			Name:    "r02-syn-unanswered",
			Purpose: "R02 positive: five SYN attempts over 15s with standard backoff and no reply, against a host answering normally on another port.",
			Build:   buildR02Positive,
		},
		{
			Name:    "r02-syn-answered",
			Purpose: "R02 negative: ordinary handshakes, including one retried SYN that is eventually answered, so no attempt went unanswered.",
			Build:   buildR02Negative,
		},
		{
			Name:    "r02-capture-truncated",
			Purpose: "R02 suppression: an unanswered SYN inside the capture-end window, where silence was never observed — only the capture stopping.",
			Build:   buildR02Truncated,
		},
		{
			Name:    "r03-syn-rejected",
			Purpose: "R03 positive: nine attempts from three clients refused on one port, while the same host answers normally on another.",
			Build:   buildR03Positive,
		},
		{
			Name:    "r03-syn-accepted",
			Purpose: "R03 negative: handshakes that complete normally, including one connection closed by reset after its transfer — a close, not a refusal.",
			Build:   buildR03Negative,
		},
		{
			Name:    "r03-forged-reset",
			Purpose: "R03 false-positive trap: refusals whose TTL disagrees with the same host's ordinary traffic by ten hops, hinting a middlebox answered on its behalf.",
			Build:   buildR03ForgedReset,
		},
		{
			Name:    "r09-reset-mid-transfer",
			Purpose: "R09 positive: eight transfers cut off by reset while data was still moving, against twelve from the same host that closed normally.",
			Build:   buildR09Positive,
		},
		{
			Name:    "r09-clean-close",
			Purpose: "R09 negative: the same transfers closed properly with FIN, plus one reset ten seconds after the last data — an idle close, not an interrupted transfer.",
			Build:   buildR09Negative,
		},
		{
			Name:    "r09-uniform-reset",
			Purpose: "R09 false-positive trap: a host that ends every connection with a reset and never a FIN — a habit to report as context, not fourteen separate faults.",
			Build:   buildR09Uniform,
		},
		{
			Name:    "r14-connection-churn",
			Purpose: "R14 positive: sixty connections to one server:port in seven seconds, each living about 70ms, alongside one long-lived connection that is being reused properly.",
			Build:   buildR14Positive,
		},
		{
			Name:    "r14-connection-reuse",
			Purpose: "R14 negative: eight connections each held open across ten exchanges — well under the connection minimum and far over the lifetime threshold.",
			Build:   buildR14Negative,
		},
		{
			Name:    "r14-midstream",
			Purpose: "R14 degradation: fifty-five connections to one endpoint already open when the capture began, so lifetime cannot be measured and the check reports unavailable.",
			Build:   buildR14Midstream,
		},
	}
}

// buildClean is a capture with nothing wrong with it.
//
// Six servers, full handshakes, six clean request/response exchanges each,
// orderly teardowns, and response times close enough together that no server
// stands out from the others. Every flow is COMPLETE, none is one-way, and no
// receiver ever closes its window.
//
// It exists to drive the screen a real healthy capture lands on, which is the
// one screen where the tool is most likely to be believed about something it
// never checked. Getting the fixture genuinely quiet matters: a fixture that
// produced one incidental finding would test the findings list instead.
func buildClean() *Builder {
	b := New()

	// Enough servers that R04 has a peer group, and response times spread
	// narrowly enough that none of them is an outlier against the others.
	deltas := evenDeltas(6, 20*ms, 2*ms)
	for i := 0; i < 6; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.20:%d", 51000+i),
			Server:    fmt.Sprintf("10.5.5.%d:443", 10+i),
			ClientISN: uint32(300000 + i*1000),
			ServerISN: uint32(800000 + i*1000),
		})
		start := 20*ms + time.Duration(i)*35*ms
		c.Handshake(start, 10*ms)
		end := exchanges(c, start+30*ms, deltas, 10*ms, 45*ms)
		c.FinClose(end, 5*ms)
	}

	return b
}

// dropsTraffic is the ordinary conversation both drop fixtures carry.
//
// It is deliberately unremarkable: these fixtures are about what the file says
// happened to the capture, not about what the rules find inside it, and a
// finding here would only be noise in the assertion.
func dropsTraffic() *Builder {
	b := New()
	for i := 0; i < 4; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 45000+i),
			Server:    fmt.Sprintf("10.2.2.%d:443", 10+i),
			ClientISN: uint32(20000 + i*1000),
			ServerISN: uint32(70000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*40*ms
		c.Handshake(start, 10*ms)
		end := exchanges(c, start+30*ms, evenDeltas(6, 20*ms, 2*ms), 10*ms, 40*ms)
		c.FinClose(end, 5*ms)
	}
	return b
}

// buildKernelDrops is the positive case: the capture host says it threw away
// part of what it saw, so loss found in this file cannot be assumed to be loss
// on the wire.
//
// Two packets in ninety-eight is about 2%: an order of magnitude above the
// threshold, so the fixture is not testing rounding, but still the sort of
// figure a real overloaded capture produces rather than an absurd one.
func buildKernelDrops() *Builder {
	return dropsTraffic().WithInterfaceStats(InterfaceStats{
		Received: 98,
		Dropped:  2,
	})
}

// buildNoKernelDrops is the negative case: the same traffic, with the capture
// host reporting that it dropped nothing. The distinction from a file that
// simply cannot say is the whole point of the rule.
func buildNoKernelDrops() *Builder {
	return dropsTraffic().WithInterfaceStats(InterfaceStats{
		Received: 98,
		Dropped:  0,
	})
}

// exchanges emits a run of clean request/response exchanges and returns the
// time just after the last one.
//
// Each exchange is client data, then server data delta+rtt later, then the
// client's acknowledgement. Subtracting the network round trip from that gap
// is what leaves the server's own time.
func exchanges(c *Conn, start time.Duration, deltas []time.Duration, rtt, gap time.Duration) time.Duration {
	t := start
	for _, d := range deltas {
		c.ClientData(t, 200)
		resp := t + d + rtt
		c.ServerData(resp, 800)
		c.ClientAck(resp+5*ms, 65535)
		t = resp + gap
	}
	return t
}

// evenDeltas returns n deltas from lo, stepping by step.
func evenDeltas(n int, lo, step time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = lo + time.Duration(i)*step
	}
	return out
}

// buildR01Positive is the R01 fixture from RULES.md's example wording: six
// zero-window advertisements across two stalls totalling 4.2s, the longest
// 2.9s, with twelve other hosts in the capture showing nothing.
func buildR01Positive() *Builder {
	b := New()

	c := b.NewConn(ConnOpts{
		Client: "10.1.1.5:44210", Server: "10.2.2.7:5432",
		ClientISN: 1000, ServerISN: 5000,
	})
	c.Handshake(0, 10*ms)
	c.ClientData(20*ms, 1000)
	c.ServerAck(100*ms, 8192) // still accepting

	// First stall: 150ms to 1450ms is 1.3s.
	c.ClientData(120*ms, 1000)
	c.ServerAck(150*ms, 0)
	c.ClientWindowProbe(400 * ms)
	c.ServerAck(410*ms, 0)
	c.ClientWindowProbe(900 * ms)
	c.ServerAck(910*ms, 0)
	c.ServerAck(1450*ms, 4096) // window update

	// Second stall: 1500ms to 4400ms is 2.9s.
	c.ClientData(1460*ms, 1000)
	c.ServerAck(1500*ms, 0)
	c.ClientWindowProbe(2000 * ms)
	c.ServerAck(2010*ms, 0)
	c.ClientWindowProbe(3000 * ms)
	c.ServerAck(3010*ms, 0)
	c.ServerAck(4400*ms, 16384) // window update

	c.ClientData(4500*ms, 500)
	c.ServerAck(4510*ms, 16384)
	c.FinClose(4600*ms, 10*ms)

	// Eleven clean peer servers. With the client and the stalling server that
	// is thirteen hosts, so the finding can say the other twelve show nothing.
	for i := 0; i < 11; i++ {
		addPeerFlow(b, i, 100*ms+time.Duration(i)*50*ms, 1)
	}

	return b
}

// addPeerFlow adds one short, clean conversation to a fixture as peer traffic.
func addPeerFlow(b *Builder, i int, start time.Duration, exchangeCount int) {
	c := b.NewConn(ConnOpts{
		Client:    fmt.Sprintf("10.1.1.5:%d", 45000+i),
		Server:    fmt.Sprintf("10.2.2.%d:443", 10+i),
		ClientISN: uint32(20000 + i*1000),
		ServerISN: uint32(70000 + i*1000),
	})
	c.Handshake(start, 10*ms)
	end := exchanges(c, start+30*ms, evenDeltas(exchangeCount, 20*ms, 2*ms), 10*ms, 20*ms)
	c.FinClose(end, 5*ms)
}

// buildR01Negative covers both false-positive traps under R01.
//
// The first flow advertises a zero window six times, but each stall is brief:
// duration is the signal, not occurrence, and sixty milliseconds in total is
// below the floor.
//
// The second flow is midstream and its first observed window is zero. It stays
// that way for five seconds before a non-zero window appears. That is not a
// receiver that stopped accepting data — the rule requires a non-zero window
// to have been advertised first — and counting it would report a five-second
// stall that never happened.
func buildR01Negative() *Builder {
	b := New()

	brief := b.NewConn(ConnOpts{
		Client: "10.1.1.5:44300", Server: "10.3.3.3:5432",
		ClientISN: 3000, ServerISN: 9000,
	})
	brief.Handshake(0, 10*ms)
	for i := 0; i < 6; i++ {
		base := 200*ms + time.Duration(i)*100*ms
		brief.ClientData(base, 500)
		brief.ServerAck(base+10*ms, 0)
		brief.ServerAck(base+20*ms, 8192)
	}
	brief.FinClose(900*ms, 10*ms)

	// No handshake: this flow was already established when the capture began.
	mid := b.NewConn(ConnOpts{
		Client: "10.1.1.6:44400", Server: "10.3.3.4:5432",
		ClientISN: 500000, ServerISN: 900000,
	})
	mid.ServerAck(1000*ms, 0) // first window seen from this side is zero
	mid.ClientData(1010*ms, 200)
	mid.ServerAck(3000*ms, 0)
	mid.ServerAck(6000*ms, 8192) // five seconds later, and not a stall
	mid.ClientData(6050*ms, 200)
	mid.ServerAck(6100*ms, 0) // this one does qualify, and lasts 20ms
	mid.ServerAck(6120*ms, 8192)
	mid.ClientData(6200*ms, 200)
	mid.ServerAck(6210*ms, 8192)

	for i := 0; i < 3; i++ {
		addPeerFlow(b, i, 100*ms+time.Duration(i)*50*ms, 1)
	}

	return b
}

// buildR04Positive is the R04 fixture from RULES.md's example wording: one
// server at 1.8s p95 with a 4.1s maximum, against twelve peers under 40ms.
func buildR04Positive() *Builder {
	b := New()

	// Eighteen responses from 1.00s to 1.68s, then 1.80s and 4.10s. Over
	// twenty samples the 95th percentile by nearest rank is the second
	// largest, so p95 is 1.8s and the maximum is 4.1s.
	slowDeltas := append(evenDeltas(18, 1000*ms, 40*ms), 1800*ms, 4100*ms)

	slow := b.NewConn(ConnOpts{
		Client: "10.1.1.5:44210", Server: "10.2.2.7:443",
		ClientISN: 1000, ServerISN: 5000,
	})
	slow.Handshake(0, 10*ms)
	end := exchanges(slow, 30*ms, slowDeltas, 10*ms, 100*ms)
	slow.FinClose(end, 5*ms)

	// Twelve peers, each with five exchanges from 20ms to 28ms plus one at
	// 30ms, so every peer's p95 is 30ms and the wording can say the others are
	// under 40ms.
	peerDeltas := []time.Duration{20 * ms, 22 * ms, 24 * ms, 26 * ms, 30 * ms}
	for i := 0; i < 12; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 45000+i),
			Server:    fmt.Sprintf("10.2.2.%d:443", 10+i),
			ClientISN: uint32(20000 + i*1000),
			ServerISN: uint32(70000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*40*ms
		c.Handshake(start, 10*ms)
		e := exchanges(c, start+30*ms, peerDeltas, 10*ms, 40*ms)
		c.FinClose(e, 5*ms)
	}

	return b
}

// buildR04Midstream is R04's inferred path: the same slow server, but every
// flow that measures it was already open when the capture began.
//
// This is the real-world condition, not a contrivance — a capture started on a
// running system to investigate a complaint catches its connections
// mid-conversation. Without a handshake there is no observed round trip to
// subtract, so flow.NetworkRTT falls back to the minimum observed ACK round
// trip and reports BasisInferred, and R04 degrades the finding and states what
// it substituted.
//
// The slow server's flows carry no handshake; the peer group's do. Quality is
// decided per server aggregate, so the peers stay confirmed and only the
// server under test degrades — which is also what makes the fixture prove the
// degradation is attributable rather than capture-wide.
//
// Every contributing flow must produce an ACK round-trip sample, or R04 takes
// its rttMissing branch instead and states a different basis. The exchange
// pattern below ends each response with a client ACK for exactly that reason.
func buildR04Midstream() *Builder {
	b := New()

	// The same twenty response times as the R04 positive, split across four
	// flows to one server: p95 by nearest rank is the second largest, so 1.8s
	// with a 4.1s maximum, and the basis sentence can say "4 of 4".
	slowDeltas := append(evenDeltas(18, 1000*ms, 40*ms), 1800*ms, 4100*ms)

	for i := 0; i < 4; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 44210+i),
			Server:    "10.2.2.7:443",
			ClientISN: uint32(1000 + i*1000),
			ServerISN: uint32(5000 + i*1000),
		})
		// No Handshake: the flow is already established. The first packet is
		// a client request, which is what tells the engine which side is
		// serving.
		start := 30*ms + time.Duration(i)*12*s
		end := exchanges(c, start, slowDeltas[i*5:(i+1)*5], 10*ms, 100*ms)
		c.FinClose(end, 5*ms)
	}

	// Twelve peers whose openings were captured, so the comparison group is
	// measured on observed round trips and stays confirmed.
	peerDeltas := []time.Duration{20 * ms, 22 * ms, 24 * ms, 26 * ms, 30 * ms}
	for i := 0; i < 12; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 45000+i),
			Server:    fmt.Sprintf("10.2.2.%d:443", 10+i),
			ClientISN: uint32(20000 + i*1000),
			ServerISN: uint32(70000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*40*ms
		c.Handshake(start, 10*ms)
		e := exchanges(c, start+30*ms, peerDeltas, 10*ms, 40*ms)
		c.FinClose(e, 5*ms)
	}

	return b
}

// buildR04Negative covers both false-positive traps under R04.
//
// The first flow is server-sent events: a fast request/response, then the
// server pushes on its own with multi-second gaps. Those pushes continue a
// response that has already been measured, so they must not read as a series
// of two-second responses.
//
// The second flow opens with a protocol banner — the server sends data with no
// preceding client request. Request and response do not alternate cleanly, so
// the flow cannot be paired and must be reported as unavailable rather than
// measured as slow.
func buildR04Negative() *Builder {
	b := New()

	sse := b.NewConn(ConnOpts{
		Client: "10.1.1.5:46000", Server: "10.5.5.5:8080",
		ClientISN: 1000, ServerISN: 5000,
	})
	sse.Handshake(0, 10*ms)
	for i := 0; i < 6; i++ {
		base := 100*ms + time.Duration(i)*8*s
		sse.ClientData(base, 150)
		sse.ServerData(base+30*ms, 400) // the response: 30ms raw, 20ms of server time
		sse.ClientAck(base+35*ms, 65535)
		sse.ServerData(base+2*s, 100) // pushed event, not a new response
		sse.ClientAck(base+2*s+5*ms, 65535)
		sse.ServerData(base+4*s, 100) // pushed event
		sse.ClientAck(base+4*s+5*ms, 65535)
	}
	sse.FinClose(50*s, 5*ms)

	banner := b.NewConn(ConnOpts{
		Client: "10.1.1.5:46100", Server: "10.6.6.6:21",
		ClientISN: 2000, ServerISN: 6000,
	})
	banner.Handshake(0, 10*ms)
	banner.ServerData(200*ms, 60) // banner, with nothing asked for
	banner.ClientAck(205*ms, 65535)
	for i := 0; i < 6; i++ {
		base := 400*ms + time.Duration(i)*4*s
		banner.ClientData(base, 20)
		banner.ServerData(base+2*s, 50) // two seconds, but unpairable
		banner.ClientAck(base+2*s+5*ms, 65535)
	}
	banner.FinClose(30*s, 5*ms)

	peerDeltas := evenDeltas(6, 20*ms, 2*ms)
	for i := 0; i < 5; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 45000+i),
			Server:    fmt.Sprintf("10.2.2.%d:443", 10+i),
			ClientISN: uint32(20000 + i*1000),
			ServerISN: uint32(70000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*40*ms
		c.Handshake(start, 10*ms)
		e := exchanges(c, start+30*ms, peerDeltas, 10*ms, 40*ms)
		c.FinClose(e, 5*ms)
	}

	return b
}

// buildMixed produces several findings from both rules across several hosts.
//
// This is the golden-file and determinism fixture. It exists to have enough
// map-derived collections in play — findings, flows, per-host aggregates,
// per-server aggregates — that an unsorted emit anywhere would show up as a
// changing document between runs.
func buildMixed() *Builder {
	b := New()

	// Three zero-window stalls of different severity, on three servers.
	stalls := []struct {
		server   string
		port     int
		episodes []struct{ open, close time.Duration }
		reset    bool
	}{
		{
			server: "10.2.2.7", port: 5432,
			episodes: []struct{ open, close time.Duration }{
				{150 * ms, 1450 * ms},  // 1.3s
				{1500 * ms, 4400 * ms}, // 2.9s
			},
		},
		{
			server: "10.2.2.8", port: 5432,
			episodes: []struct{ open, close time.Duration }{
				{200 * ms, 900 * ms},   // 0.7s
				{1000 * ms, 1800 * ms}, // 0.8s
			},
		},
		{
			server: "10.2.2.9", port: 5432,
			episodes: []struct{ open, close time.Duration }{
				{300 * ms, 900 * ms}, // 0.6s, then reset shortly after
			},
			reset: true,
		},
	}

	for i, st := range stalls {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 44210+i),
			Server:    fmt.Sprintf("%s:%d", st.server, st.port),
			ClientISN: uint32(1000 + i*100),
			ServerISN: uint32(5000 + i*100),
		})
		c.Handshake(0, 10*ms)
		c.ClientData(20*ms, 1000)
		c.ServerAck(100*ms, 8192)

		var last time.Duration
		for _, ep := range st.episodes {
			c.ClientData(ep.open-20*ms, 1000)
			c.ServerAck(ep.open, 0)
			c.ClientWindowProbe(ep.open + (ep.close-ep.open)/2)
			c.ServerAck(ep.open+(ep.close-ep.open)/2+10*ms, 0)
			c.ServerAck(ep.close, 8192)
			last = ep.close
		}
		if st.reset {
			// Within the proximity window, so this finding carries the bonus.
			c.ServerReset(last + 500*ms)
		} else {
			c.FinClose(last+100*ms, 10*ms)
		}
	}

	// Two slow servers and eight fast ones.
	slow := []struct {
		addr   string
		deltas []time.Duration
	}{
		{"10.4.4.1", append(evenDeltas(9, 1800*ms, 20*ms), 2600*ms)},
		{"10.4.4.2", append(evenDeltas(9, 1100*ms, 10*ms), 1500*ms)},
	}
	for i, sv := range slow {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 47000+i),
			Server:    sv.addr + ":443",
			ClientISN: uint32(30000 + i*1000),
			ServerISN: uint32(80000 + i*1000),
		})
		c.Handshake(0, 10*ms)
		e := exchanges(c, 30*ms, sv.deltas, 10*ms, 100*ms)
		c.FinClose(e, 5*ms)
	}

	fastDeltas := evenDeltas(6, 20*ms, 2*ms)
	for i := 0; i < 8; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 48000+i),
			Server:    fmt.Sprintf("10.4.4.%d:443", 10+i),
			ClientISN: uint32(40000 + i*1000),
			ServerISN: uint32(90000 + i*1000),
		})
		start := 50*ms + time.Duration(i)*40*ms
		c.Handshake(start, 10*ms)
		e := exchanges(c, start+30*ms, fastDeltas, 10*ms, 40*ms)
		c.FinClose(e, 5*ms)
	}

	return b
}
