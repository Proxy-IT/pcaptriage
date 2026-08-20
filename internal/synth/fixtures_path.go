package synth

import (
	"fmt"
	"time"
)

// buildR10Positive is R10's positive: one host reached over a long path,
// against a population of nearby ones.
//
// Twelve hosts answer in 8ms; one answers in 180ms, which is 22 times the
// median and well past the 4x threshold. The distant host's latency barely
// moves across its connections — the steady signature the finding reports as
// path length rather than congestion.
func buildR10Positive() *Builder {
	b := New()

	// The distant host, with the twenty-two connections RULES.md's own example
	// describes, so the figures the spec quotes are the figures this fixture
	// produces. Round trips sit between 178ms and 182ms: the spread stays far
	// inside half the median and reads as steady.
	//
	// The count is not incidental. Impact is the excess latency accumulated
	// across the connections that paid it, so twenty-two of them is what
	// carries this finding to significant — the same shape at six connections
	// is worth noting, which is the behaviour the denominator exists to give.
	var distantRTTs []time.Duration
	for i := 0; i < 22; i++ {
		distantRTTs = append(distantRTTs, 178*ms+time.Duration(i%5)*ms)
	}
	for i, rtt := range distantRTTs {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 47000+i),
			Server:    "10.7.7.3:443",
			ClientISN: uint32(10000 + i*1000),
			ServerISN: uint32(60000 + i*1000),
		})
		start := time.Duration(i) * 400 * ms
		c.Handshake(start, rtt)
		c.ClientData(start+rtt*2, 200)
		c.ServerData(start+rtt*2+rtt, 800)
		c.ClientAck(start+rtt*3+5*ms, 65535)
		c.FinClose(start+rtt*3+40*ms, 5*ms)
	}

	// Twelve nearby hosts at 8ms, three connections each — enough for every
	// one of them to be assessed, so the median is drawn from a real
	// population rather than from two hosts.
	for h := 0; h < 12; h++ {
		for i := 0; i < 3; i++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("10.1.1.5:%d", 48000+h*10+i),
				Server:    fmt.Sprintf("10.2.2.%d:443", 10+h),
				ClientISN: uint32(200000 + h*5000 + i*100),
				ServerISN: uint32(700000 + h*5000 + i*100),
			})
			start := 3*s + time.Duration(h*3+i)*120*ms
			c.Handshake(start, 8*ms)
			c.ClientData(start+16*ms, 200)
			c.ServerData(start+24*ms, 800)
			c.ClientAck(start+29*ms, 65535)
			c.FinClose(start+60*ms, 4*ms)
		}
	}

	return b
}

// buildR10Variable is the congestion shape: the same elevated median, but the
// round trips swing widely across connections.
//
// It exists to hold the steady/variable distinction to account. Both fixtures
// trip the ratio; only this one may describe the latency as varying, and a
// rule that reported the same sentence for both would be asserting a
// difference it had not measured.
func buildR10Variable() *Builder {
	b := New()

	// Six connections between 60ms and 400ms. The median is around 180ms and
	// the spread is nearly twice that, so nothing here reads as steady.
	swings := []time.Duration{60 * ms, 400 * ms, 90 * ms, 350 * ms, 180 * ms, 220 * ms}
	for i, rtt := range swings {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 47000+i),
			Server:    "10.7.7.3:443",
			ClientISN: uint32(10000 + i*1000),
			ServerISN: uint32(60000 + i*1000),
		})
		start := time.Duration(i) * 700 * ms
		c.Handshake(start, rtt)
		c.ClientData(start+rtt*2, 200)
		c.ServerData(start+rtt*2+rtt, 800)
		c.ClientAck(start+rtt*3+5*ms, 65535)
		c.FinClose(start+rtt*3+40*ms, 5*ms)
	}

	for h := 0; h < 12; h++ {
		for i := 0; i < 3; i++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("10.1.1.5:%d", 48000+h*10+i),
				Server:    fmt.Sprintf("10.2.2.%d:443", 10+h),
				ClientISN: uint32(200000 + h*5000 + i*100),
				ServerISN: uint32(700000 + h*5000 + i*100),
			})
			start := 6*s + time.Duration(h*3+i)*120*ms
			c.Handshake(start, 8*ms)
			c.ClientData(start+16*ms, 200)
			c.ServerData(start+24*ms, 800)
			c.ClientAck(start+29*ms, 65535)
			c.FinClose(start+60*ms, 4*ms)
		}
	}

	return b
}

// buildR10Negative is the false-positive trap: every host is far away.
//
// The check compares against the capture's own population, so a file where
// everything is slow has no outlier in it — and saying so is the honest
// result. A rule with an absolute latency threshold would report all thirteen
// hosts here and be wrong about every one.
func buildR10Negative() *Builder {
	b := New()

	for h := 0; h < 13; h++ {
		for i := 0; i < 3; i++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("10.1.1.5:%d", 49000+h*10+i),
				Server:    fmt.Sprintf("10.3.3.%d:443", 10+h),
				ClientISN: uint32(300000 + h*5000 + i*100),
				ServerISN: uint32(800000 + h*5000 + i*100),
			})
			// 170ms to 190ms: uniformly distant, no outlier.
			rtt := 170*ms + time.Duration(h)*ms + time.Duration(i)*3*ms
			start := time.Duration(h*3+i) * 500 * ms
			c.Handshake(start, rtt)
			c.ClientData(start+rtt*2, 200)
			c.ServerData(start+rtt*2+rtt, 800)
			c.ClientAck(start+rtt*3+5*ms, 65535)
			c.FinClose(start+rtt*3+40*ms, 5*ms)
		}
	}

	return b
}
