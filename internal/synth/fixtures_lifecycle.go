package synth

import (
	"fmt"
	"time"
)

// The Batch 2 connection-lifecycle fixtures for R09 and R14: connections cut
// off while data was still moving, and connections opened far more often than
// they needed to be.

// buildR09Positive is the R09 fixture: several connections from one host
// terminated by reset while a transfer was still active, against a majority
// that closed normally — so the "the remaining N closed normally" comparison
// has something to compare against and the uniformity trap does not fire.
func buildR09Positive() *Builder {
	b := New()

	// Eight connections cut off part-way through a substantial download. Each
	// runs for about two seconds before the reset — the shape RULES.md's
	// example describes, where a few hundred kilobytes had already moved.
	var t time.Duration = 100 * ms
	for i := 0; i < 8; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 60000+i),
			Server:    "10.2.2.7:443",
			ClientISN: uint32(100000 + i*1000),
			ServerISN: uint32(500000 + i*1000),
		})
		c.Handshake(t, 10*ms)
		c.ClientData(t+30*ms, 400)
		// A download in progress: twenty segments over two seconds, with the
		// client's acknowledgements running two segments behind, as they do
		// on a real transfer. That lag is the point — when the reset lands,
		// bytes are still unconfirmed, which is what "data in flight" means
		// and what separates an interrupted transfer from one that finished.
		var sent []uint32
		for n := 0; n < 20; n++ {
			at := t + 60*ms + time.Duration(n)*100*ms
			sent = append(sent, c.ServerNextSeq())
			c.ServerData(at, 16000)
			// From the third segment on: acking sent[0] any earlier would
			// repeat the handshake's own acknowledgement number and read as a
			// duplicate ACK, an artifact of the fixture rather than anything
			// this capture is meant to show.
			if n >= 3 {
				c.ClientAckAt(at+8*ms, sent[n-2])
			}
		}
		// Reset 40ms after the last data segment, with the final two segments
		// still unacknowledged.
		c.ServerReset(t + 2100*ms)
		t += 2400 * ms
	}

	// The same host closing other connections properly. Without these the
	// uniformity trap would fire and this fixture would be testing that
	// instead.
	for i := 0; i < 12; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 61000+i),
			Server:    "10.2.2.7:443",
			ClientISN: uint32(200000 + i*1000),
			ServerISN: uint32(600000 + i*1000),
		})
		start := 20000*ms + time.Duration(i)*150*ms
		c.Handshake(start, 10*ms)
		end := exchanges(c, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		c.FinClose(end, 5*ms)
	}

	return b
}

// buildR09Negative is the clean case: transfers of the same shape, every one
// closed with a proper FIN exchange. Nothing here may produce an R09 finding.
func buildR09Negative() *Builder {
	b := New()

	for i := 0; i < 10; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.3.3.5:%d", 62000+i),
			Server:    "10.4.4.7:443",
			ClientISN: uint32(300000 + i*1000),
			ServerISN: uint32(700000 + i*1000),
		})
		start := 100*ms + time.Duration(i)*150*ms
		c.Handshake(start, 10*ms)
		c.ClientData(start+30*ms, 400)
		c.ServerData(start+60*ms, 8000)
		c.ClientAck(start+70*ms, 65535)
		c.FinClose(start+90*ms, 5*ms)
	}

	// A reset long after the last data segment: the connection had gone quiet,
	// so this ended an idle connection rather than interrupting a transfer,
	// and R09 must not claim it.
	idle := b.NewConn(ConnOpts{
		Client: "10.3.3.5:62900", Server: "10.4.4.7:443",
		ClientISN: 400000, ServerISN: 800000,
	})
	idle.Handshake(2000*ms, 10*ms)
	idle.ClientData(2030*ms, 400)
	idle.ServerData(2060*ms, 4000)
	idle.ClientAck(2070*ms, 65535)
	idle.ServerReset(12000 * ms) // ten seconds later

	return b
}

// buildR09Uniform is RULES.md's false-positive trap: a host that closes every
// single connection with a reset rather than a FIN. Some applications do this
// deliberately to skip TIME_WAIT, so it is a habit rather than a fault, and
// the finding has to read as context rather than as N separate failures.
func buildR09Uniform() *Builder {
	b := New()

	for i := 0; i < 14; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.5.5.5:%d", 63000+i),
			Server:    "10.6.6.7:9000",
			ClientISN: uint32(500000 + i*1000),
			ServerISN: uint32(900000 + i*1000),
		})
		start := 100*ms + time.Duration(i)*120*ms
		c.Handshake(start, 10*ms)
		c.ClientData(start+30*ms, 300)
		c.ServerData(start+55*ms, 6000)
		c.ClientAck(start+65*ms, 65535)
		// A final segment the client never acknowledges before the reset
		// arrives. That leaves data in flight, so these resets are NOT
		// excluded as end-of-transfer closes — which is the point: this is the
		// habitual-reset case that slips past that carve-out and needs the
		// uniformity backstop to be read correctly.
		c.ServerData(start+75*ms, 6000)
		// Every one of them ends this way. No FIN anywhere on this host.
		c.ServerReset(start + 85*ms)
	}

	// Unrelated hosts closing normally, so the capture is not uniformly
	// reset-based and the habit is visibly this one host's.
	for i := 0; i < 4; i++ {
		p := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.5.5.6:%d", 64000+i),
			Server:    fmt.Sprintf("10.6.6.%d:443", 20+i),
			ClientISN: uint32(600000 + i*1000),
			ServerISN: uint32(950000 + i*1000),
		})
		start := 2000*ms + time.Duration(i)*150*ms
		p.Handshake(start, 10*ms)
		e := exchanges(p, start+30*ms, evenDeltas(3, 20*ms, 2*ms), 10*ms, 25*ms)
		p.FinClose(e, 5*ms)
	}

	return b
}

// buildR14Positive is the R14 fixture: one client cycling through many
// short-lived connections to the same server:port instead of reusing one.
func buildR14Positive() *Builder {
	b := New()

	// Sixty connections, each carrying one exchange and closing — comfortably
	// over the fifty-connection minimum, with a lifetime well under a second.
	var t time.Duration = 100 * ms
	for i := 0; i < 60; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.5:%d", 40000+i),
			Server:    "10.2.2.7:5432",
			ClientISN: uint32(100000 + i*1000),
			ServerISN: uint32(500000 + i*1000),
		})
		c.Handshake(t, 6*ms)
		c.ClientData(t+15*ms, 200)
		c.ServerData(t+40*ms, 900)
		c.ClientAck(t+48*ms, 65535)
		c.FinClose(t+60*ms, 4*ms)
		// Each connection lives about 68ms; a new one every 120ms.
		t += 120 * ms
	}

	// A long-lived connection to a different service on the same host, which
	// is what reuse looks like — and must not be swept into the churn finding.
	reuse := b.NewConn(ConnOpts{
		Client: "10.1.1.5:41000", Server: "10.2.2.7:443",
		ClientISN: 900000, ServerISN: 950000,
	})
	reuse.Handshake(200*ms, 8*ms)
	end := exchanges(reuse, 240*ms, evenDeltas(8, 20*ms, 3*ms), 8*ms, 500*ms)
	reuse.FinClose(end, 5*ms)

	return b
}

// buildR14Negative is ordinary connection reuse: a handful of connections,
// each held open across many exchanges. Below the connection minimum and far
// above the lifetime threshold, so nothing here may fire.
func buildR14Negative() *Builder {
	b := New()

	for i := 0; i < 8; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.7.7.5:%d", 42000+i),
			Server:    "10.8.8.7:5432",
			ClientISN: uint32(200000 + i*1000),
			ServerISN: uint32(600000 + i*1000),
		})
		start := 100*ms + time.Duration(i)*200*ms
		c.Handshake(start, 8*ms)
		// Held open across ten exchanges — several seconds of life each.
		end := exchanges(c, start+30*ms, evenDeltas(10, 20*ms, 2*ms), 8*ms, 400*ms)
		c.FinClose(end, 5*ms)
	}

	return b
}

// buildR14Midstream is the degradation case: enough connections to one
// endpoint to qualify, but most of them were already open when the capture
// began, so their lifetimes cannot be measured. RULES.md requires the check be
// reported unavailable with the excluded proportion, not silently skipped.
func buildR14Midstream() *Builder {
	b := New()

	// Fifty-five connections already in progress: no handshake, just traffic.
	var t time.Duration = 100 * ms
	for i := 0; i < 55; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.9.9.5:%d", 43000+i),
			Server:    "10.10.10.7:5432",
			ClientISN: uint32(300000 + i*1000),
			ServerISN: uint32(700000 + i*1000),
		})
		c.ClientData(t, 200)
		c.ServerData(t+20*ms, 900)
		c.ClientAck(t+28*ms, 65535)
		c.FinClose(t+40*ms, 4*ms)
		t += 60 * ms
	}

	// A few whose openings were captured — not enough on their own to clear
	// the minimum, which is exactly the situation the note has to explain.
	for i := 0; i < 5; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.9.9.5:%d", 44000+i),
			Server:    "10.10.10.7:5432",
			ClientISN: uint32(800000 + i*1000),
			ServerISN: uint32(880000 + i*1000),
		})
		start := 4000*ms + time.Duration(i)*100*ms
		c.Handshake(start, 6*ms)
		c.ClientData(start+15*ms, 200)
		c.ServerData(start+40*ms, 900)
		c.ClientAck(start+48*ms, 65535)
		c.FinClose(start+60*ms, 4*ms)
	}

	return b
}
