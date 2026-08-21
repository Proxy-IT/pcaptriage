package synth

import (
	"fmt"
	"time"
)

// Certificate expiry dates the R12 fixtures use, fixed so the committed bytes
// are reproducible. The capture clock sits at BaseTime, so "soon" and "far"
// are relative to that rather than to whenever the suite is regenerated.
var (
	fixtureCertExpiry = time.Date(2024, 3, 18, 0, 0, 0, 0, time.UTC)
	fixtureCertFar    = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

// buildR11Positive is R11's positive: one resolver failing, another working.
//
// The second resolver is not decoration. R11 compares a resolver against the
// others in the same capture, so a file containing only the broken one has no
// population and the finding falls back to reporting without comparison. A
// real capture of a failing resolver has the working one beside it, because
// clients are usually configured with two.
//
// The failing resolver: eighteen queries that get no answer at all, six that
// come back SERVFAIL, and a handful that succeed slowly — which is what gives
// the rule a measured cost for the ones that failed.
func buildR11Positive() *Builder {
	b := New()

	const bad = "10.0.0.53:53"
	const good = "10.0.0.54:53"

	var id uint16 = 1000
	t := 100 * ms

	// Eighteen unanswered. Each query is sent and nothing comes back; the
	// capture runs well past the two-second window so the silence is
	// observed rather than merely unrecorded.
	for i := 0; i < 18; i++ {
		b.AddDNS(DNSSpec{
			At: t, Client: fmt.Sprintf("10.1.1.%d:40000", 10+i%4), Resolver: bad,
			ID: id,
		})
		id++
		t += 150 * ms
	}

	// Six SERVFAIL, answered quickly — which is the point of the sub-case:
	// an error costs almost no time and still means the connection behind it
	// never happened.
	for i := 0; i < 6; i++ {
		client := fmt.Sprintf("10.1.1.%d:40100", 10+i%4)
		b.AddDNS(DNSSpec{At: t, Client: client, Resolver: bad, ID: id})
		b.AddDNS(DNSSpec{At: t + 12*ms, Client: client, Resolver: bad, ID: id,
			Response: true, Rcode: 2})
		id++
		t += 200 * ms
	}

	// Four that work, slowly. These give the rule the median cost of a
	// working lookup here, which is what prices the failures.
	for i := 0; i < 4; i++ {
		client := fmt.Sprintf("10.1.1.%d:40200", 10+i%4)
		b.AddDNS(DNSSpec{At: t, Client: client, Resolver: bad, ID: id})
		b.AddDNS(DNSSpec{At: t + 640*ms, Client: client, Resolver: bad, ID: id,
			Response: true, Rcode: 0, Answers: 1})
		id++
		t += 900 * ms
	}

	// The working resolver, answering promptly throughout. This is the
	// population the failing one is compared against.
	t2 := 120 * ms
	for i := 0; i < 20; i++ {
		client := fmt.Sprintf("10.1.1.%d:41000", 10+i%4)
		b.AddDNS(DNSSpec{At: t2, Client: client, Resolver: good, ID: id})
		b.AddDNS(DNSSpec{At: t2 + 8*ms, Client: client, Resolver: good, ID: id,
			Response: true, Rcode: 0, Answers: 1})
		id++
		t2 += 400 * ms
	}

	return b
}

// buildR11Negative is the clean case: two resolvers, every lookup answered
// promptly and correctly.
//
// The trap it guards is the one every comparative rule has — a capture where
// lookups are merely unremarkable must produce nothing, and a rule with an
// absolute idea of "slow" would report the 40ms answers here.
func buildR11Negative() *Builder {
	b := New()

	var id uint16 = 2000
	t := 100 * ms
	for _, resolver := range []string{"10.0.0.53:53", "10.0.0.54:53"} {
		for i := 0; i < 15; i++ {
			client := fmt.Sprintf("10.1.1.%d:42000", 10+i%5)
			b.AddDNS(DNSSpec{At: t, Client: client, Resolver: resolver, ID: id})
			b.AddDNS(DNSSpec{At: t + 40*ms, Client: client, Resolver: resolver, ID: id,
				Response: true, Rcode: 0, Answers: 2})
			id++
			t += 250 * ms
		}
	}
	return b
}

// buildR11Encrypted is the unavailable case: resolver traffic this build
// cannot read.
//
// Port 853 is DNS over TLS. The rule must say it could not look rather than
// letting an encrypted resolver produce the same empty result as a healthy
// one — which is the whole failure mode R11's degradation note exists for.
func buildR11Encrypted() *Builder {
	b := New()

	// Cleartext lookups to one resolver, working normally.
	var id uint16 = 3000
	t := 100 * ms
	for i := 0; i < 8; i++ {
		client := fmt.Sprintf("10.1.1.%d:43000", 10+i%3)
		b.AddDNS(DNSSpec{At: t, Client: client, Resolver: "10.0.0.53:53", ID: id})
		b.AddDNS(DNSSpec{At: t + 15*ms, Client: client, Resolver: "10.0.0.53:53", ID: id,
			Response: true, Rcode: 0, Answers: 1})
		id++
		t += 300 * ms
	}

	// And a DoT conversation, which is opaque. Rendered as TCP to 853, the
	// way a real one appears.
	c := b.NewConn(ConnOpts{
		Client: "10.1.1.20:44000", Server: "10.0.0.55:853",
		ClientISN: 7000, ServerISN: 9000,
	})
	c.HandshakeWithOptions(200*ms, 10*ms, 1460, true)
	ct := 250 * ms
	for i := 0; i < 6; i++ {
		c.ClientData(ct, 120)
		c.ServerData(ct+20*ms, 300)
		c.ClientAck(ct+25*ms, 65535)
		ct += 400 * ms
	}
	c.FinClose(ct+100*ms, 5*ms)

	return b
}

// buildR12Positive is R12's positive: one server refusing negotiations,
// against others that complete them.
//
// Twenty-three handshakes end in a fatal handshake_failure alert. Six more to
// the same server complete, slowly — which gives the rule the measured cost of
// a working negotiation here, and is what prices the failures under the
// wasted-work denominator.
//
// The other servers are the population. R12 compares a server against the
// others in the same capture, so without them the finding reports what it saw
// and declines to call it unusual.
func buildR12Positive() *Builder {
	b := New()

	// The failing server. A real fatal alert arrives after the round trip and
	// the server's reply, not instantly — a fixture whose handshakes failed in
	// microseconds would understate the shape and, more importantly, would
	// make the wasted-work figure meaningless.
	t := 100 * ms
	for i := 0; i < 23; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.%d:%d", 10+i%6, 45000+i),
			Server:    "10.2.2.7:443",
			ClientISN: uint32(10000 + i*500),
			ServerISN: uint32(50000 + i*500),
		})
		c.HandshakeWithOptions(t, 20*ms, 1460, true)
		c.ClientBytes(t+40*ms, TLSClientHello())
		c.ServerBytes(t+70*ms, TLSServerHello(0x0303))
		c.ServerBytes(t+75*ms, TLSCertificate(fixtureCertExpiry))
		// The client rejects what it was shown.
		c.ClientBytes(t+95*ms, TLSFatalAlert(40))
		c.ServerReset(t + 110*ms)
		t += 180 * ms
	}

	// Six that work on the same server, taking 1.4s — over the one-second
	// threshold, so they are reported as slow as well.
	for i := 0; i < 6; i++ {
		c := b.NewConn(ConnOpts{
			Client:    fmt.Sprintf("10.1.1.%d:%d", 10+i%6, 46000+i),
			Server:    "10.2.2.7:443",
			ClientISN: uint32(30000 + i*500),
			ServerISN: uint32(70000 + i*500),
		})
		c.HandshakeWithOptions(t, 20*ms, 1460, true)
		c.ClientBytes(t+40*ms, TLSClientHello())
		c.ServerBytes(t+900*ms, TLSServerHello(0x0303))
		c.ServerBytes(t+905*ms, TLSCertificate(fixtureCertExpiry))
		c.ClientBytes(t+1440*ms, TLSAppData(200))
		c.ServerBytes(t+1500*ms, TLSAppData(400))
		c.FinClose(t+1600*ms, 6*ms)
		t += 1900 * ms
	}

	// Four other servers negotiating normally in about 90ms.
	for h := 0; h < 4; h++ {
		for i := 0; i < 5; i++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("10.1.1.%d:%d", 10+i%6, 47000+h*10+i),
				Server:    fmt.Sprintf("10.2.2.%d:443", 20+h),
				ClientISN: uint32(100000 + h*5000 + i*300),
				ServerISN: uint32(200000 + h*5000 + i*300),
			})
			start := 60*s + time.Duration(h*5+i)*300*ms
			c.HandshakeWithOptions(start, 15*ms, 1460, true)
			c.ClientBytes(start+30*ms, TLSClientHello())
			c.ServerBytes(start+60*ms, TLSServerHello(0x0303))
			c.ServerBytes(start+65*ms, TLSCertificate(fixtureCertExpiry))
			c.ClientBytes(start+120*ms, TLSAppData(200))
			c.ServerBytes(start+150*ms, TLSAppData(400))
			c.FinClose(start+200*ms, 5*ms)
		}
	}

	return b
}

// buildR12Negative is the clean case: every negotiation completes promptly
// with a certificate valid well beyond the capture.
func buildR12Negative() *Builder {
	b := New()

	for h := 0; h < 3; h++ {
		for i := 0; i < 6; i++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("10.1.1.%d:%d", 10+i%4, 48000+h*10+i),
				Server:    fmt.Sprintf("10.2.2.%d:443", 30+h),
				ClientISN: uint32(300000 + h*5000 + i*300),
				ServerISN: uint32(400000 + h*5000 + i*300),
			})
			start := 100*ms + time.Duration(h*6+i)*250*ms
			c.HandshakeWithOptions(start, 12*ms, 1460, true)
			c.ClientBytes(start+25*ms, TLSClientHello())
			c.ServerBytes(start+50*ms, TLSServerHello(0x0303))
			c.ServerBytes(start+55*ms, TLSCertificate(fixtureCertFar))
			c.ClientBytes(start+95*ms, TLSAppData(200))
			c.ServerBytes(start+120*ms, TLSAppData(400))
			c.FinClose(start+160*ms, 5*ms)
		}
	}
	return b
}

// buildR12Encrypted is the unavailable case: TLS 1.3, where the handshake is
// encrypted after the server's first message and no certificate is visible.
//
// The negotiations all succeed. That is the point — a reader must not take an
// absence of certificate findings here as a statement that the certificates
// are fine, and R12's note is what stops them.
func buildR12Encrypted() *Builder {
	b := New()

	for h := 0; h < 2; h++ {
		for i := 0; i < 8; i++ {
			c := b.NewConn(ConnOpts{
				Client:    fmt.Sprintf("10.1.1.%d:%d", 10+i%4, 49000+h*10+i),
				Server:    fmt.Sprintf("10.2.2.%d:443", 40+h),
				ClientISN: uint32(500000 + h*5000 + i*300),
				ServerISN: uint32(600000 + h*5000 + i*300),
			})
			start := 100*ms + time.Duration(h*8+i)*250*ms
			c.HandshakeWithOptions(start, 12*ms, 1460, true)
			c.ClientBytes(start+25*ms, TLSClientHello())
			// A 1.3 ServerHello and then nothing readable: no Certificate
			// record, because a real 1.3 server encrypts it.
			c.ServerBytes(start+50*ms, TLSServerHello(0x0304))
			c.ClientBytes(start+90*ms, TLSAppData(200))
			c.ServerBytes(start+115*ms, TLSAppData(400))
			c.FinClose(start+160*ms, 5*ms)
		}
	}
	return b
}
