package synth

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"time"
)

// TLS message construction, for R12's fixtures.
//
// Only the records R12 reads: a ClientHello, a ServerHello with a version, a
// Certificate message carrying one real certificate, a fatal alert, and an
// application-data record standing in for the encrypted traffic that follows a
// successful negotiation.
//
// The handshake bodies are minimal rather than realistic. R12 reads the record
// type, the handshake type, the alert numbers, the version and one expiry
// date; a fixture that carried a full cipher-suite list and extension set
// would be asserting that fields nobody parses were ignored.

// tlsRecord wraps a handshake body in a record header.
func tlsRecord(rtype uint8, version uint16, body []byte) []byte {
	out := make([]byte, 5, 5+len(body))
	out[0] = rtype
	binary.BigEndian.PutUint16(out[1:3], version)
	binary.BigEndian.PutUint16(out[3:5], uint16(len(body)))
	return append(out, body...)
}

// tlsHandshake wraps a message body in a handshake header.
func tlsHandshake(htype uint8, body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	out[0] = htype
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	return append(out, body...)
}

// TLSClientHello is a ClientHello record.
func TLSClientHello() []byte {
	// Version, 32 random bytes, empty session id. Enough to be well-formed.
	body := make([]byte, 2+32+1)
	binary.BigEndian.PutUint16(body[0:2], 0x0303)
	return tlsRecord(22, 0x0301, tlsHandshake(1, body))
}

// TLSServerHello is a ServerHello record announcing version.
//
// Pass 0x0303 for TLS 1.2 and 0x0304 for 1.3. The 1.3 case is what makes
// certificate inspection unavailable: a real 1.3 server encrypts everything
// after this message, so the fixture emits no Certificate record at all.
func TLSServerHello(version uint16) []byte {
	body := make([]byte, 2+32+1)
	binary.BigEndian.PutUint16(body[0:2], version)
	return tlsRecord(22, 0x0303, tlsHandshake(2, body))
}

// TLSCertificate is a Certificate record carrying one certificate expiring at
// notAfter.
//
// A real, parseable certificate rather than a stub, because the decoder hands
// the bytes to crypto/x509 and a stub would exercise the error path instead of
// the one the rule depends on.
func TLSCertificate(notAfter time.Time) []byte {
	der := selfSigned(notAfter)

	body := make([]byte, 6+len(der))
	total := 3 + len(der)
	body[0] = byte(total >> 16)
	body[1] = byte(total >> 8)
	body[2] = byte(total)
	body[3] = byte(len(der) >> 16)
	body[4] = byte(len(der) >> 8)
	body[5] = byte(len(der))
	copy(body[6:], der)

	return tlsRecord(22, 0x0303, tlsHandshake(11, body))
}

// TLSFatalAlert is a fatal alert record. desc 40 is handshake_failure.
func TLSFatalAlert(desc uint8) []byte {
	return tlsRecord(21, 0x0303, []byte{2, desc})
}

// TLSAppData is an application-data record, standing in for the encrypted
// traffic that follows a completed negotiation. Its arrival is how R12 knows
// a handshake finished, since the messages that conclude one are themselves
// encrypted.
func TLSAppData(n int) []byte {
	return tlsRecord(23, 0x0303, make([]byte, n))
}

// fixedSource is a deterministic byte stream standing in for crypto/rand.
//
// Fixtures are committed files and the whole suite rests on byte-identical
// regeneration: a certificate built from real randomness would produce
// different bytes on every `-update`, so every golden touching it would churn
// for no reason and nobody could reproduce a committed fixture.
//
// This is fixture material and nothing else. The keys it produces are
// deterministic by construction and therefore worthless as keys — which is
// exactly the point, and why they never leave this package.
type fixedSource struct{ state uint64 }

func (f *fixedSource) Read(p []byte) (int, error) {
	for i := range p {
		// xorshift64*, chosen because it is a few lines and reproducible
		// across platforms and Go versions, unlike math/rand's stream.
		f.state ^= f.state >> 12
		f.state ^= f.state << 25
		f.state ^= f.state >> 27
		p[i] = byte((f.state * 0x2545F4914F6CDD1D) >> 56)
	}
	return len(p), nil
}

// selfSigned builds a DER certificate expiring at notAfter.
//
// Everything that affects the committed bytes is fixed: the serial, the
// subject, the validity start, and the randomness. Only notAfter varies, which
// is the one field R12 reads.
func selfSigned(notAfter time.Time) []byte {
	// Ed25519 rather than ECDSA, and the reason is determinism rather than
	// preference: Go hedges ECDSA signatures with entropy from crypto/rand
	// whatever reader it is handed, so the same inputs produce different bytes
	// every run. Ed25519 signing is a deterministic function of key and
	// message (RFC 8032), so a fixed seed gives fixed certificate bytes.
	src := &fixedSource{state: 0x9E3779B97F4A7C15}
	pub, priv, err := ed25519.GenerateKey(src)
	if err != nil {
		panic("synth: generating a fixture key: " + err.Error())
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture.invalid"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(src, tmpl, tmpl, pub, priv)
	if err != nil {
		panic("synth: creating a fixture certificate: " + err.Error())
	}
	return der
}

// ClientBytes emits an exact payload from the client.
func (c *Conn) ClientBytes(at time.Duration, b []byte) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.client, Dst: c.server,
		Seq: c.cseq, Ack: c.sseq,
		Flags: 0x18, Window: c.cwin, WindowScale: -1, Payload: b,
	})
	c.cseq += uint32(len(b))
}

// ServerBytes emits an exact payload from the server.
func (c *Conn) ServerBytes(at time.Duration, b []byte) {
	c.b.AddTCP(TCPSpec{
		At: at, Src: c.server, Dst: c.client,
		Seq: c.sseq, Ack: c.cseq,
		Flags: 0x18, Window: c.swin, WindowScale: -1, Payload: b,
	})
	c.sseq += uint32(len(b))
}
