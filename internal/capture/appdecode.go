package capture

import (
	"crypto/x509"
	"encoding/binary"
	"time"
)

// Application-layer decoding, for the two v1 rules that need to see above L4.
//
// The rule this file follows, and the reason the package doc's guarantee had
// to be restated: **every field extracted here is a named scalar, and the
// bytes they were read from are never retained.** A record type, a response
// code, a count, an alert number, an expiry date. Nothing here can hold a
// name, a hostname, a certificate subject, or any span of the payload — there
// is deliberately no []byte and no string among them, so "no payload bytes in
// output" is enforced by the shape of the struct rather than by remembering
// not to copy anything.
//
// TestDecoderCarriesNoPayloadCapableField holds that to account.

// DNS response codes this build distinguishes. Others are recorded by number.
const (
	DNSRcodeNoError  uint8 = 0
	DNSRcodeServFail uint8 = 2
	DNSRcodeNXDomain uint8 = 3
)

// TLS record and handshake type numbers, and the alert level this build acts
// on. Only the ones the rules read are named.
const (
	TLSRecordHandshake uint8 = 22
	TLSRecordAlert     uint8 = 21

	TLSHandshakeClientHello uint8 = 1
	TLSHandshakeServerHello uint8 = 2
	TLSHandshakeCertificate uint8 = 11

	TLSAlertFatal uint8 = 2
)

// dnsPort is the only port this build reads DNS on.
//
// Cleartext port 53, per RULES.md. DNS over TLS (853) and DoH are encrypted
// and produce nothing here — which R11 reports as unavailable rather than
// letting an encrypted resolver look like a silent one.
const dnsPort = 53

// decodeDNS reads the DNS header out of a UDP payload.
//
// The header only: transaction id, whether it is a response, the response
// code, and the question and answer counts. The question section — which
// carries the name being looked up — is deliberately not parsed. R11 reports
// how many lookups failed and how long they took, never which names, so
// reading them would be collecting data the tool has no use for and a
// promise it would then have to keep about not emitting.
func decodeDNS(b []byte, p *Packet) {
	if len(b) < 12 {
		return
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	p.DNSPresent = true
	p.DNSID = binary.BigEndian.Uint16(b[0:2])
	p.DNSIsResponse = flags&0x8000 != 0
	p.DNSRcode = uint8(flags & 0x000F)
	p.DNSQuestions = binary.BigEndian.Uint16(b[4:6])
	p.DNSAnswers = binary.BigEndian.Uint16(b[6:8])
}

// decodeTLS walks the TLS records in one TCP segment.
//
// What it reads: the record type, the handshake type of the first handshake
// message, the alert level and description on an alert record, the version
// from a ServerHello, and the expiry date of the first certificate in a
// Certificate message.
//
// What it does not do, stated because R12's wording depends on the
// difference: it does not reassemble across segments. A handshake message
// split over two frames is not parsed, and a Certificate message larger than
// one segment — which is common — yields no date. That is a source of
// "certificate not inspected", and R12 must not read the absence of a date as
// the absence of a problem.
func decodeTLS(b []byte, p *Packet) {
	// A TLS record header is 5 bytes: type, version (2), length (2). The
	// version check is what keeps this from firing on arbitrary payload that
	// happens to start with 22.
	for len(b) >= 5 {
		rtype := b[0]
		ver := binary.BigEndian.Uint16(b[1:3])
		length := int(binary.BigEndian.Uint16(b[3:5]))
		if ver < 0x0300 || ver > 0x0304 || length <= 0 {
			return
		}
		if len(b) < 5+length {
			// Truncated or spanning segments: record what the type was and
			// stop rather than reading past the buffer.
			p.TLSPresent = true
			if p.TLSRecordType == 0 {
				p.TLSRecordType = rtype
			}
			return
		}
		body := b[5 : 5+length]
		p.TLSPresent = true
		if p.TLSRecordType == 0 {
			p.TLSRecordType = rtype
		}

		switch rtype {
		case TLSRecordAlert:
			if len(body) >= 2 {
				p.TLSAlertLevel = body[0]
				p.TLSAlertDesc = body[1]
			}
		case TLSRecordHandshake:
			decodeTLSHandshake(body, p)
		}

		b = b[5+length:]
	}
}

// decodeTLSHandshake reads handshake messages inside one record.
func decodeTLSHandshake(b []byte, p *Packet) {
	for len(b) >= 4 {
		htype := b[0]
		hlen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if hlen < 0 || len(b) < 4+hlen {
			if p.TLSHandshakeType == 0 {
				p.TLSHandshakeType = htype
			}
			return
		}
		body := b[4 : 4+hlen]
		if p.TLSHandshakeType == 0 {
			p.TLSHandshakeType = htype
		}

		switch htype {
		case TLSHandshakeServerHello:
			// The negotiated version. In TLS 1.3 the legacy field says 1.2 and
			// the real version is in a supported_versions extension; this
			// build reads the legacy field and R12 treats anything it cannot
			// confirm as "not inspected" rather than assuming 1.2.
			if len(body) >= 2 {
				p.TLSVersion = binary.BigEndian.Uint16(body[0:2])
			}
		case TLSHandshakeCertificate:
			decodeFirstCertExpiry(body, p)
		}

		b = b[4+hlen:]
	}
}

// decodeFirstCertExpiry extracts the expiry date of the first certificate.
//
// Only NotAfter is kept, as a Unix second. The certificate itself, its
// subject, its issuer and its key are parsed and discarded — crypto/x509 does
// the parsing precisely so this file does not hand-roll ASN.1 over
// attacker-controlled bytes, and the single scalar that survives is the only
// thing R12 reports.
func decodeFirstCertExpiry(b []byte, p *Packet) {
	// Certificate message: 3-byte total length, then repeated 3-byte length
	// plus DER.
	if len(b) < 6 {
		return
	}
	b = b[3:]
	certLen := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	if certLen <= 0 || len(b) < 3+certLen {
		return
	}
	cert, err := x509.ParseCertificate(b[3 : 3+certLen])
	if err != nil {
		return
	}
	p.TLSCertNotAfter = cert.NotAfter.Unix()
}

// CertNotAfter returns the certificate expiry as a time, and whether one was
// read at all.
func (p *Packet) CertNotAfter() (time.Time, bool) {
	if p.TLSCertNotAfter == 0 {
		return time.Time{}, false
	}
	return time.Unix(p.TLSCertNotAfter, 0).UTC(), true
}
