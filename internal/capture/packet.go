// Package capture reads pcap and pcapng files and decodes Ethernet, IP, TCP
// and UDP headers by hand, plus the two application protocols the v1 rules
// read.
//
// Framing (block structure, timestamp resolution, multiple interfaces) is
// delegated to pcapgo. Everything above that is decoded here, into a single
// reusable Packet struct, so the hot loop allocates nothing per packet.
//
// # The payload guarantee, and how its basis changed
//
// Hard constraint 3 is that no payload bytes reach output. Until Batch 3 this
// package enforced it in the strongest possible way: **it never looked.** The
// decoder stopped at the TCP header, recorded PayloadLength, and had no code
// path that could read a payload byte — so there was nothing to leak and
// nothing to review.
//
// R11 and R12 ended that. A DNS response code lives in the payload, and so
// does a TLS alert number and a certificate's expiry date, and a rule cannot
// report what a decoder refuses to read. So the basis moved, deliberately and
// with a compensating guard:
//
//	before: structural because payload is never read
//	now:    structural because only named scalars survive reading it
//
// That is genuinely weaker. "We only extract named fields" is an assertion
// where "we never read payload" was a property, so it is held up by tests
// rather than by intent — see allowlist_test.go, which requires every
// application-layer field to be declared in an explicit allowlist and to be a
// scalar incapable of holding a name, a subject, or a span of traffic.
//
// What is read above L4 is deliberately minimal, and appdecode.go says what
// each field is for. The DNS question section is not parsed at all: R11
// reports how many lookups failed and how long they took, never which names,
// so reading them would be collecting data the tool has no use for and then
// owing a promise about not emitting it.
package capture

import (
	"net/netip"
	"time"
)

// IP protocol numbers.
const (
	ProtoICMPv4 uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// TCP flag bits, as they appear in the low byte of the TCP flags field.
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
)

// Packet is the decoded view of one frame. It is reused across the read loop,
// so callers must not retain it: copy out anything needed beyond the current
// iteration.
type Packet struct {
	// Framing
	Frame          uint64
	Time           time.Time
	CaptureLength  int
	OriginalLength int
	// Truncated reports that the capture length was below the original wire
	// length, so this frame was cut short by the snaplen.
	Truncated bool

	// L2
	VLANCount int
	VLANs     [2]uint16

	// L3
	IPVersion uint8
	Src       netip.Addr
	Dst       netip.Addr
	TTL       uint8
	IPID      uint16
	// IPPayloadLength is the L4 byte count (header plus payload) taken from
	// the IP length field, clamped to the bytes actually captured.
	IPPayloadLength int
	// Fragmented reports a non-first IP fragment, where no L4 header is
	// present to decode.
	Fragmented bool

	Proto uint8

	// L4 (TCP only in v1)
	SrcPort       uint16
	DstPort       uint16
	Seq           uint32
	Ack           uint32
	Flags         uint8
	Window        uint16
	DataOffset    int
	PayloadLength int

	// TCP options. The option walker has to traverse every option correctly
	// regardless of how few are kept, so retaining another one costs nothing
	// beyond the field.
	//
	// OptWindowScale is -1 when the option was absent.
	OptWindowScale int8

	// OptMSS is the maximum segment size the sender advertised, or 0 when the
	// option was absent. Only meaningful on SYN segments.
	//
	// Kept so offload artifacts can be judged against what the connection
	// itself negotiated rather than against an assumed link MTU. A capture
	// taken on an endpoint shows segments the NIC later split, so apparent
	// segment size is not wire segment size — and the only trustworthy
	// statement about "too large" is one made relative to the maximum the two
	// ends agreed on in view of the capture.
	OptMSS uint16

	// Application-layer fields, for the two v1 rules that read above L4.
	//
	// Every one is a named scalar. There is deliberately no []byte and no
	// string here: a field capable of holding a span of payload is a field
	// that will eventually hold one, and the "no payload bytes in output"
	// guarantee is enforced by the shape of this struct rather than by
	// remembering not to copy anything into it. See appdecode.go for what each
	// field is for, and allowlist_test.go for the guard.
	//
	// DNS, read from UDP port 53 only. The question section — which carries
	// the name being looked up — is not parsed at all.
	DNSPresent    bool
	DNSIsResponse bool
	DNSID         uint16
	DNSRcode      uint8
	DNSQuestions  uint16
	DNSAnswers    uint16

	// TLS, read from TCP payload. TLSCertNotAfter is a Unix second, zero when
	// no certificate was read — which is the common case, not an error.
	TLSPresent       bool
	TLSRecordType    uint8
	TLSHandshakeType uint8
	TLSAlertLevel    uint8
	TLSAlertDesc     uint8
	TLSVersion       uint16
	TLSCertNotAfter  int64

	// DecodeErr is set when the frame was read but could not be decoded. The
	// packet is then not usable beyond its framing fields.
	DecodeErr error
}

// HasFlag reports whether all bits in f are set.
func (p *Packet) HasFlag(f uint8) bool { return p.Flags&f == f }

// AnyFlag reports whether any bit in f is set.
func (p *Packet) AnyFlag(f uint8) bool { return p.Flags&f != 0 }

// ConsumesSeq reports whether this segment occupies sequence space, and so can
// be acknowledged. Pure ACKs do not.
func (p *Packet) ConsumesSeq() bool {
	return p.PayloadLength > 0 || p.AnyFlag(FlagSYN|FlagFIN)
}

// SeqEnd returns the sequence number one past the last byte this segment
// occupies, using wrapping arithmetic.
func (p *Packet) SeqEnd() uint32 {
	end := p.Seq + uint32(p.PayloadLength)
	if p.AnyFlag(FlagSYN) {
		end++
	}
	if p.AnyFlag(FlagFIN) {
		end++
	}
	return end
}

// SeqLE reports a <= b under TCP serial-number arithmetic (RFC 1982).
func SeqLE(a, b uint32) bool { return int32(a-b) <= 0 }

// SeqLT reports a < b under TCP serial-number arithmetic.
func SeqLT(a, b uint32) bool { return int32(a-b) < 0 }

// reset clears the per-packet fields that decode does not unconditionally
// overwrite, so a reused Packet cannot leak state from the previous frame.
func (p *Packet) reset() {
	p.Truncated = false
	p.VLANCount = 0
	p.IPVersion = 0
	p.Src = netip.Addr{}
	p.Dst = netip.Addr{}
	p.TTL = 0
	p.IPID = 0
	p.IPPayloadLength = 0
	p.Fragmented = false
	p.Proto = 0
	p.SrcPort = 0
	p.DstPort = 0
	p.Seq = 0
	p.Ack = 0
	p.Flags = 0
	p.Window = 0
	p.DataOffset = 0
	p.PayloadLength = 0
	p.OptWindowScale = -1
	p.OptMSS = 0
	p.DNSPresent = false
	p.DNSIsResponse = false
	p.DNSID = 0
	p.DNSRcode = 0
	p.DNSQuestions = 0
	p.DNSAnswers = 0
	p.TLSPresent = false
	p.TLSRecordType = 0
	p.TLSHandshakeType = 0
	p.TLSAlertLevel = 0
	p.TLSAlertDesc = 0
	p.TLSVersion = 0
	p.TLSCertNotAfter = 0
	p.DecodeErr = nil
}
