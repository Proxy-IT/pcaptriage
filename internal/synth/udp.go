package synth

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// UDP and DNS construction, for R11's fixtures.
//
// The builder was TCP-only until Batch 3. This adds the smallest UDP surface
// that lets a fixture express what R11 reads: a query, a response with a given
// code, and silence where a response should have been.

// DNSSpec is one DNS message.
//
// It carries no name. R11 does not parse the question section and reports how
// many lookups failed rather than which ones, so a fixture has nothing to gain
// from carrying names it would only be asserting were ignored. The question
// count is set; the question bytes are a minimal well-formed stub.
type DNSSpec struct {
	// At is the offset from BaseTime.
	At time.Duration
	// Client and Resolver are "addr:port".
	Client, Resolver string
	// ID pairs a response with its query, the way a real resolver does.
	ID uint16
	// Response marks this as an answer rather than a question.
	Response bool
	// Rcode is the response code — 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN.
	Rcode uint8
	// Answers is the answer count, which a successful lookup has and a failed
	// one does not.
	Answers uint16
}

// AddDNS appends one DNS message over UDP.
func (b *Builder) AddDNS(s DNSSpec) {
	client, err := netip.ParseAddrPort(s.Client)
	if err != nil {
		panic(fmt.Sprintf("synth: bad client %q: %v", s.Client, err))
	}
	resolver, err := netip.ParseAddrPort(s.Resolver)
	if err != nil {
		panic(fmt.Sprintf("synth: bad resolver %q: %v", s.Resolver, err))
	}

	// A minimal question section: one label "a", type A, class IN. Present so
	// the datagram is well-formed for any tool that reads it — tshark reads
	// these fixtures too — rather than because the engine looks at it.
	question := []byte{0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01}

	msg := make([]byte, 12, 12+len(question)+16)
	binary.BigEndian.PutUint16(msg[0:2], s.ID)
	var flags uint16
	if s.Response {
		flags |= 0x8000 // QR
		flags |= 0x0080 // RA, which a real resolver sets
	}
	flags |= 0x0100 // RD, set on the query and echoed
	flags |= uint16(s.Rcode) & 0x000F
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[4:6], 1) // one question
	binary.BigEndian.PutUint16(msg[6:8], s.Answers)
	msg = append(msg, question...)

	// An answer record, where the response claims one. A pointer back to the
	// question name, type A, class IN, a short TTL, and four bytes of address.
	for i := uint16(0); i < s.Answers; i++ {
		msg = append(msg,
			0xC0, 0x0C, // name pointer to offset 12
			0x00, 0x01, // type A
			0x00, 0x01, // class IN
			0x00, 0x00, 0x00, 0x3C, // TTL 60
			0x00, 0x04, // rdlength
			10, 20, 30, 40,
		)
	}

	src, dst := client, resolver
	if s.Response {
		src, dst = resolver, client
	}

	udp := make([]byte, 8+len(msg))
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	// Checksum left zero, which is legal for IPv4 UDP and is what the TCP
	// path here does too.
	copy(udp[8:], msg)

	b.addFrame(s.At, src.Addr(), dst.Addr(), ProtoUDPNum, udp)
}

// ProtoUDPNum is UDP's IP protocol number.
const ProtoUDPNum uint8 = 17

// addFrame wraps an L4 payload in IPv4 and Ethernet.
//
// IPv4 only, deliberately: R11's fixtures are cleartext DNS to a resolver, and
// nothing in the rule reads anything that differs by address family. AddTCP
// carries its own framing because it also computes a TCP checksum over a
// pseudo-header and has an IPv6 path the reordering fixtures need; sharing one
// helper between them would mean generalising that, which is more than either
// caller currently wants. If a third protocol arrives, factor then.
func (b *Builder) addFrame(at time.Duration, src, dst netip.Addr, proto uint8, l4 []byte) {
	if !src.Is4() || !dst.Is4() {
		panic("synth: addFrame is IPv4 only")
	}
	s4, d4 := src.As4(), dst.As4()

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // don't fragment
	ip[8] = DefaultTTL
	ip[9] = proto
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	eth := make([]byte, 14)
	copy(eth[0:6], macForAddr(dst))
	copy(eth[6:12], macForAddr(src))
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	data := make([]byte, 0, len(eth)+len(ip)+len(l4))
	data = append(data, eth...)
	data = append(data, ip...)
	data = append(data, l4...)

	b.frames = append(b.frames, frame{at: at, data: data})
}
