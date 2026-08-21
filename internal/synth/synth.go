// Package synth builds capture files byte by byte for tests.
//
// Fixtures are crafted here rather than captured from a live stack: no
// network, no privileges, no timing jitter, and small enough to commit. This
// is the primary answer to the corpus problem — no public collection of
// labelled network performance pathologies exists, so the positive and
// negative case for every rule has to be constructed.
//
// Everything here is deterministic. Timestamps are offsets from a fixed base,
// payload bytes are zeros, and MAC addresses are derived from the IP, so the
// same fixture definition always produces the same file.
package synth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
)

// BaseTime is the capture start for every synthesised fixture. It is fixed so
// output does not depend on when the fixture was built.
var BaseTime = time.Date(2024, 3, 14, 9, 0, 0, 0, time.UTC)

// DefaultSnaplen is written into the fixture file headers.
const DefaultSnaplen = 262144

// Builder accumulates frames and writes them out as pcap or pcapng.
type Builder struct {
	frames []frame

	// stats, when set, is written as an Interface Statistics Block in the
	// pcapng rendering. Classic pcap has nowhere to put it, so the two
	// renderings of a fixture carrying one are deliberately not equivalent.
	stats *InterfaceStats
}

// InterfaceStats is the capture host's own packet counters, as a capture tool
// records them when it closes the file.
type InterfaceStats struct {
	// Received is packets the capture host saw.
	Received uint64
	// Dropped is packets it discarded before writing them.
	Dropped uint64
}

// WithInterfaceStats attaches capture-host counters to the pcapng rendering.
func (b *Builder) WithInterfaceStats(s InterfaceStats) *Builder {
	b.stats = &s
	return b
}

type frame struct {
	at   time.Duration
	data []byte
	// wire is the length the frame had on the wire, which differs from
	// len(data) only for a sliced capture. Zero means "not sliced", so every
	// fixture that does not ask for slicing keeps len(data) for both.
	wire int
}

// New returns an empty builder.
func New() *Builder { return &Builder{} }

// TCPSpec describes one TCP segment to synthesise.
type TCPSpec struct {
	// At is the offset from BaseTime.
	At time.Duration
	// Src and Dst are "addr:port".
	Src, Dst string

	Seq, Ack uint32
	Flags    uint8
	Window   uint16

	// WindowScale, when non-negative, adds a window scale option. It is only
	// meaningful on SYN segments.
	WindowScale int

	// MSS, when non-zero, adds a maximum segment size option. Only meaningful
	// on SYN segments. Real stacks always send it; fixtures that model
	// realistic handshakes should too.
	MSS uint16

	// SACKPermitted adds the SACK-permitted option. Only meaningful on SYN
	// segments.
	SACKPermitted bool

	// TTL is the IPv4 time-to-live, or the IPv6 hop limit. Zero means
	// DefaultTTL, which is what every fixture authored before this field
	// existed gets — so adding it changed no committed fixture.
	//
	// Per-packet rather than per-connection because the one rule that reads
	// it, R03, is looking for a segment whose TTL disagrees with the rest of
	// its peer's traffic: a forged RST injected by a middlebox closer to the
	// capture point than the real host is. That is only expressible if a
	// single segment can differ from its neighbours.
	TTL uint8

	// PayloadLen is the number of payload bytes. The bytes themselves are
	// zeros; no rule reads them and no report may contain them.
	PayloadLen int

	// Payload, when set, supplies the actual bytes instead of zeros, and its
	// length overrides PayloadLen. Used only by fixtures that model an
	// application protocol the rules read — R12's TLS records. Everything else
	// leaves it nil, because no other rule looks at payload content.
	Payload []byte
}

// DefaultTTL is the hop count fixtures use unless they say otherwise. 64 is
// the initial TTL Linux and macOS send with, so a packet that has crossed no
// router still carries it.
const DefaultTTL = 64

// AddTCP appends one TCP segment.
func (b *Builder) AddTCP(s TCPSpec) {
	src, err := netip.ParseAddrPort(s.Src)
	if err != nil {
		panic(fmt.Sprintf("synth: bad source %q: %v", s.Src, err))
	}
	dst, err := netip.ParseAddrPort(s.Dst)
	if err != nil {
		panic(fmt.Sprintf("synth: bad destination %q: %v", s.Dst, err))
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		panic("synth: source and destination must be the same address family")
	}

	// Option layout. The WindowScale-only encoding is kept byte-for-byte as it
	// was before MSS and SACK-permitted existed, so every fixture authored
	// against it renders identically; the combined encoding follows the order
	// real stacks emit (MSS, SACK-permitted, window scale) and pads to a
	// four-byte boundary with NOPs.
	var opts []byte
	if s.MSS > 0 {
		opts = append(opts, 2, 4, byte(s.MSS>>8), byte(s.MSS))
	}
	if s.SACKPermitted {
		opts = append(opts, 4, 2)
	}
	if s.WindowScale >= 0 {
		if len(opts) == 0 {
			// Legacy encoding: NOP, then window scale.
			opts = append(opts, 1, 3, 3, byte(s.WindowScale))
		} else {
			opts = append(opts, 3, 3, byte(s.WindowScale))
		}
	}
	for len(opts)%4 != 0 {
		opts = append(opts, 1) // NOP padding
	}
	dataOffset := 20 + len(opts)

	payloadLen := s.PayloadLen
	if len(s.Payload) > 0 {
		payloadLen = len(s.Payload)
	}
	tcp := make([]byte, dataOffset+payloadLen)
	if len(s.Payload) > 0 {
		copy(tcp[dataOffset:], s.Payload)
	}
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], s.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.Ack)
	tcp[12] = byte(dataOffset/4) << 4
	tcp[13] = s.Flags
	binary.BigEndian.PutUint16(tcp[14:16], s.Window)
	copy(tcp[20:], opts)

	ttl := s.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	var (
		ip        []byte
		etherType uint16
	)
	if src.Addr().Is4() {
		s4, d4 := src.Addr().As4(), dst.Addr().As4()

		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
		// The IP ID is derived from the sequence number so it advances with the
		// stream and is reproducible. It also means a segment's IP ID reflects
		// its original transmission order — which is exactly the property R07's
		// reordering heuristic reads, so a fixture that replays a segment late
		// carries the ID it was "first sent" with, the way a real NIC would.
		binary.BigEndian.PutUint16(ip[4:6], uint16(s.Seq>>8))
		binary.BigEndian.PutUint16(ip[6:8], 0x4000) // don't fragment
		ip[8] = ttl
		ip[9] = capture.ProtoTCP
		copy(ip[12:16], s4[:])
		copy(ip[16:20], d4[:])
		binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(s4, d4, tcp))
		etherType = 0x0800
	} else {
		s16, d16 := src.Addr().As16(), dst.Addr().As16()

		// A plain IPv6 header: no extension headers, and — the property the R07
		// IPv6 fixture exists to exercise — no IP ID field at all.
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcp)))
		ip[6] = capture.ProtoTCP // next header
		ip[7] = ttl              // hop limit
		copy(ip[8:24], s16[:])
		copy(ip[24:40], d16[:])

		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum6(s16, d16, tcp))
		etherType = 0x86dd
	}

	eth := make([]byte, 14)
	copy(eth[0:6], macForAddr(dst.Addr()))
	copy(eth[6:12], macForAddr(src.Addr()))
	binary.BigEndian.PutUint16(eth[12:14], etherType)

	data := make([]byte, 0, len(eth)+len(ip)+len(tcp))
	data = append(data, eth...)
	data = append(data, ip...)
	data = append(data, tcp...)

	b.frames = append(b.frames, frame{at: s.At, data: data})
}

// macForAddr derives a reproducible MAC for either address family.
func macForAddr(a netip.Addr) []byte {
	if a.Is4() {
		return macFor(a.As4())
	}
	a16 := a.As16()
	var last4 [4]byte
	copy(last4[:], a16[12:16])
	return macFor(last4)
}

// tcpChecksum6 is the TCP checksum over the IPv6 pseudo-header.
func tcpChecksum6(src, dst [16]byte, tcp []byte) uint16 {
	pseudo := make([]byte, 40, 40+len(tcp))
	copy(pseudo[0:16], src[:])
	copy(pseudo[16:32], dst[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = capture.ProtoTCP
	pseudo = append(pseudo, tcp...)
	return checksum(pseudo)
}

// macFor derives a locally-administered MAC from an IPv4 address, so each host
// in a fixture has a distinct and reproducible link address.
func macFor(ip [4]byte) []byte {
	return []byte{0x02, 0x00, ip[0], ip[1], ip[2], ip[3]}
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst [4]byte, tcp []byte) uint16 {
	pseudo := make([]byte, 12, 12+len(tcp))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = capture.ProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	pseudo = append(pseudo, tcp...)
	return checksum(pseudo)
}

// Len reports how many frames have been added.
func (b *Builder) Len() int { return len(b.frames) }

// sortedFrames returns the frames in timestamp order.
//
// Fixtures are authored flow by flow for readability, but a real
// single-interface capture is written in time order — emitting authored order
// produced files capinfos flags as not strictly time-ordered, which no genuine
// capture of this kind would be. The sort is stable, so frames placed at the
// same instant keep their authored order: intra-instant ordering stays an
// authoring decision, never a sort accident.
func (b *Builder) sortedFrames() []frame {
	out := make([]frame, len(b.frames))
	copy(out, b.frames)
	sort.SliceStable(out, func(i, j int) bool { return out[i].at < out[j].at })
	return out
}

// Pcap renders the fixture as a classic pcap file.
func (b *Builder) Pcap() ([]byte, error) {
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(DefaultSnaplen, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	for _, f := range b.sortedFrames() {
		if err := w.WritePacket(b.captureInfo(f), f.data); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// Pcapng renders the fixture as a pcapng file.
//
// The section and interface options are pinned rather than left to defaults,
// so nothing about the machine that built the fixture leaks into it.
func (b *Builder) Pcapng() ([]byte, error) {
	var buf bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&buf, pcapgo.NgInterface{
		Name:                "fixture",
		LinkType:            layers.LinkTypeEthernet,
		SnapLength:          DefaultSnaplen,
		TimestampResolution: 6, // microseconds, matching the pcap rendering
	}, pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    "synthetic",
			OS:          "synthetic",
			Application: "pcaptriage-fixture",
		},
	})
	if err != nil {
		return nil, err
	}
	frames := b.sortedFrames()
	for _, f := range frames {
		if err := w.WritePacket(b.captureInfo(f), f.data); err != nil {
			return nil, err
		}
	}

	// Written after the packets, which is where a capture tool puts it: the
	// counters are only final once capture stops. With frames in time order,
	// the last frame is also the latest.
	if b.stats != nil {
		last := BaseTime
		if n := len(frames); n > 0 {
			last = BaseTime.Add(frames[n-1].at)
		}
		if err := w.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{
			StartTime:       BaseTime,
			EndTime:         last,
			LastUpdate:      last,
			PacketsReceived: b.stats.Received,
			PacketsDropped:  b.stats.Dropped,
		}); err != nil {
			return nil, err
		}
	}

	if err := w.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Builder) captureInfo(f frame) gopacket.CaptureInfo {
	wire := f.wire
	if wire == 0 {
		wire = len(f.data)
	}
	return gopacket.CaptureInfo{
		Timestamp:     BaseTime.Add(f.at),
		CaptureLength: len(f.data),
		Length:        wire,
	}
}

// MangleTCPDataOffset rewrites the TCP data offset field of every nth TCP
// frame to a value below the 20-byte minimum, modelling a capture whose header
// bytes did not survive whatever wrote the file.
//
// This corrupts deliberately, which no other builder method does, so it is
// worth being explicit about what it models. A capture from a NETSCOUT
// InfiniStream appliance arrived with a third of its frames in exactly this
// state: IPv4 headers checksumming clean, TCP data offsets holding values no
// stack emits, and flag bytes distributed like noise. The point of the fixture
// is that the tool must say so rather than build flows out of the remainder
// and report findings from them.
//
// Frames are selected in timestamp order so the choice does not depend on
// authoring order, and the nibble is set rather than randomised, so the file is
// byte-identical on every run.
func (b *Builder) MangleTCPDataOffset(everyNth int) {
	if everyNth < 1 {
		panic("synth: MangleTCPDataOffset needs a positive interval")
	}

	// sortedFrames copies the slice but not the backing arrays, so writing
	// through it reaches the frames the builder will emit.
	seen := 0
	for _, f := range b.sortedFrames() {
		d := f.data
		if len(d) < 14+20 || binary.BigEndian.Uint16(d[12:14]) != 0x0800 {
			continue // not IPv4 over Ethernet
		}
		ihl := int(d[14]&0x0f) * 4
		if ihl < 20 || d[14+9] != 6 {
			continue // not TCP
		}
		off := 14 + ihl
		if len(d) < off+20 {
			continue
		}

		seen++
		if seen%everyNth != 0 {
			continue
		}
		// Data offset 1 == a 4-byte TCP header, which cannot exist. The low
		// nibble is reserved and left as it was.
		d[off+12] = (d[off+12] & 0x0f) | 0x10
	}
}

// SliceFrames truncates every frame to at most n captured bytes while
// recording the length it had on the wire, modelling a capture taken with a
// snap length — `tcpdump -s 54`, or an appliance configured for headers only.
//
// The distinction this exists to preserve is the one the malformed-header
// guard turns on: a sliced frame is missing bytes, but every length field it
// does carry is still the one the sender wrote. Nothing about it is
// self-contradictory, and it must not read as corruption.
func (b *Builder) SliceFrames(n int) {
	for i := range b.frames {
		f := &b.frames[i]
		if f.wire == 0 {
			f.wire = len(f.data)
		}
		if len(f.data) > n {
			f.data = f.data[:n]
		}
	}
}
