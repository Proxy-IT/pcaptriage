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

	// PayloadLen is the number of payload bytes. The bytes themselves are
	// zeros; no rule reads them and no report may contain them.
	PayloadLen int
}

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
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		panic("synth: only IPv4 fixtures are supported")
	}

	var opts []byte
	if s.WindowScale >= 0 {
		// NOP, then window scale, then end-of-list, padded to 4 bytes.
		opts = []byte{1, 3, 3, byte(s.WindowScale)}
	}
	dataOffset := 20 + len(opts)

	tcp := make([]byte, dataOffset+s.PayloadLen)
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], s.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.Ack)
	tcp[12] = byte(dataOffset/4) << 4
	tcp[13] = s.Flags
	binary.BigEndian.PutUint16(tcp[14:16], s.Window)
	copy(tcp[20:], opts)

	s4, d4 := src.Addr().As4(), dst.Addr().As4()

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	// The IP ID is derived from the sequence number so it advances with the
	// stream and is reproducible.
	binary.BigEndian.PutUint16(ip[4:6], uint16(s.Seq>>8))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // don't fragment
	ip[8] = 64
	ip[9] = capture.ProtoTCP
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(s4, d4, tcp))

	eth := make([]byte, 14)
	copy(eth[0:6], macFor(d4))
	copy(eth[6:12], macFor(s4))
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)

	data := make([]byte, 0, len(eth)+len(ip)+len(tcp))
	data = append(data, eth...)
	data = append(data, ip...)
	data = append(data, tcp...)

	b.frames = append(b.frames, frame{at: s.At, data: data})
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

// Pcap renders the fixture as a classic pcap file.
func (b *Builder) Pcap() ([]byte, error) {
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(DefaultSnaplen, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	for _, f := range b.frames {
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
	for _, f := range b.frames {
		if err := w.WritePacket(b.captureInfo(f), f.data); err != nil {
			return nil, err
		}
	}

	// Written after the packets, which is where a capture tool puts it: the
	// counters are only final once capture stops.
	if b.stats != nil {
		last := BaseTime
		if n := len(b.frames); n > 0 {
			last = BaseTime.Add(b.frames[n-1].at)
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
	return gopacket.CaptureInfo{
		Timestamp:     BaseTime.Add(f.at),
		CaptureLength: len(f.data),
		Length:        len(f.data),
	}
}
