package findings

import (
	"sort"
	"strings"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
)

// SnapshotPacket takes a header snapshot of a frame.
//
// It is called only for frames a finding will actually cite, never on the hot
// path for every packet — the callers gate it on whether the occurrence is
// being retained.
func SnapshotPacket(p *capture.Packet, role PacketRole, note string, markers ...string) PacketRef {
	ref := PacketRef{
		Frame:      p.Frame,
		Time:       p.Time,
		Src:        endpointString(p, true),
		Dst:        endpointString(p, false),
		Protocol:   protocolName(p.Proto),
		Length:     p.OriginalLength,
		Seq:        p.Seq,
		Ack:        p.Ack,
		Window:     p.Window,
		Flags:      FlagString(p.Flags),
		PayloadLen: p.PayloadLength,
		Role:       role,
		Note:       note,
	}
	if len(markers) > 0 {
		ref.Markers = append([]string(nil), markers...)
	}
	return ref
}

func endpointString(p *capture.Packet, src bool) string {
	addr, port := p.Dst, p.DstPort
	if src {
		addr, port = p.Src, p.SrcPort
	}
	if !addr.IsValid() {
		return "?"
	}
	if addr.Is6() {
		return "[" + addr.String() + "]:" + itoa(int(port))
	}
	return addr.String() + ":" + itoa(int(port))
}

func protocolName(proto uint8) string {
	switch proto {
	case capture.ProtoTCP:
		return "TCP"
	case capture.ProtoUDP:
		return "UDP"
	case capture.ProtoICMPv4:
		return "ICMP"
	case capture.ProtoICMPv6:
		return "ICMPv6"
	}
	return "IP"
}

// FlagString renders TCP flags the way Wireshark lists them, in header order.
func FlagString(flags uint8) string {
	var set []string
	for _, f := range []struct {
		bit  uint8
		name string
	}{
		{capture.FlagCWR, "CWR"},
		{capture.FlagECE, "ECE"},
		{capture.FlagURG, "URG"},
		{capture.FlagACK, "ACK"},
		{capture.FlagPSH, "PSH"},
		{capture.FlagRST, "RST"},
		{capture.FlagSYN, "SYN"},
		{capture.FlagFIN, "FIN"},
	} {
		if flags&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	return strings.Join(set, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// SortPacketRefs orders refs by frame number, which is the order a reader will
// meet them in Wireshark.
func SortPacketRefs(refs []PacketRef) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].Frame < refs[j].Frame })
}

// SetRelativeTimes fills RelSeconds from the capture's first packet time, which
// is the clock Wireshark's default time column uses.
//
// It runs at emit time rather than when the packet is recorded, because the
// capture's start is only settled once the read has finished.
func SetRelativeTimes(refs []PacketRef, captureStart time.Time) {
	if captureStart.IsZero() {
		return
	}
	for i := range refs {
		refs[i].RelSeconds = refs[i].Time.Sub(captureStart).Seconds()
	}
}
