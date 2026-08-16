package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Decode errors. These are per-frame and non-fatal: the engine counts them by
// reason and continues, because a capture is attacker-controlled data and a
// single malformed frame must not abort the run.
var (
	ErrShortEthernet    = errors.New("frame shorter than an Ethernet header")
	ErrShortVLAN        = errors.New("frame shorter than the VLAN tag it claims")
	ErrVLANDepth        = errors.New("more stacked VLAN tags than supported")
	ErrUnknownEtherType = errors.New("ethertype is not IPv4 or IPv6")
	ErrShortIPv4        = errors.New("frame shorter than an IPv4 header")
	ErrBadIPv4IHL       = errors.New("IPv4 header length field is out of range")
	ErrBadIPv4Length    = errors.New("IPv4 total length is below its header length")
	ErrShortIPv6        = errors.New("frame shorter than an IPv6 header")
	ErrIPv6ExtDepth     = errors.New("more IPv6 extension headers than supported")
	ErrShortIPv6Ext     = errors.New("frame shorter than the IPv6 extension header it claims")
	ErrFragment         = errors.New("non-first IP fragment carries no L4 header")
	ErrShortTCP         = errors.New("frame shorter than a TCP header")
	ErrBadTCPOffset     = errors.New("TCP data offset is below the minimum header size")
	ErrNotTCP           = errors.New("not a TCP segment")
)

// UnsupportedLinkTypeError reports a capture whose link layer this build does
// not decode. v1 decodes Ethernet only; the error names what was seen so the
// user is told why rather than getting an empty report.
type UnsupportedLinkTypeError struct {
	LinkType int
	Name     string
}

func (e *UnsupportedLinkTypeError) Error() string {
	return fmt.Sprintf("unsupported link type %d (%s): this build decodes Ethernet only", e.LinkType, e.Name)
}

const (
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86dd
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88a8
	etherTypeQinQ2 = 0x9100

	maxVLANTags = 2
	maxIPv6Ext  = 8
)

// DecodeEthernet decodes one Ethernet frame into p, stopping at the TCP
// header. Non-TCP traffic decodes as far as L3 and then returns ErrNotTCP,
// which the caller may treat as "read but not analysed" rather than an error.
//
// data is borrowed for the duration of the call and never retained.
func DecodeEthernet(data []byte, p *Packet) error {
	p.reset()

	if len(data) < 14 {
		p.DecodeErr = ErrShortEthernet
		return ErrShortEthernet
	}
	off := 12
	et := binary.BigEndian.Uint16(data[off:])
	off += 2

	for et == etherTypeVLAN || et == etherTypeQinQ || et == etherTypeQinQ2 {
		if p.VLANCount >= maxVLANTags {
			p.DecodeErr = ErrVLANDepth
			return ErrVLANDepth
		}
		if len(data) < off+4 {
			p.DecodeErr = ErrShortVLAN
			return ErrShortVLAN
		}
		p.VLANs[p.VLANCount] = binary.BigEndian.Uint16(data[off:]) & 0x0fff
		p.VLANCount++
		et = binary.BigEndian.Uint16(data[off+2:])
		off += 4
	}

	switch et {
	case etherTypeIPv4:
		return decodeIPv4(data[off:], p)
	case etherTypeIPv6:
		return decodeIPv6(data[off:], p)
	default:
		p.DecodeErr = ErrUnknownEtherType
		return ErrUnknownEtherType
	}
}

func decodeIPv4(b []byte, p *Packet) error {
	if len(b) < 20 {
		p.DecodeErr = ErrShortIPv4
		return ErrShortIPv4
	}
	p.IPVersion = 4

	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 {
		p.DecodeErr = ErrBadIPv4IHL
		return ErrBadIPv4IHL
	}
	if ihl > len(b) {
		// Header claims more than was captured. Snaplen truncation lands here.
		p.Truncated = true
		p.DecodeErr = ErrShortIPv4
		return ErrShortIPv4
	}

	total := int(binary.BigEndian.Uint16(b[2:4]))
	p.IPID = binary.BigEndian.Uint16(b[4:6])
	fragField := binary.BigEndian.Uint16(b[6:8])
	fragOffset := fragField & 0x1fff
	p.TTL = b[8]
	p.Proto = b[9]

	var s4, d4 [4]byte
	copy(s4[:], b[12:16])
	copy(d4[:], b[16:20])
	p.Src = netip.AddrFrom4(s4)
	p.Dst = netip.AddrFrom4(d4)

	if fragOffset != 0 {
		p.Fragmented = true
		p.DecodeErr = ErrFragment
		return ErrFragment
	}

	avail := len(b) - ihl
	switch {
	case total == 0:
		// TCP segmentation offload writes a zero total length on some
		// capture paths. Fall back to what was actually captured; the wire
		// segment size is not knowable here either way.
		p.IPPayloadLength = avail
	case total < ihl:
		p.DecodeErr = ErrBadIPv4Length
		return ErrBadIPv4Length
	default:
		p.IPPayloadLength = total - ihl
		if p.IPPayloadLength > avail {
			p.Truncated = true
			p.IPPayloadLength = avail
		}
	}

	return decodeL4(b[ihl:], p)
}

func decodeIPv6(b []byte, p *Packet) error {
	if len(b) < 40 {
		p.DecodeErr = ErrShortIPv6
		return ErrShortIPv6
	}
	p.IPVersion = 6

	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	next := b[6]
	p.TTL = b[7] // hop limit

	var s16, d16 [16]byte
	copy(s16[:], b[8:24])
	copy(d16[:], b[24:40])
	p.Src = netip.AddrFrom16(s16).Unmap()
	p.Dst = netip.AddrFrom16(d16).Unmap()

	off := 40
	remaining := payloadLen
	if remaining == 0 || off+remaining > len(b) {
		// Jumbogram, offload artifact, or truncation. Use what is present.
		if off+remaining > len(b) && remaining != 0 {
			p.Truncated = true
		}
		remaining = len(b) - off
	}

	for i := 0; ; i++ {
		if i >= maxIPv6Ext {
			p.DecodeErr = ErrIPv6ExtDepth
			return ErrIPv6ExtDepth
		}
		switch next {
		case 0, 43, 60, 135: // hop-by-hop, routing, destination options, mobility
			if off+8 > len(b) {
				p.DecodeErr = ErrShortIPv6Ext
				return ErrShortIPv6Ext
			}
			extLen := (int(b[off+1]) + 1) * 8
			if off+extLen > len(b) {
				p.DecodeErr = ErrShortIPv6Ext
				return ErrShortIPv6Ext
			}
			next = b[off]
			off += extLen
			remaining -= extLen
		case 51: // authentication header, length in 4-byte units minus 2
			if off+8 > len(b) {
				p.DecodeErr = ErrShortIPv6Ext
				return ErrShortIPv6Ext
			}
			extLen := (int(b[off+1]) + 2) * 4
			if off+extLen > len(b) {
				p.DecodeErr = ErrShortIPv6Ext
				return ErrShortIPv6Ext
			}
			next = b[off]
			off += extLen
			remaining -= extLen
		case 44: // fragment header
			if off+8 > len(b) {
				p.DecodeErr = ErrShortIPv6Ext
				return ErrShortIPv6Ext
			}
			fragOffset := binary.BigEndian.Uint16(b[off+2:]) &^ 0x0007
			p.Proto = b[off]
			if fragOffset != 0 {
				p.Fragmented = true
				p.DecodeErr = ErrFragment
				return ErrFragment
			}
			next = b[off]
			off += 8
			remaining -= 8
		case 59: // no next header
			p.Proto = 59
			p.DecodeErr = ErrNotTCP
			return ErrNotTCP
		default:
			p.Proto = next
			if remaining < 0 {
				remaining = 0
			}
			if avail := len(b) - off; remaining > avail {
				p.Truncated = true
				remaining = avail
			}
			p.IPPayloadLength = remaining
			return decodeL4(b[off:], p)
		}
	}
}

func decodeL4(b []byte, p *Packet) error {
	if p.Proto != ProtoTCP {
		p.DecodeErr = ErrNotTCP
		return ErrNotTCP
	}
	if len(b) < 20 {
		p.Truncated = true
		p.DecodeErr = ErrShortTCP
		return ErrShortTCP
	}

	p.SrcPort = binary.BigEndian.Uint16(b[0:2])
	p.DstPort = binary.BigEndian.Uint16(b[2:4])
	p.Seq = binary.BigEndian.Uint32(b[4:8])
	p.Ack = binary.BigEndian.Uint32(b[8:12])
	p.DataOffset = int(b[12]>>4) * 4
	p.Flags = b[13]
	p.Window = binary.BigEndian.Uint16(b[14:16])

	if p.DataOffset < 20 {
		p.DecodeErr = ErrBadTCPOffset
		return ErrBadTCPOffset
	}

	// Payload length comes from the IP length field, not from the captured
	// byte count: with a truncating snaplen the captured bytes are short but
	// the segment really did carry that much data.
	payload := p.IPPayloadLength - p.DataOffset
	if payload < 0 {
		payload = 0
	}
	p.PayloadLength = payload

	optEnd := p.DataOffset
	if optEnd > len(b) {
		// Options were cut off by the snaplen. Parse what is there.
		p.Truncated = true
		optEnd = len(b)
	}
	if optEnd > 20 {
		parseTCPOptions(b[20:optEnd], p)
	}
	return nil
}

// parseTCPOptions walks the option list. Only window scale is extracted — it
// is what the per-flow completeness state needs — but every option kind has to
// be traversed correctly to reach it.
func parseTCPOptions(b []byte, p *Packet) {
	for i := 0; i < len(b); {
		kind := b[i]
		switch kind {
		case 0: // end of option list
			return
		case 1: // no-op
			i++
			continue
		}
		if i+1 >= len(b) {
			return
		}
		length := int(b[i+1])
		if length < 2 || i+length > len(b) {
			return
		}
		if kind == 3 && length == 3 {
			shift := b[i+2]
			// RFC 7323 caps the shift at 14; larger values must be treated as 14.
			if shift > 14 {
				shift = 14
			}
			p.OptWindowScale = int8(shift)
		}
		i += length
	}
}
