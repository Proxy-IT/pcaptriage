package capture

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

// buildFrame assembles an Ethernet/IPv4/TCP frame for decoder tests.
func buildFrame(vlans []uint16, payload int, opts []byte) []byte {
	dataOffset := 20 + len(opts)
	tcp := make([]byte, dataOffset+payload)
	binary.BigEndian.PutUint16(tcp[0:2], 44210)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 0x1000)
	binary.BigEndian.PutUint32(tcp[8:12], 0x2000)
	tcp[12] = byte(dataOffset/4) << 4
	tcp[13] = FlagPSH | FlagACK
	binary.BigEndian.PutUint16(tcp[14:16], 8192)
	copy(tcp[20:], opts)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = ProtoTCP
	copy(ip[12:16], []byte{10, 1, 1, 5})
	copy(ip[16:20], []byte{10, 2, 2, 7})

	// [dst MAC][src MAC] then, per VLAN tag, [0x8100][TCI], then the real
	// ethertype and the IP header.
	out := make([]byte, 12)
	for _, v := range vlans {
		out = append(out, 0x81, 0x00, byte(v>>8), byte(v))
	}
	out = append(out, 0x08, 0x00)
	out = append(out, ip...)
	out = append(out, tcp...)
	return out
}

// packetHasByteSlice reports whether Packet has gained any field capable of
// holding raw bytes.
func packetHasByteSlice() bool {
	t := reflect.TypeOf(Packet{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i).Type
		switch f.Kind() {
		case reflect.Slice, reflect.Array:
			if f.Elem().Kind() == reflect.Uint8 {
				return true
			}
		case reflect.String:
			return true
		}
	}
	return false
}

func TestDecodePlainTCP(t *testing.T) {
	var p Packet
	if err := DecodeEthernet(buildFrame(nil, 100, nil), &p); err != nil {
		t.Fatal(err)
	}
	if p.IPVersion != 4 {
		t.Errorf("IPVersion = %d, want 4", p.IPVersion)
	}
	if p.Src.String() != "10.1.1.5" || p.Dst.String() != "10.2.2.7" {
		t.Errorf("addresses = %s -> %s", p.Src, p.Dst)
	}
	if p.SrcPort != 44210 || p.DstPort != 443 {
		t.Errorf("ports = %d -> %d", p.SrcPort, p.DstPort)
	}
	if p.PayloadLength != 100 {
		t.Errorf("PayloadLength = %d, want 100", p.PayloadLength)
	}
	if p.Window != 8192 {
		t.Errorf("Window = %d, want 8192", p.Window)
	}
	if !p.HasFlag(FlagACK) || !p.HasFlag(FlagPSH) {
		t.Errorf("Flags = %#x", p.Flags)
	}
	if p.OptWindowScale != -1 {
		t.Errorf("OptWindowScale = %d, want -1 when the option is absent", p.OptWindowScale)
	}
}

func TestDecodeVLANTags(t *testing.T) {
	for _, tags := range [][]uint16{{100}, {100, 200}} {
		var p Packet
		if err := DecodeEthernet(buildFrame(tags, 10, nil), &p); err != nil {
			t.Fatalf("%d tags: %v", len(tags), err)
		}
		if p.VLANCount != len(tags) {
			t.Errorf("VLANCount = %d, want %d", p.VLANCount, len(tags))
		}
		for i, want := range tags {
			if got := p.VLANs[i] & 0x0fff; got != want&0x0fff {
				t.Errorf("VLAN %d = %d, want %d", i, got, want&0x0fff)
			}
		}
		if p.PayloadLength != 10 {
			t.Errorf("PayloadLength = %d, want 10", p.PayloadLength)
		}
	}
}

func TestDecodeWindowScaleOption(t *testing.T) {
	var p Packet
	// NOP, window scale 7, padded to a 4-byte boundary.
	if err := DecodeEthernet(buildFrame(nil, 0, []byte{1, 3, 3, 7}), &p); err != nil {
		t.Fatal(err)
	}
	if p.OptWindowScale != 7 {
		t.Errorf("OptWindowScale = %d, want 7", p.OptWindowScale)
	}
}

// TestDecodeWindowScaleClamped checks RFC 7323's cap. A capture is
// attacker-controlled data and a shift of 255 would otherwise propagate.
func TestDecodeWindowScaleClamped(t *testing.T) {
	var p Packet
	if err := DecodeEthernet(buildFrame(nil, 0, []byte{1, 3, 3, 200}), &p); err != nil {
		t.Fatal(err)
	}
	if p.OptWindowScale != 14 {
		t.Errorf("OptWindowScale = %d, want 14 (the RFC 7323 maximum)", p.OptWindowScale)
	}
}

// TestDecodeMalformedInputDoesNotPanic is the hostile-input requirement.
// Every prefix and several corruptions of a valid frame must produce an error
// rather than a panic or an out-of-range read.
func TestDecodeMalformedInputDoesNotPanic(t *testing.T) {
	full := buildFrame([]uint16{100}, 64, []byte{1, 3, 3, 7})

	for i := 0; i <= len(full); i++ {
		var p Packet
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte prefix: %v", i, r)
				}
			}()
			_ = DecodeEthernet(full[:i], &p)
		}()
	}

	// Corrupt each byte in turn to a value likely to break a length field.
	for _, v := range []byte{0x00, 0xff, 0x0f, 0xf0} {
		for i := range full {
			corrupt := append([]byte{}, full...)
			corrupt[i] = v
			var p Packet
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic with byte %d set to %#x: %v", i, v, r)
					}
				}()
				_ = DecodeEthernet(corrupt, &p)
			}()
		}
	}
}

// TestDecodeRejectsBadHeaderLengths checks the specific length fields that
// would otherwise index out of range.
func TestDecodeRejectsBadHeaderLengths(t *testing.T) {
	t.Run("ipv4 ihl below minimum", func(t *testing.T) {
		f := buildFrame(nil, 10, nil)
		f[14] = 0x44 // IHL of 4 words is 16 bytes, below the 20-byte minimum
		var p Packet
		if err := DecodeEthernet(f, &p); !errors.Is(err, ErrBadIPv4IHL) {
			t.Errorf("err = %v, want ErrBadIPv4IHL", err)
		}
	})

	t.Run("tcp data offset below minimum", func(t *testing.T) {
		f := buildFrame(nil, 10, nil)
		f[14+20+12] = 0x40 // 4 words is 16 bytes, below the 20-byte minimum
		var p Packet
		if err := DecodeEthernet(f, &p); !errors.Is(err, ErrBadTCPOffset) {
			t.Errorf("err = %v, want ErrBadTCPOffset", err)
		}
	})

	t.Run("ipv4 total length below header", func(t *testing.T) {
		f := buildFrame(nil, 10, nil)
		binary.BigEndian.PutUint16(f[16:18], 10)
		var p Packet
		if err := DecodeEthernet(f, &p); !errors.Is(err, ErrBadIPv4Length) {
			t.Errorf("err = %v, want ErrBadIPv4Length", err)
		}
	})
}

// TestDecodeNonFirstFragment checks that a fragment with no L4 header is
// reported rather than decoded from whatever bytes happen to follow.
func TestDecodeNonFirstFragment(t *testing.T) {
	f := buildFrame(nil, 40, nil)
	binary.BigEndian.PutUint16(f[14+6:], 185) // fragment offset, no more-fragments bit
	var p Packet
	if err := DecodeEthernet(f, &p); !errors.Is(err, ErrFragment) {
		t.Errorf("err = %v, want ErrFragment", err)
	}
	if !p.Fragmented {
		t.Error("Fragmented was not set")
	}
	if p.Src.String() != "10.1.1.5" {
		t.Error("L3 addresses should still decode on a fragment")
	}
}

// TestDecodeNonTCP checks that other protocols decode to L3 and stop, rather
// than being reported as a decode failure. The v1 rules are TCP only, and a
// capture full of UDP is not a capture the tool failed to read.
func TestDecodeNonTCP(t *testing.T) {
	f := buildFrame(nil, 40, nil)
	f[14+9] = ProtoUDP
	var p Packet
	if err := DecodeEthernet(f, &p); !errors.Is(err, ErrNotTCP) {
		t.Errorf("err = %v, want ErrNotTCP", err)
	}
	if p.Proto != ProtoUDP {
		t.Errorf("Proto = %d, want %d", p.Proto, ProtoUDP)
	}
}

// TestSeqArithmetic checks the wrapping comparison used for ACK matching.
func TestSeqArithmetic(t *testing.T) {
	cases := []struct {
		a, b uint32
		le   bool
	}{
		{0, 0, true},
		{1, 2, true},
		{2, 1, false},
		{0xffffffff, 0, true},  // wraps forward
		{0, 0xffffffff, false}, // and not backward
		{0xfffffff0, 0x10, true},
	}
	for _, c := range cases {
		if got := SeqLE(c.a, c.b); got != c.le {
			t.Errorf("SeqLE(%#x, %#x) = %v, want %v", c.a, c.b, got, c.le)
		}
	}
}

// TestSeqEnd checks that SYN and FIN each occupy a sequence number, which is
// what makes ACK RTT sampling line up on handshakes and teardowns.
func TestSeqEnd(t *testing.T) {
	p := Packet{Seq: 100, PayloadLength: 50}
	if got := p.SeqEnd(); got != 150 {
		t.Errorf("data only: SeqEnd = %d, want 150", got)
	}
	p.Flags = FlagSYN
	if got := p.SeqEnd(); got != 151 {
		t.Errorf("with SYN: SeqEnd = %d, want 151", got)
	}
	p.Flags = FlagFIN
	if got := p.SeqEnd(); got != 151 {
		t.Errorf("with FIN: SeqEnd = %d, want 151", got)
	}
}

// TestPacketNeverRetainsPayload is a structural check on the "no payload bytes
// in output" guarantee: the decoded packet records a length and nothing else
// about the payload, so there is no field for payload to leak through.
func TestPacketNeverRetainsPayload(t *testing.T) {
	data := buildFrame(nil, 64, nil)
	for i := 14 + 20 + 20; i < len(data); i++ {
		data[i] = 0xAB // recognisable payload
	}
	var p Packet
	if err := DecodeEthernet(data, &p); err != nil {
		t.Fatal(err)
	}
	if p.PayloadLength != 64 {
		t.Fatalf("PayloadLength = %d, want 64", p.PayloadLength)
	}
	// There is no []byte field on Packet at all; this asserts the shape stays
	// that way if someone adds one.
	if got := packetHasByteSlice(); got {
		t.Error("Packet gained a byte-slice field; payload must never be retained")
	}
}
