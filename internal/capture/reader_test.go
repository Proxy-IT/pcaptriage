package capture

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// tcpFrame is one Ethernet/IPv4/TCP SYN, 54 bytes, used to prove that a file
// opens far enough to decode a packet rather than merely far enough to read a
// header.
func tcpFrame() []byte {
	f := make([]byte, 0, 54)
	f = append(f, 0x02, 0, 0, 0, 0, 0x02) // dst MAC
	f = append(f, 0x02, 0, 0, 0, 0, 0x01) // src MAC
	f = append(f, 0x08, 0x00)             // IPv4

	ip := []byte{
		0x45, 0x00, 0x00, 0x28, // version/IHL, DSCP, total length 40
		0x00, 0x01, 0x00, 0x00, // id, flags/fragment
		0x40, 0x06, 0x00, 0x00, // TTL, protocol TCP, checksum
		10, 0, 0, 1, // source
		10, 0, 0, 2, // destination
	}
	f = append(f, ip...)

	tcp := []byte{
		0x04, 0xd2, 0x00, 0x50, // ports 1234 -> 80
		0x00, 0x00, 0x00, 0x01, // sequence
		0x00, 0x00, 0x00, 0x00, // acknowledgement
		0x50, 0x02, 0xff, 0xff, // data offset 5, SYN, window
		0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
	}
	return append(f, tcp...)
}

// writePcap builds a classic pcap holding one frame, with the global header's
// snap length set to whatever the caller asks for — including zero, which is
// how libpcap spells "no truncation limit".
func writePcap(t *testing.T, snaplen uint32, order binary.ByteOrder) string {
	t.Helper()

	magic := uint32(0xa1b2c3d4)
	hdr := make([]byte, 24)
	order.PutUint32(hdr[0:4], magic)
	order.PutUint16(hdr[4:6], 2)
	order.PutUint16(hdr[6:8], 4)
	order.PutUint32(hdr[16:20], snaplen)
	order.PutUint32(hdr[20:24], 1) // Ethernet

	frame := tcpFrame()
	rec := make([]byte, 16)
	order.PutUint32(rec[0:4], 1700000000)
	order.PutUint32(rec[4:8], 0)
	order.PutUint32(rec[8:12], uint32(len(frame)))
	order.PutUint32(rec[12:16], uint32(len(frame)))

	path := filepath.Join(t.TempDir(), "capture.pcap")
	out := append(append(hdr, rec...), frame...)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPcapZeroSnaplenIsReadable covers the file several capture appliances
// write: a classic pcap whose global header declares a snap length of zero.
//
// Zero is how the format has to spell "unlimited", since the field is a plain
// uint32 with no absent value. Read as a literal ceiling it rejects every
// packet, which is what made these files fail to load at all.
func TestPcapZeroSnaplenIsReadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
	}{
		{"little-endian", binary.LittleEndian},
		{"big-endian", binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Open(writePcap(t, 0, tc.order))
			if err != nil {
				t.Fatalf("a zero snap length must not stop the file opening: %v", err)
			}
			defer r.Close()

			if _, ok := r.Snaplen(); ok {
				// Reporting the substituted number would be inventing a limit
				// the file never declared.
				snaplen, _ := r.Snaplen()
				t.Errorf("snap length reported as known (%d); the file declares none", snaplen)
			}

			var p Packet
			decoded, err := r.Next(&p)
			if err != nil {
				t.Fatalf("reading the packet: %v", err)
			}
			if !decoded {
				t.Fatalf("packet did not decode: %v", p.DecodeErr)
			}
			if p.SrcPort != 1234 || p.DstPort != 80 {
				t.Errorf("decoded ports %d -> %d, want 1234 -> 80", p.SrcPort, p.DstPort)
			}
			if p.Truncated {
				t.Error("packet marked truncated; nothing was cut off")
			}
			if _, err := r.Next(&p); err != io.EOF {
				t.Errorf("second read = %v, want EOF", err)
			}
		})
	}
}

// TestPcapDeclaredSnaplenIsReported holds the other side of the same line: a
// file that does declare a limit must still have that exact number reported,
// so the shim cannot quietly erase a real snap length.
func TestPcapDeclaredSnaplenIsReported(t *testing.T) {
	r, err := Open(writePcap(t, 262144, binary.LittleEndian))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	snaplen, ok := r.Snaplen()
	if !ok {
		t.Fatal("snap length reported as unknown; the file declares 262144")
	}
	if snaplen != 262144 {
		t.Errorf("snap length = %d, want 262144", snaplen)
	}
}
