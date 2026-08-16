package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Format names the capture container.
type Format string

const (
	FormatPcap   Format = "pcap"
	FormatPcapng Format = "pcapng"
)

// ErrUnknownFormat reports a file that is neither pcap nor pcapng.
var ErrUnknownFormat = errors.New("file is neither pcap nor pcapng (magic number not recognised)")

// DropAvailability says whether this capture can tell us how many packets the
// capturing host dropped before they ever reached the file.
//
// The distinction between "the file says none" and "the file cannot say"
// matters more here than almost anywhere else in the tool. Packets dropped by
// the capture host look exactly like packets lost on the network, and a rule
// reporting loss cannot tell them apart. Reporting "no drops" when the truth is
// "no drop counter exists" would be the false all-clear the brief's section 9
// is about.
type DropAvailability string

const (
	// DropsReported means the file carries drop counters and they were read.
	DropsReported DropAvailability = "reported"
	// DropsAbsent means the format supports drop counters but this file has
	// none — a pcapng with no Interface Statistics Block.
	DropsAbsent DropAvailability = "absent"
	// DropsUnsupported means the format has nowhere to record them. Classic
	// pcap has no such field at all.
	DropsUnsupported DropAvailability = "unsupported-format"
)

// InterfaceDrops is one capture interface's packet counters, as the file
// reports them.
type InterfaceDrops struct {
	// ID is the pcapng interface identifier.
	ID int
	// Name is the interface name where the file records one.
	Name string
	// Dropped is packets the capture host discarded before writing them.
	Dropped uint64
	// Received is packets the capture host saw. Zero when the file omits it.
	Received uint64
	// ReceivedKnown reports whether Received was present; a file may record
	// drops without recording receipts.
	ReceivedKnown bool
}

// countingReader tallies bytes pulled from the file, so an interface can show
// how far through a capture the run is.
//
// The count is bytes read from disk rather than packets decoded, which lags the
// buffered reader slightly. That is immaterial for a progress indicator and
// costs nothing on the hot path.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// Reader streams packets out of a capture file.
//
// The file is opened read-only and never written to. Packet data is read
// zero-copy: the byte slice handed to the decoder is valid only until the next
// call, which is safe because the decoder retains nothing.
type Reader struct {
	f       *os.File
	br      *bufio.Reader
	counter *countingReader
	size    int64

	pcap *pcapgo.Reader
	ng   *pcapgo.NgReader

	format   Format
	linkType layers.LinkType
	snaplen  uint32
	// snaplenKnown is false for pcapng files that advertise no snap length,
	// which means unlimited rather than zero.
	snaplenKnown bool

	// dropsByInterface accumulates Interface Statistics Blocks as they are
	// read. Keyed by interface id, so it is sorted before it is handed out.
	//
	// An ISB is normally written when the capture is closed, so these arrive at
	// the very end of the file — after every packet. Nothing may read them
	// mid-run and expect them to be complete.
	dropsByInterface map[int]InterfaceDrops

	frame uint64
}

// Open opens a capture file for reading.
//
// The returned Reader holds the file open until Close. The file is opened
// O_RDONLY; nothing in this package writes to, or anywhere near, the input
// path.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	counter := &countingReader{r: f}
	r := &Reader{f: f, counter: counter, br: bufio.NewReaderSize(counter, 1<<20)}
	if fi, err := f.Stat(); err == nil {
		r.size = fi.Size()
	}

	magic, err := r.br.Peek(4)
	if err != nil {
		f.Close()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: file is shorter than a capture file header", ErrUnknownFormat)
		}
		return nil, err
	}

	switch {
	case binary.BigEndian.Uint32(magic) == 0x0a0d0d0a:
		r.format = FormatPcapng
		r.dropsByInterface = make(map[int]InterfaceDrops)
		ng, err := pcapgo.NewNgReader(r.br, pcapgo.NgReaderOptions{
			// Mixing link types in one file is a merge artifact. Refusing it
			// is better than silently dropping the packets libpcap would drop.
			WantMixedLinkType:          false,
			ErrorOnMismatchingLinkType: true,
			SkipUnknownVersion:         true,
			// Interface Statistics Blocks are how a pcapng records what the
			// capture host itself threw away. pcapgo surfaces them here, so
			// nothing has to parse the block structure by hand.
			StatisticsCallback: r.recordInterfaceStats,
		})
		if err != nil {
			f.Close()
			return nil, err
		}
		r.ng = ng
		r.linkType = ng.LinkType()
		r.readNgSnaplen()

	case isPcapMagic(magic):
		r.format = FormatPcap
		pr, err := pcapgo.NewReader(r.br)
		if err != nil {
			f.Close()
			return nil, err
		}
		r.pcap = pr
		r.linkType = pr.LinkType()
		r.snaplen = pr.Snaplen()
		r.snaplenKnown = true

	default:
		f.Close()
		return nil, ErrUnknownFormat
	}

	if r.linkType != layers.LinkTypeEthernet {
		f.Close()
		return nil, &UnsupportedLinkTypeError{
			LinkType: int(r.linkType),
			Name:     r.linkType.String(),
		}
	}

	return r, nil
}

func isPcapMagic(b []byte) bool {
	v := binary.BigEndian.Uint32(b)
	switch v {
	case 0xa1b2c3d4, 0xd4c3b2a1, // microsecond, both byte orders
		0xa1b23c4d, 0x4d3cb2a1: // nanosecond, both byte orders
		return true
	}
	return false
}

// readNgSnaplen takes the smallest snap length across the interfaces declared
// so far. Interfaces added later in the file are not reflected; that is a
// capture-quality concern for R15 rather than something the decoder needs.
func (r *Reader) readNgSnaplen() {
	n := r.ng.NInterfaces()
	for i := 0; i < n; i++ {
		iface, err := r.ng.Interface(i)
		if err != nil {
			continue
		}
		if iface.SnapLength == 0 {
			continue // unlimited
		}
		if !r.snaplenKnown || iface.SnapLength < r.snaplen {
			r.snaplen = iface.SnapLength
			r.snaplenKnown = true
		}
	}
}

// Format reports the container format.
func (r *Reader) Format() Format { return r.format }

// LinkType reports the link layer of the capture.
func (r *Reader) LinkType() layers.LinkType { return r.linkType }

// Snaplen reports the capture snap length. ok is false when the file declares
// no limit.
func (r *Reader) Snaplen() (snaplen uint32, ok bool) { return r.snaplen, r.snaplenKnown }

// recordInterfaceStats folds one Interface Statistics Block into the tally.
//
// A file may carry several for the same interface — statistics are cumulative
// snapshots, so the last one seen for an interface wins rather than being
// summed. Summing would multiply the same drops by however many times the
// capture tool checkpointed them.
func (r *Reader) recordInterfaceStats(id int, stats pcapgo.NgInterfaceStatistics) {
	d := InterfaceDrops{ID: id}
	if stats.PacketsDropped != pcapgo.NgNoValue64 {
		d.Dropped = stats.PacketsDropped
	}
	if stats.PacketsReceived != pcapgo.NgNoValue64 {
		d.Received = stats.PacketsReceived
		d.ReceivedKnown = true
	}
	if iface, err := r.ng.Interface(id); err == nil {
		d.Name = iface.Name
	}
	r.dropsByInterface[id] = d
}

// Drops reports what the capture host discarded, and whether the file was able
// to say at all.
//
// Only meaningful once the file has been read to the end: an Interface
// Statistics Block is normally written when the capture is closed, so calling
// this mid-run will under-report.
func (r *Reader) Drops() (drops []InterfaceDrops, availability DropAvailability) {
	if r.format != FormatPcapng {
		// Classic pcap has no field for this. Not "no drops" — no answer.
		return nil, DropsUnsupported
	}
	if len(r.dropsByInterface) == 0 {
		return nil, DropsAbsent
	}

	ids := make([]int, 0, len(r.dropsByInterface))
	for id := range r.dropsByInterface {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	out := make([]InterfaceDrops, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.dropsByInterface[id])
	}
	return out, DropsReported
}

// BytesRead reports how many bytes have been pulled from the file so far.
func (r *Reader) BytesRead() int64 { return r.counter.n.Load() }

// Size reports the file's total size in bytes, or zero if it could not be
// determined.
func (r *Reader) Size() int64 { return r.size }

// Next reads and decodes the next frame into p.
//
// It returns io.EOF at end of file. Any other returned error is fatal to the
// run. A frame that was read but could not be decoded is reported by
// decoded == false with the reason in p.DecodeErr; the caller should count it
// and continue, since one malformed frame must not abort analysis of the rest.
func (r *Reader) Next(p *Packet) (decoded bool, err error) {
	var (
		data []byte
		ci   gopacket.CaptureInfo
	)
	if r.pcap != nil {
		data, ci, err = r.pcap.ZeroCopyReadPacketData()
	} else {
		data, ci, err = r.ng.ZeroCopyReadPacketData()
	}
	if err != nil {
		return false, err
	}

	r.frame++

	// DecodeEthernet resets p, so the framing fields are applied after it.
	derr := DecodeEthernet(data, p)

	p.Frame = r.frame
	p.Time = ci.Timestamp.UTC()
	p.CaptureLength = ci.CaptureLength
	p.OriginalLength = ci.Length
	if ci.Length > ci.CaptureLength {
		p.Truncated = true
	}

	return derr == nil, nil
}

// Close releases the underlying file.
func (r *Reader) Close() error { return r.f.Close() }
