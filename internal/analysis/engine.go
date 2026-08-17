// Package analysis drives the single streaming pass: read, decode, update flow
// state, offer the packet to every rule, then emit findings once the
// comparative baselines are complete.
package analysis

import (
	"errors"
	"io"
	"net/netip"
	"sort"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Progress reports how far through a capture a run has got.
//
// It exists so an interface can show that work is happening on a large file.
// It carries no findings and cannot influence what is detected.
type Progress struct {
	PacketsRead uint64
	BytesRead   int64
	// TotalBytes is the file size, or zero where it could not be determined.
	TotalBytes int64
	// Done marks the final callback, sent once the read has finished.
	Done bool
}

// Fraction returns progress through the file in the range 0 to 1, and whether
// it is known at all.
func (p Progress) Fraction() (float64, bool) {
	if p.Done {
		return 1, true
	}
	if p.TotalBytes <= 0 {
		return 0, false
	}
	f := float64(p.BytesRead) / float64(p.TotalBytes)
	if f > 1 {
		f = 1
	}
	return f, true
}

// DefaultProgressInterval is how many packets pass between progress callbacks.
const DefaultProgressInterval = 4096

// Options configure a run.
type Options struct {
	// MaxFlows bounds concurrently tracked flows. Zero uses
	// flow.DefaultMaxFlows.
	MaxFlows int

	// Progress, when set, is called periodically during the read and once more
	// when it finishes.
	//
	// It lives here rather than in an interface so that the GUI does not have
	// to reimplement any part of the read loop to know how far along it is.
	// It is called from the reading goroutine, so it should not block.
	Progress func(Progress)

	// ProgressInterval is how many packets pass between callbacks. Zero uses
	// DefaultProgressInterval.
	ProgressInterval int
}

// CaptureInfo describes the file and what was read out of it.
type CaptureInfo struct {
	Path     string
	Format   string
	LinkType string

	Snaplen      uint32
	SnaplenKnown bool

	PacketsRead      uint64
	PacketsDecoded   uint64
	PacketsTCP       uint64
	PacketsNonTCP    uint64
	PacketsUndecoded uint64
	// UndecodedReasons counts decode failures by reason, so a capture the tool
	// largely failed to read cannot look like a capture with nothing in it.
	UndecodedReasons map[string]uint64

	FirstPacketTime time.Time
	LastPacketTime  time.Time

	TCPFlows       int
	CompleteFlows  int
	PartialFlows   int
	MidstreamFlows int
	OneWayFlows    int
	TCPHosts       int

	FlowCap       int
	FlowsEvicted  uint64
	PeakLiveFlows int

	// DropAvailability says whether this capture could report packets the
	// capture host discarded before writing them.
	DropAvailability capture.DropAvailability
	// InterfaceDrops is per-interface, ascending by interface id.
	InterfaceDrops []capture.InterfaceDrops
	// PacketsDropped is the total across interfaces.
	PacketsDropped uint64
	// DropRatio is PacketsDropped against what the file would have held had
	// nothing been dropped, so 0.01 means one packet in a hundred never
	// reached the file.
	DropRatio float64
	// DropsSignificant reports that the ratio cleared the threshold at which
	// apparent packet loss can no longer be assumed to be loss on the wire.
	DropsSignificant bool
}

// Result is everything a report needs from a run.
type Result struct {
	Capture  CaptureInfo
	Findings []*findings.Finding
	Notes    []findings.Note
	Checks   []rules.Meta
	// Quality is what the capture itself can support, as the rules saw it.
	// Carried out of the run so a reader can tell why a finding was degraded
	// without re-deriving the reason.
	Quality rules.CaptureQuality
}

// Run analyses a capture file.
//
// The input file is opened read-only and nothing is written to or near it.
func Run(path string, opts Options) (*Result, error) {
	r, err := capture.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	maxFlows := opts.MaxFlows
	if maxFlows <= 0 {
		maxFlows = flow.DefaultMaxFlows
	}

	detectors := rules.Default()
	store := findings.NewStore()

	info := CaptureInfo{
		Path:             path,
		Format:           string(r.Format()),
		LinkType:         r.LinkType().String(),
		UndecodedReasons: make(map[string]uint64),
		FlowCap:          maxFlows,
	}
	info.Snaplen, info.SnaplenKnown = r.Snaplen()

	// Per-flow counters are accumulated at flow close, because the flow state
	// itself is evictable and will not all be present at the end of the run.
	var (
		completeFlows  int
		partialFlows   int
		midstreamFlows int
		oneWayFlows    int
	)

	flows := flow.NewStore(maxFlows, len(detectors), func(st *flow.State) {
		switch st.Completeness() {
		case flow.Complete:
			completeFlows++
		case flow.Partial:
			partialFlows++
		default:
			midstreamFlows++
		}
		if st.OneWay() {
			oneWayFlows++
		}
		for i, d := range detectors {
			d.OnFlowEnd(st.Detector(i), st)
		}
	})

	hosts := make(map[netip.Addr]struct{})

	progressEvery := opts.ProgressInterval
	if progressEvery <= 0 {
		progressEvery = DefaultProgressInterval
	}
	report := func(done bool) {
		if opts.Progress == nil {
			return
		}
		opts.Progress(Progress{
			PacketsRead: info.PacketsRead,
			BytesRead:   r.BytesRead(),
			TotalBytes:  r.Size(),
			Done:        done,
		})
	}
	report(false)

	var pkt capture.Packet
	for {
		decoded, err := r.Next(&pkt)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		info.PacketsRead++
		if opts.Progress != nil && info.PacketsRead%uint64(progressEvery) == 0 {
			report(false)
		}
		// Min and max over all packets, not first-in-file and last-in-file:
		// file order is not time order. Multi-interface merges interleave
		// imperfectly, and the committed fixtures themselves are appended by
		// flow — capinfos reports them as not strictly time-ordered. Taking
		// packet 1 as the start would misreport the capture window for any
		// such file; the tshark cross-validation harness compares this span
		// against the oracle's.
		if info.FirstPacketTime.IsZero() || pkt.Time.Before(info.FirstPacketTime) {
			info.FirstPacketTime = pkt.Time
		}
		if pkt.Time.After(info.LastPacketTime) {
			info.LastPacketTime = pkt.Time
		}

		if !decoded {
			// Non-TCP traffic is decoded as far as L3 and then reported as
			// "not TCP", which is not a failure — the v1 rules are TCP only.
			if errors.Is(pkt.DecodeErr, capture.ErrNotTCP) {
				info.PacketsNonTCP++
				continue
			}
			info.PacketsUndecoded++
			if pkt.DecodeErr != nil {
				info.UndecodedReasons[pkt.DecodeErr.Error()]++
			}
			continue
		}

		info.PacketsDecoded++
		if pkt.Proto != capture.ProtoTCP {
			info.PacketsNonTCP++
			continue
		}
		info.PacketsTCP++

		key, dir := flow.MakeKey(pkt.Proto,
			flow.Endpoint{Addr: pkt.Src, Port: pkt.SrcPort},
			flow.Endpoint{Addr: pkt.Dst, Port: pkt.DstPort})

		st, created := flows.GetOrCreate(key)
		if created {
			for i, d := range detectors {
				flows.SetDetector(st, i, d.NewFlow())
			}
			hosts[key.A.Addr] = struct{}{}
			hosts[key.B.Addr] = struct{}{}
		}

		// Flow state is updated before rules see the packet, so a rule can
		// rely on server identification and RTT already reflecting this frame.
		st.Observe(&pkt, dir)
		for i, d := range detectors {
			d.OnPacket(st.Detector(i), st, &pkt, dir)
		}
		flows.Touch(st)
	}

	report(true)

	flows.CloseAll()

	fstats := flows.Stats()
	info.TCPFlows = int(fstats.Created)
	info.CompleteFlows = completeFlows
	info.PartialFlows = partialFlows
	info.MidstreamFlows = midstreamFlows
	info.OneWayFlows = oneWayFlows
	info.FlowsEvicted = fstats.Evicted
	info.PeakLiveFlows = fstats.PeakLive
	info.TCPHosts = len(hosts)

	// Drop counters live in an Interface Statistics Block, which a capture tool
	// writes when it closes the file — so they are only complete now, once the
	// read has finished.
	drops, dropAvailability := r.Drops()
	summariseDrops(&info, drops, dropAvailability)

	pop := &rules.Population{
		TCPFlows:       info.TCPFlows,
		TCPHosts:       sortedAddrs(hosts),
		MidstreamFlows: midstreamFlows,
		PartialFlows:   partialFlows,
		CompleteFlows:  completeFlows,
		CaptureStart:   info.FirstPacketTime,
		CaptureEnd:     info.LastPacketTime,
		Quality:        dropQuality(&info),
	}

	for _, d := range detectors {
		d.Emit(pop, store)
	}

	// Said on every capture, whatever the answer. "No drops recorded" and "no
	// drop counter exists" are different facts and the second must not be
	// rendered as the first.
	store.AddNote(dropNote(&info))

	if fstats.Evicted > 0 {
		store.AddNote(findings.Note{
			Kind:   "info",
			RuleID: "",
			Text:   "Some flows were evicted before the capture ended because the concurrent flow cap was reached. Those flows were analysed only up to the point of eviction. Raise --max-flows to analyse them in full.",
		})
	}

	// The run is over: the population is complete, so findings can be ranked and
	// read. Everything above this line writes to the store; nothing reads it.
	store.Seal()

	return &Result{
		Capture:  info,
		Findings: store.Findings(),
		Notes:    store.Notes(),
		Checks:   rules.AllMeta(),
		Quality:  pop.Quality,
	}, nil
}

// sortedAddrs returns the host set in ascending order. Anything built from a
// map is sorted before it leaves this package.
func sortedAddrs(m map[netip.Addr]struct{}) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}
