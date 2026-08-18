package flow

import (
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
)

// Completeness is the per-flow capture completeness state from BRIEF.md
// section 10. It is tracked per flow, never globally: a single capture
// routinely contains both established and newly opened connections.
type Completeness uint8

const (
	// Midstream means neither SYN nor SYN/ACK was observed. Window sizing is
	// unavailable; every other analysis proceeds.
	Midstream Completeness = iota
	// Partial means one SYN was observed. That side's shift is known, but
	// scaling activates only if both peers sent the option, so it cannot be
	// confirmed active.
	Partial
	// Complete means SYN and SYN/ACK were both observed.
	Complete
)

func (c Completeness) String() string {
	switch c {
	case Complete:
		return "complete"
	case Partial:
		return "partial"
	default:
		return "midstream"
	}
}

// Basis records how a derived property was arrived at, mirroring the evidence
// quality tags in BRIEF.md section 10.
type Basis uint8

const (
	// BasisNone means the property is not known at all.
	BasisNone Basis = iota
	// BasisObserved means it came from directly observed protocol state.
	BasisObserved
	// BasisInferred means it came from a defensible deduction.
	BasisInferred
)

// rttRingSize bounds the outstanding-segment table used for ACK RTT sampling.
// Eight is ample for a minimum-RTT estimate and keeps per-flow state small
// enough that the LRU cap translates to a predictable memory ceiling.
const rttRingSize = 8

type rttEntry struct {
	seqEnd uint32
	sent   time.Time
	// ambiguous marks a sequence range that was sent more than once, so the
	// ACK cannot be attributed to a particular transmission (Karn's algorithm).
	ambiguous bool
	valid     bool
}

type rttRing struct {
	buf [rttRingSize]rttEntry
	n   int
}

func (r *rttRing) push(seqEnd uint32, t time.Time) {
	for i := 0; i < r.n; i++ {
		if r.buf[i].valid && r.buf[i].seqEnd == seqEnd {
			r.buf[i].ambiguous = true
			return
		}
	}
	if r.n == rttRingSize {
		copy(r.buf[:], r.buf[1:])
		r.n--
	}
	r.buf[r.n] = rttEntry{seqEnd: seqEnd, sent: t, valid: true}
	r.n++
}

// resolve consumes every entry covered by ack and returns the RTT sample from
// the newest unambiguous one.
func (r *rttRing) resolve(ack uint32, now time.Time) (time.Duration, bool) {
	var (
		sample time.Duration
		found  bool
		keep   int
	)
	for i := 0; i < r.n; i++ {
		e := r.buf[i]
		if !e.valid {
			continue
		}
		if capture.SeqLE(e.seqEnd, ack) {
			if !e.ambiguous {
				sample = now.Sub(e.sent)
				found = true
			}
			continue // consumed
		}
		r.buf[keep] = e
		keep++
	}
	for i := keep; i < r.n; i++ {
		r.buf[i] = rttEntry{}
	}
	r.n = keep
	if found && sample < 0 {
		return 0, false
	}
	return sample, found
}

// State is the per-flow packet-path state. It is evictable: the LRU store may
// discard it at any point once its close hook has run.
type State struct {
	Key Key

	FirstFrame uint64
	LastFrame  uint64
	FirstSeen  time.Time
	LastSeen   time.Time

	// Packets, DataSegments and DataBytes are indexed by Direction.
	Packets      [2]uint64
	DataSegments [2]uint64
	DataBytes    [2]uint64

	// Handshake observation.
	sawSYN     [2]bool
	synTime    [2]time.Time
	sawSYNACK  bool
	synAckTime time.Time
	synAckDir  Direction

	// WindowScale is the shift advertised by each side, or -1 when that side's
	// SYN was not seen. Retained for completeness reporting; the v1 rules do
	// not size windows in absolute bytes.
	WindowScale [2]int8

	// ServerDir is the direction in which the server sends. ServerBasis says
	// whether that came from the handshake or from which side spoke first.
	ServerDir   Direction
	ServerBasis Basis

	// HandshakeRTT is SYN to SYN/ACK, available only on complete flows.
	HandshakeRTT      time.Duration
	HandshakeRTTValid bool

	// MinACKRTT is the smallest observed data-to-ACK round trip, used as the
	// midstream fallback for network RTT.
	MinACKRTT      time.Duration
	MinACKRTTValid bool
	rtt            [2]rttRing

	SawRST   bool
	RSTTime  time.Time
	RSTFrame uint64

	// FIN observation, used only to move closed flows to the front of the
	// eviction queue.
	sawFIN [2]bool

	// detectors holds one opaque state object per registered rule, indexed by
	// the rule's position in the detector list. Rules own the contents; the
	// flow store only knows to hand them back on close.
	detectors []any
}

// Completeness reports the capture completeness state of the flow.
func (s *State) Completeness() Completeness {
	sawAnySYN := s.sawSYN[DirAToB] || s.sawSYN[DirBToA]
	switch {
	case sawAnySYN && s.sawSYNACK:
		return Complete
	case sawAnySYN || s.sawSYNACK:
		return Partial
	default:
		return Midstream
	}
}

// OneWay reports that traffic was observed in one direction only, which makes
// direction-comparing analysis impossible for this flow.
func (s *State) OneWay() bool {
	return s.Packets[DirAToB] == 0 || s.Packets[DirBToA] == 0
}

// HasPayload reports whether either side ever carried application data, which
// is the simplest evidence a connection was actually established. A rule about
// connections that never opened uses it to exclude ones that plainly did.
func (s *State) HasPayload() bool {
	return s.DataSegments[DirAToB] > 0 || s.DataSegments[DirBToA] > 0
}

// Closed reports that a FIN was seen in both directions or a RST in either.
func (s *State) Closed() bool {
	return s.SawRST || (s.sawFIN[DirAToB] && s.sawFIN[DirBToA])
}

// ServerEndpoint returns the endpoint acting as the server, and whether that
// is known at all.
func (s *State) ServerEndpoint() (Endpoint, bool) {
	if s.ServerBasis == BasisNone {
		return Endpoint{}, false
	}
	return s.Key.Endpoint(s.ServerDir), true
}

// ClientEndpoint returns the endpoint acting as the client.
func (s *State) ClientEndpoint() (Endpoint, bool) {
	if s.ServerBasis == BasisNone {
		return Endpoint{}, false
	}
	return s.Key.Endpoint(s.ServerDir.Other()), true
}

// NetworkRTT returns the flow's best network round-trip estimate and how it
// was derived.
//
// A complete flow uses the handshake, which is directly observed. A midstream
// flow falls back to the minimum observed ACK round trip, which can only
// overestimate, and is reported as inferred so rules can degrade accordingly.
func (s *State) NetworkRTT() (time.Duration, Basis) {
	if s.HandshakeRTTValid {
		return s.HandshakeRTT, BasisObserved
	}
	if s.MinACKRTTValid {
		return s.MinACKRTT, BasisInferred
	}
	return 0, BasisNone
}

// Detector returns the per-flow state belonging to rule index i.
func (s *State) Detector(i int) any {
	if i < 0 || i >= len(s.detectors) {
		return nil
	}
	return s.detectors[i]
}

// Observe folds one packet into the flow state. It runs before any rule sees
// the packet, so rules can rely on server identification and RTT already
// reflecting the current frame.
func (s *State) Observe(p *capture.Packet, dir Direction) {
	if s.Packets[DirAToB]+s.Packets[DirBToA] == 0 {
		s.FirstFrame = p.Frame
		s.FirstSeen = p.Time
	}
	s.LastFrame = p.Frame
	s.LastSeen = p.Time
	s.Packets[dir]++
	if p.PayloadLength > 0 {
		s.DataSegments[dir]++
		s.DataBytes[dir] += uint64(p.PayloadLength)
	}

	syn := p.AnyFlag(capture.FlagSYN)
	ack := p.AnyFlag(capture.FlagACK)

	switch {
	case syn && !ack:
		if !s.sawSYN[dir] {
			s.sawSYN[dir] = true
			s.synTime[dir] = p.Time
		}
		if p.OptWindowScale >= 0 {
			s.WindowScale[dir] = p.OptWindowScale
		}
		// The side that sends a bare SYN is the client, so the server sends
		// the other way.
		s.setServer(dir.Other(), BasisObserved)

	case syn && ack:
		if !s.sawSYNACK {
			s.sawSYNACK = true
			s.synAckTime = p.Time
			s.synAckDir = dir
		}
		if !s.sawSYN[dir] {
			s.sawSYN[dir] = true
			s.synTime[dir] = p.Time
		}
		if p.OptWindowScale >= 0 {
			s.WindowScale[dir] = p.OptWindowScale
		}
		// The side that answers with SYN/ACK is the server.
		s.setServer(dir, BasisObserved)
		if s.sawSYN[dir.Other()] && !s.HandshakeRTTValid {
			if d := p.Time.Sub(s.synTime[dir.Other()]); d >= 0 {
				s.HandshakeRTT = d
				s.HandshakeRTTValid = true
			}
		}
	}

	if p.AnyFlag(capture.FlagFIN) {
		s.sawFIN[dir] = true
	}
	if p.AnyFlag(capture.FlagRST) && !s.SawRST {
		s.SawRST = true
		s.RSTTime = p.Time
		s.RSTFrame = p.Frame
	}

	// Server identification for midstream flows: whichever side sends data
	// first is taken to be the client. This is a deduction, not an
	// observation, and is tagged as such.
	if s.ServerBasis == BasisNone && p.PayloadLength > 0 {
		s.setServer(dir.Other(), BasisInferred)
	}

	// ACK RTT sampling. A segment that occupies sequence space is recorded,
	// and the reverse direction's acknowledgement of it yields a sample.
	if p.ConsumesSeq() {
		s.rtt[dir].push(p.SeqEnd(), p.Time)
	}
	if ack {
		if sample, ok := s.rtt[dir.Other()].resolve(p.Ack, p.Time); ok {
			if !s.MinACKRTTValid || sample < s.MinACKRTT {
				s.MinACKRTT = sample
				s.MinACKRTTValid = true
			}
		}
	}
}

// setServer records the server side. An observed determination always wins
// over an inferred one, and neither is revised once made.
func (s *State) setServer(d Direction, b Basis) {
	if s.ServerBasis == BasisObserved {
		return
	}
	if s.ServerBasis == BasisInferred && b != BasisObserved {
		return
	}
	s.ServerDir = d
	s.ServerBasis = b
}
