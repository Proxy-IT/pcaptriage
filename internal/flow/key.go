// Package flow holds the packet-path tier of the two-tier memory model: the
// per-flow TCP state machine and the LRU-bounded store that holds it.
//
// Everything in this package is evictable. Anything that has to survive to the
// end of the run belongs in the findings store instead, not here — see
// BRIEF.md section 5.
package flow

import (
	"net/netip"
	"strconv"
)

// Endpoint is one side of a flow.
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

// Compare orders endpoints by address then port. It exists so flow keys have a
// canonical form and so anything built from a flow map can be sorted before
// being emitted.
func (e Endpoint) Compare(o Endpoint) int {
	if c := e.Addr.Compare(o.Addr); c != 0 {
		return c
	}
	switch {
	case e.Port < o.Port:
		return -1
	case e.Port > o.Port:
		return 1
	}
	return 0
}

// String renders the endpoint as host:port, bracketing IPv6 addresses.
func (e Endpoint) String() string {
	if !e.Addr.IsValid() {
		return "?:" + strconv.Itoa(int(e.Port))
	}
	return netip.AddrPortFrom(e.Addr, e.Port).String()
}

// Direction identifies which way a packet travelled within a flow.
//
// The flow key stores its two endpoints in a canonical order, so direction is
// simply which of them sent the packet.
type Direction uint8

const (
	// DirAToB is traffic from Key.A to Key.B.
	DirAToB Direction = 0
	// DirBToA is traffic from Key.B to Key.A.
	DirBToA Direction = 1
)

// Other returns the opposite direction.
func (d Direction) Other() Direction { return d ^ 1 }

// Key identifies a flow by its 5-tuple, with the endpoints in canonical order
// so both directions of a conversation map to the same key.
type Key struct {
	Proto uint8
	A     Endpoint
	B     Endpoint
}

// MakeKey builds the canonical key for a packet and reports which direction
// that packet travelled.
func MakeKey(proto uint8, src, dst Endpoint) (Key, Direction) {
	src.Addr = src.Addr.Unmap()
	dst.Addr = dst.Addr.Unmap()
	if src.Compare(dst) <= 0 {
		return Key{Proto: proto, A: src, B: dst}, DirAToB
	}
	return Key{Proto: proto, A: dst, B: src}, DirBToA
}

// Endpoint returns the endpoint that sends in direction d.
func (k Key) Endpoint(d Direction) Endpoint {
	if d == DirAToB {
		return k.A
	}
	return k.B
}

// Compare orders keys deterministically. Every emit path that walks a flow map
// sorts with this first.
func (k Key) Compare(o Key) int {
	switch {
	case k.Proto < o.Proto:
		return -1
	case k.Proto > o.Proto:
		return 1
	}
	if c := k.A.Compare(o.A); c != 0 {
		return c
	}
	return k.B.Compare(o.B)
}

// String renders the key as "A <-> B".
func (k Key) String() string { return k.A.String() + " <-> " + k.B.String() }
