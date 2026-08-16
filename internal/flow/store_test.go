package flow

import (
	"net/netip"
	"testing"
)

func ep(addr string, port uint16) Endpoint {
	return Endpoint{Addr: netip.MustParseAddr(addr), Port: port}
}

func key(a string, ap uint16, b string, bp uint16) Key {
	k, _ := MakeKey(6, ep(a, ap), ep(b, bp))
	return k
}

// TestMakeKeyIsCanonical checks that both directions of a conversation map to
// the same flow. Getting this wrong splits every connection in two and makes
// every flow look one-way.
func TestMakeKeyIsCanonical(t *testing.T) {
	client, server := ep("10.1.1.5", 44210), ep("10.2.2.7", 443)

	fwd, fdir := MakeKey(6, client, server)
	rev, rdir := MakeKey(6, server, client)

	if fwd != rev {
		t.Fatalf("directions produced different keys:\n %v\n %v", fwd, rev)
	}
	if fdir == rdir {
		t.Fatal("both directions reported the same Direction")
	}
	if fwd.Endpoint(fdir) != client {
		t.Errorf("Endpoint(%v) = %v, want the client", fdir, fwd.Endpoint(fdir))
	}
	if fwd.Endpoint(rdir) != server {
		t.Errorf("Endpoint(%v) = %v, want the server", rdir, fwd.Endpoint(rdir))
	}
}

// TestKeyOrderingIsTotal checks the comparison used to sort flows before
// anything derived from the flow map is emitted.
func TestKeyOrderingIsTotal(t *testing.T) {
	keys := []Key{
		key("10.1.1.5", 1, "10.2.2.7", 443),
		key("10.1.1.5", 2, "10.2.2.7", 443),
		key("10.1.1.4", 1, "10.2.2.7", 443),
		key("10.1.1.5", 1, "10.2.2.8", 443),
	}
	for i, a := range keys {
		for j, b := range keys {
			c := a.Compare(b)
			if i == j && c != 0 {
				t.Errorf("key compared unequal to itself: %v", a)
			}
			if got := b.Compare(a); got != -c {
				t.Errorf("Compare is not antisymmetric for %v and %v: %d vs %d", a, b, c, got)
			}
		}
	}
}

// TestLRUEvictsOldestAndRunsCloseHook is the memory bound doing its job. The
// close hook is the only chance a rule gets to move anything out of the
// evictable tier, so it has to run for every flow exactly once.
func TestLRUEvictsOldestAndRunsCloseHook(t *testing.T) {
	var closed []Key
	s := NewStore(2, 0, func(st *State) { closed = append(closed, st.Key) })

	k1 := key("10.0.0.1", 1, "10.0.0.9", 80)
	k2 := key("10.0.0.2", 1, "10.0.0.9", 80)
	k3 := key("10.0.0.3", 1, "10.0.0.9", 80)

	s.GetOrCreate(k1)
	s.GetOrCreate(k2)
	s.GetOrCreate(k1) // k1 is now the most recently used, so k2 evicts first
	s.GetOrCreate(k3)

	if len(closed) != 1 || closed[0] != k2 {
		t.Fatalf("evicted %v, want just %v", closed, k2)
	}
	if got := s.Stats().Evicted; got != 1 {
		t.Errorf("Evicted = %d, want 1", got)
	}

	s.CloseAll()
	if len(closed) != 3 {
		t.Fatalf("close hook ran %d times in total, want 3 (one per flow)", len(closed))
	}
}

// TestCloseAllVisitsInSortedOrder is the determinism guard on the packet-path
// tier.
//
// Rules aggregate across flows in the close hook. If CloseAll walked the flow
// map directly, that aggregation would happen in Go's randomised map order and
// anything order-sensitive inside a rule would vary between runs on the same
// file.
func TestCloseAllVisitsInSortedOrder(t *testing.T) {
	// Repeat, because a single pass could agree with sorted order by chance.
	for attempt := 0; attempt < 20; attempt++ {
		var closed []Key
		s := NewStore(1000, 0, func(st *State) { closed = append(closed, st.Key) })

		for i := 0; i < 50; i++ {
			s.GetOrCreate(key("10.0.0.1", uint16(1000+i), "10.0.0.9", 80))
		}
		s.CloseAll()

		if len(closed) != 50 {
			t.Fatalf("closed %d flows, want 50", len(closed))
		}
		for i := 1; i < len(closed); i++ {
			if closed[i-1].Compare(closed[i]) >= 0 {
				t.Fatalf("attempt %d: flows closed out of order at index %d:\n %v\n %v",
					attempt, i, closed[i-1], closed[i])
			}
		}
	}
}

// TestClosedFlowsEvictFirst checks that a reset or fully torn-down connection
// gives up its slot before a live one does.
func TestClosedFlowsEvictFirst(t *testing.T) {
	var closed []Key
	s := NewStore(2, 0, func(st *State) { closed = append(closed, st.Key) })

	k1 := key("10.0.0.1", 1, "10.0.0.9", 80)
	k2 := key("10.0.0.2", 1, "10.0.0.9", 80)
	k3 := key("10.0.0.3", 1, "10.0.0.9", 80)

	st1, _ := s.GetOrCreate(k1)
	s.GetOrCreate(k2)

	// k1 is the most recently used, but it has been reset.
	st1.SawRST = true
	s.Touch(st1)

	s.GetOrCreate(k3)

	if len(closed) != 1 || closed[0] != k1 {
		t.Fatalf("evicted %v, want the closed flow %v", closed, k1)
	}
}

// TestStoreNeverExceedsCap is the flat-memory promise: the store must stay
// bounded no matter how many distinct flows the capture contains.
func TestStoreNeverExceedsCap(t *testing.T) {
	const cap = 8
	s := NewStore(cap, 0, nil)
	for i := 0; i < 500; i++ {
		s.GetOrCreate(key("10.0.0.1", uint16(i), "10.0.0.9", 80))
		if got := len(s.byKey); got > cap {
			t.Fatalf("store holds %d flows, cap is %d", got, cap)
		}
	}
	if got := s.Stats().PeakLive; got > cap {
		t.Errorf("PeakLive = %d, cap is %d", got, cap)
	}
	if got := s.Stats().Created; got != 500 {
		t.Errorf("Created = %d, want 500", got)
	}
}
