package flow

import (
	"sort"
)

// DefaultMaxFlows bounds the number of concurrently tracked flows.
//
// Per-flow state is on the order of a kilobyte, so this cap is what turns "no
// unbounded memory" into a number. It is a starting point, not a calibrated
// constant, and is exposed on the command line.
const DefaultMaxFlows = 16384

// CloseFunc is called exactly once per flow, before its state is discarded.
// It is the only opportunity a rule has to move anything it wants to keep out
// of the evictable packet-path tier and into the retained findings store.
type CloseFunc func(*State)

type node struct {
	state      *State
	prev, next *node
}

// Store holds live flow state, bounded by an LRU cap.
//
// This is the evictable tier. Nothing here survives to the end of the run by
// design: when a flow is evicted or the capture ends, the close hook runs and
// the state goes away.
type Store struct {
	max     int
	byKey   map[Key]*node
	head    *node // most recently used
	tail    *node // next to be evicted
	onClose CloseFunc

	// detectorSlots is how many per-rule state objects each new flow carries.
	detectorSlots int

	created uint64
	evicted uint64
	closed  uint64
	maxLive int
}

// NewStore creates a flow store holding at most max flows. onClose runs for
// every flow, whether it is evicted mid-run or closed at the end.
func NewStore(max int, detectorSlots int, onClose CloseFunc) *Store {
	if max < 1 {
		max = 1
	}
	return &Store{
		max:           max,
		byKey:         make(map[Key]*node),
		onClose:       onClose,
		detectorSlots: detectorSlots,
	}
}

// GetOrCreate returns the state for a key, creating it if absent. created
// reports whether this call brought the flow into existence, which is the
// caller's cue to initialise per-rule state.
func (s *Store) GetOrCreate(k Key) (st *State, created bool) {
	if n, ok := s.byKey[k]; ok {
		s.moveToFront(n)
		return n.state, false
	}

	if len(s.byKey) >= s.max {
		s.evictOldest()
	}

	state := &State{
		Key:         k,
		WindowScale: [2]int8{-1, -1},
	}
	if s.detectorSlots > 0 {
		state.detectors = make([]any, s.detectorSlots)
	}
	n := &node{state: state}
	s.byKey[k] = n
	s.pushFront(n)
	s.created++
	if len(s.byKey) > s.maxLive {
		s.maxLive = len(s.byKey)
	}
	return state, true
}

// SetDetector installs rule i's per-flow state on a flow.
func (s *Store) SetDetector(st *State, i int, v any) {
	if i >= 0 && i < len(st.detectors) {
		st.detectors[i] = v
	}
}

// Touch marks a flow as closed for eviction purposes. A flow that has been
// reset or has exchanged FINs in both directions is moved to the front of the
// eviction queue, so live conversations are kept in preference to finished
// ones.
//
// The state is not removed here. Removing it would let a late straggler on the
// same 5-tuple create a second flow, which would show up as connection churn
// that did not happen.
func (s *Store) Touch(st *State) {
	if !st.Closed() {
		return
	}
	if n, ok := s.byKey[st.Key]; ok {
		s.moveToBack(n)
	}
}

// CloseAll runs the close hook for every remaining flow and empties the store.
//
// Flows are closed in sorted key order. Rules aggregate across flows here, and
// aggregation must not depend on Go's randomised map iteration order.
func (s *Store) CloseAll() {
	keys := make([]Key, 0, len(s.byKey))
	for k := range s.byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Compare(keys[j]) < 0 })

	for _, k := range keys {
		n := s.byKey[k]
		if s.onClose != nil {
			s.onClose(n.state)
		}
		s.closed++
		delete(s.byKey, k)
	}
	s.head, s.tail = nil, nil
}

func (s *Store) evictOldest() {
	n := s.tail
	if n == nil {
		return
	}
	if s.onClose != nil {
		s.onClose(n.state)
	}
	s.unlink(n)
	delete(s.byKey, n.state.Key)
	s.evicted++
	s.closed++
}

// Stats reports store counters for the completeness banner.
type Stats struct {
	// Created is the number of distinct flows observed.
	Created uint64
	// Evicted is how many were discarded mid-run because the cap was reached.
	// A non-zero value means some flows were analysed only up to the point of
	// eviction.
	Evicted uint64
	// PeakLive is the highest number of concurrently tracked flows.
	PeakLive int
	// Cap is the configured LRU cap.
	Cap int
}

// Stats returns the store's counters.
func (s *Store) Stats() Stats {
	return Stats{Created: s.created, Evicted: s.evicted, PeakLive: s.maxLive, Cap: s.max}
}

// --- intrusive doubly-linked list, most-recently-used at the head ---

func (s *Store) pushFront(n *node) {
	n.prev = nil
	n.next = s.head
	if s.head != nil {
		s.head.prev = n
	}
	s.head = n
	if s.tail == nil {
		s.tail = n
	}
}

func (s *Store) unlink(n *node) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		s.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		s.tail = n.prev
	}
	n.prev, n.next = nil, nil
}

func (s *Store) moveToFront(n *node) {
	if s.head == n {
		return
	}
	s.unlink(n)
	s.pushFront(n)
}

func (s *Store) moveToBack(n *node) {
	if s.tail == n {
		return
	}
	s.unlink(n)
	n.next = nil
	n.prev = s.tail
	if s.tail != nil {
		s.tail.next = n
	}
	s.tail = n
	if s.head == nil {
		s.head = n
	}
}
