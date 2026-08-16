package findings

import (
	"testing"
	"time"
)

var t0 = time.Date(2024, 3, 14, 9, 0, 0, 0, time.UTC)

// TestEvidenceCapsRepetition is the repetition cap from the brief: a flow that
// retransmits fifty thousand times must produce one finding with a count of
// fifty thousand, not fifty thousand findings, and must cite a bounded number
// of frames.
func TestEvidenceCapsRepetition(t *testing.T) {
	var e Evidence
	for i := 1; i <= 50000; i++ {
		e.Record(uint64(i), t0.Add(time.Duration(i)*time.Millisecond), float64(i%7))
	}

	if e.Total != 50000 {
		t.Errorf("Total = %d, want 50000", e.Total)
	}
	frames := e.Frames()
	if len(frames) > MaxFrames {
		t.Errorf("cited %d frames, cap is %d", len(frames), MaxFrames)
	}
	if e.FirstFrame() != 1 {
		t.Errorf("FirstFrame = %d, want 1", e.FirstFrame())
	}
}

// TestEvidenceFramesIncludeFirstAndWorst checks the two frames the brief
// requires be retained regardless of which representative mode is in use.
func TestEvidenceFramesIncludeFirstAndWorst(t *testing.T) {
	for _, mode := range []EvidenceMode{ModeFirst, ModeWorst} {
		e := Evidence{Mode: mode}
		for i := 1; i <= 100; i++ {
			// The worst occurrence is deliberately late, so ModeFirst would
			// not otherwise have kept it.
			v := float64(i)
			e.Record(uint64(i*10), t0, v)
		}

		frames := e.Frames()
		var sawFirst, sawWorst bool
		for _, f := range frames {
			if f == e.FirstFrame() {
				sawFirst = true
			}
			if f == e.WorstFrame() {
				sawWorst = true
			}
		}
		if !sawFirst {
			t.Errorf("mode %d: frame list omits the first occurrence %d: %v", mode, e.FirstFrame(), frames)
		}
		if !sawWorst {
			t.Errorf("mode %d: frame list omits the worst occurrence %d: %v", mode, e.WorstFrame(), frames)
		}
		if e.WorstFrame() != 1000 {
			t.Errorf("mode %d: WorstFrame = %d, want 1000", mode, e.WorstFrame())
		}
	}
}

// TestEvidenceModeWorstKeepsHighestValues checks that a rule asking for the
// most pronounced occurrences gets them, so following the cited frames lands
// on the behaviour the finding describes.
func TestEvidenceModeWorstKeepsHighestValues(t *testing.T) {
	e := Evidence{Mode: ModeWorst}
	// Values 1..20 arriving in ascending order; the top eight are 13..20.
	for i := 1; i <= 20; i++ {
		e.Record(uint64(i), t0, float64(i))
	}
	frames := e.Frames()
	if len(frames) != MaxFrames {
		t.Fatalf("got %d frames, want %d", len(frames), MaxFrames)
	}
	// Frames 13..20 are the eight largest, but the first occurrence claims a
	// slot, so frame 1 displaces the smallest of them.
	want := map[uint64]bool{1: true, 14: true, 15: true, 16: true, 17: true, 18: true, 19: true, 20: true}
	for _, f := range frames {
		if !want[f] {
			t.Errorf("unexpected frame %d in %v; want the first occurrence and the seven worst", f, frames)
		}
	}
}

// TestEvidenceFramesAreSortedAndUnique checks the property the report relies
// on: a reader types these into Wireshark in order.
func TestEvidenceFramesAreSortedAndUnique(t *testing.T) {
	for _, mode := range []EvidenceMode{ModeFirst, ModeWorst} {
		e := Evidence{Mode: mode}
		for _, f := range []uint64{50, 10, 90, 10, 30, 70, 20, 60, 40, 80} {
			e.Record(f, t0, float64(f%13))
		}
		frames := e.Frames()
		for i := 1; i < len(frames); i++ {
			if frames[i-1] >= frames[i] {
				t.Errorf("mode %d: frames not strictly ascending: %v", mode, frames)
				break
			}
		}
	}
}

// TestStoreEnforcesOneFindingPerRulePerScope is the other half of the
// repetition cap.
func TestStoreEnforcesOneFindingPerRulePerScope(t *testing.T) {
	s := NewStore()

	if !s.Add(&Finding{RuleID: "R01", ScopeKey: "flow-a"}) {
		t.Fatal("first finding was rejected")
	}
	if s.Add(&Finding{RuleID: "R01", ScopeKey: "flow-a"}) {
		t.Error("a second finding for the same rule and scope was accepted")
	}
	if !s.Add(&Finding{RuleID: "R01", ScopeKey: "flow-b"}) {
		t.Error("a finding for a different scope was rejected")
	}
	if !s.Add(&Finding{RuleID: "R04", ScopeKey: "flow-a"}) {
		t.Error("a finding from a different rule was rejected")
	}
	s.Seal()
	if got := len(s.Findings()); got != 3 {
		t.Errorf("store holds %d findings, want 3", got)
	}
}

// TestStoreIsCompletionOnly pins the observability decision documented on Store.
//
// A finding's significance is computed against capture-wide medians and its
// wording quotes the population, so neither is knowable until the read has
// finished. Reading early is a programming error and is made to fail loudly
// rather than return an ordering that will change.
func TestStoreIsCompletionOnly(t *testing.T) {
	s := NewStore()
	s.Add(&Finding{RuleID: "R01", ScopeKey: "flow-a"})

	if s.Sealed() {
		t.Error("a new store reports itself sealed")
	}

	assertPanics(t, "Findings before Seal", func() { s.Findings() })
	assertPanics(t, "Notes before Seal", func() { s.Notes() })

	s.Seal()
	if !s.Sealed() {
		t.Error("Seal did not take effect")
	}
	if got := len(s.Findings()); got != 1 {
		t.Errorf("after Seal, Findings returned %d, want 1", got)
	}

	// The complement: the run is over, so nothing may be added to it.
	assertPanics(t, "Add after Seal", func() { s.Add(&Finding{RuleID: "R04", ScopeKey: "x"}) })
}

func assertPanics(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", what)
		}
	}()
	fn()
}

// TestFindingsOrderIsStable checks that equally significant findings come out
// in the same order every time, which is what makes the report byte-identical
// across runs.
func TestFindingsOrderIsStable(t *testing.T) {
	build := func() []*Finding {
		s := NewStore()
		s.Add(&Finding{RuleID: "R04", ScopeKey: "b", Significance: 10})
		s.Add(&Finding{RuleID: "R01", ScopeKey: "z", Significance: 10})
		s.Add(&Finding{RuleID: "R01", ScopeKey: "a", Significance: 10})
		s.Add(&Finding{RuleID: "R01", ScopeKey: "m", Significance: 99})
		s.Seal()
		return s.Findings()
	}

	first := build()
	for i := 0; i < 20; i++ {
		again := build()
		for j := range first {
			if first[j].RuleID != again[j].RuleID || first[j].ScopeKey != again[j].ScopeKey {
				t.Fatalf("ordering changed between runs at position %d", j)
			}
		}
	}

	// Highest significance first, then rule id, then scope.
	want := []string{"R01/m", "R01/a", "R01/z", "R04/b"}
	for i, f := range first {
		if got := f.RuleID + "/" + f.ScopeKey; got != want[i] {
			t.Errorf("position %d = %s, want %s", i, got, want[i])
		}
	}
}
