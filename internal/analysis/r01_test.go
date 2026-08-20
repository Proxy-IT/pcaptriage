package analysis_test

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// allFixtures is synth.Fixtures() with the emptiness check the tests that walk
// it were each missing.
//
// A test whose only assertions are inside `for _, f := range synth.Fixtures()`
// passes unchanged if that list is ever empty, which is indistinguishable from
// passing on a correct one — the defect class
// TestNoTestAssertsOnlyInsideAnUncheckedLoop exists to catch. One helper puts
// the check in a single place rather than repeating a length assertion in each
// caller.
func allFixtures(t *testing.T) []synth.Fixture {
	t.Helper()
	all := synth.Fixtures()
	if len(all) == 0 {
		t.Fatal("no fixtures registered, so a walk over them would assert nothing")
	}
	return all
}

// runFixture analyses a committed fixture.
func runFixture(t *testing.T, name string) *analysis.Result {
	t.Helper()
	res, err := analysis.Run(synth.FixturePath(name, "pcap"), analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", name, err)
	}
	return res
}

// findingsFor returns every finding produced by a rule.
func findingsFor(res *analysis.Result, ruleID string) []*findings.Finding {
	var out []*findings.Finding
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// TestR01Positive checks the zero-window fixture against the wording and the
// figures specified in RULES.md.
func TestR01Positive(t *testing.T) {
	res := runFixture(t, "r01-zero-window-stall")

	got := findingsFor(res, "R01")
	if len(got) != 1 {
		t.Fatalf("want exactly one R01 finding, got %d", len(got))
	}
	f := got[0]

	if want := "Receiver stopped accepting data — 10.2.2.7:5432"; f.Title != want {
		t.Errorf("title:\n got %q\nwant %q", f.Title, want)
	}

	// The fixture is built to reproduce RULES.md's example figures exactly:
	// six advertisements, 4.2s cumulative, 2.9s longest, twelve clean peers.
	wantObs := "Advertised a zero receive window 6 times, stalling the sender for 4.2s total " +
		"(longest single stall 2.9s). The other 12 hosts in this capture show no zero window events."
	if f.Observation != wantObs {
		t.Errorf("observation:\n got %q\nwant %q", f.Observation, wantObs)
	}

	wantNext := "the receiving application on 10.2.2.7 — a zero window means the application is not " +
		"reading from its socket buffer fast enough. Look at CPU, blocked threads, or a downstream " +
		"dependency on that host."
	if f.CheckNext != wantNext {
		t.Errorf("check next:\n got %q\nwant %q", f.CheckNext, wantNext)
	}

	// R01 does not degrade: zero multiplied by any window scale factor is
	// still zero, so it holds on midstream captures too.
	if f.Quality != findings.Confirmed {
		t.Errorf("quality = %q, want %q", f.Quality, findings.Confirmed)
	}

	if f.TotalCount != 6 {
		t.Errorf("total count = %d, want 6", f.TotalCount)
	}
	if got, want := f.Metrics["cumulative_stall_ms"], int64(4200); got != want {
		t.Errorf("cumulative_stall_ms = %v, want %v", got, want)
	}
	if got, want := f.Metrics["max_stall_ms"], int64(2900); got != want {
		t.Errorf("max_stall_ms = %v, want %v", got, want)
	}
	if got, want := f.Metrics["stall_episodes"], uint64(2); got != want {
		t.Errorf("stall_episodes = %v, want %v", got, want)
	}
	if len(f.Frames) == 0 {
		t.Error("finding cites no frames; every finding must point at frames that evidence it")
	}
	if f.WorstFrame == 0 {
		t.Error("finding records no worst occurrence")
	}

	// The report may never contain a causal claim.
	assertAdvisory(t, f)
}

// TestR01NegativeBriefStalls covers both false-positive traps under R01.
//
// Six zero-window advertisements totalling sixty milliseconds are normal
// operation, and a midstream flow whose first observed window is zero has not
// shown a receiver that stopped accepting data — it has shown a receiver that
// was already full when the capture started.
func TestR01NegativeBriefStalls(t *testing.T) {
	res := runFixture(t, "r01-brief-zero-windows")

	if got := findingsFor(res, "R01"); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected R01 finding: %s — %s", f.Title, f.Observation)
		}
		t.Fatalf("want no R01 findings on the negative fixture, got %d", len(got))
	}

	// Suppression must be visible. A check that quietly found something and
	// decided not to say so is the failure mode this note exists to prevent.
	var noted bool
	for _, n := range res.Notes {
		if n.RuleID == "R01" && strings.Contains(n.Text, "zero receive window") {
			noted = true
		}
	}
	if !noted {
		t.Error("brief zero windows were suppressed without a note saying so")
	}
}

// TestR01MidstreamZeroWindowNotCounted is the sharp edge of the second trap.
//
// In the negative fixture the midstream flow sits at a zero window for five
// seconds before ever advertising a non-zero one. If the rule counted that, it
// would report a five-second stall, which would be both the largest finding in
// the capture and entirely fictional.
func TestR01MidstreamZeroWindowNotCounted(t *testing.T) {
	res := runFixture(t, "r01-brief-zero-windows")
	for _, f := range findingsFor(res, "R01") {
		if strings.Contains(f.Title, "10.3.3.4") {
			t.Fatalf("counted a zero window advertised before any non-zero window: %s", f.Observation)
		}
	}
	if res.Capture.MidstreamFlows == 0 {
		t.Error("fixture was expected to contain a midstream flow; per-flow completeness tracking may be wrong")
	}
}

// assertAdvisory checks that a finding states what was observed rather than
// what caused it. The distinction is the whole posture of the tool, so it is
// asserted rather than left to review.
func assertAdvisory(t *testing.T, f *findings.Finding) {
	t.Helper()
	banned := []string{
		" is slow", " is broken", " is failing", " is overloaded",
		"caused by", "the cause", "root cause", "because the server",
		"you should", "must be",
	}
	text := strings.ToLower(f.Title + " " + f.Observation + " " + f.CheckNext)
	for _, b := range banned {
		if strings.Contains(text, b) {
			t.Errorf("finding %q contains verdict language %q; findings state what was observed, not what it means", f.Title, b)
		}
	}
}
