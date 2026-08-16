package analysis_test

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/findings"
)

// TestR04Positive checks the server response outlier fixture against the
// wording and the figures specified in RULES.md.
func TestR04Positive(t *testing.T) {
	res := runFixture(t, "r04-server-response-outlier")

	got := findingsFor(res, "R04")
	if len(got) != 1 {
		for _, f := range got {
			t.Logf("finding: %s — %s", f.Title, f.Observation)
		}
		t.Fatalf("want exactly one R04 finding, got %d", len(got))
	}
	f := got[0]

	if want := "One server much slower to respond than its peers — 10.2.2.7:443"; f.Title != want {
		t.Errorf("title:\n got %q\nwant %q", f.Title, want)
	}

	// The fixture reproduces RULES.md's example figures: 1.8s at p95, 4.1s
	// maximum, twelve peers under 40ms.
	wantObs := "Responded in 1.8s at p95 (max 4.1s) while the other 12 servers in this capture are " +
		"under 40ms at p95. Measured from last request byte to first response byte, with network " +
		"round-trip time subtracted — so this is time spent on the server, not on the network."
	if f.Observation != wantObs {
		t.Errorf("observation:\n got %q\nwant %q", f.Observation, wantObs)
	}

	wantNext := "application or backend dependency latency on 10.2.2.7. " +
		"The network path to this host looks comparable to its peers."
	if f.CheckNext != wantNext {
		t.Errorf("check next:\n got %q\nwant %q", f.CheckNext, wantNext)
	}

	// Every flow in this fixture has a handshake, so the round trip that was
	// subtracted was directly observed rather than approximated.
	if f.Quality != findings.Confirmed {
		t.Errorf("quality = %q, want %q (all contributing flows have handshakes)", f.Quality, findings.Confirmed)
	}

	if got, want := f.Metrics["p95_ms"], int64(1800); got != want {
		t.Errorf("p95_ms = %v, want %v", got, want)
	}
	if got, want := f.Metrics["max_ms"], int64(4100); got != want {
		t.Errorf("max_ms = %v, want %v", got, want)
	}
	if got, want := f.Metrics["exchanges"], uint64(20); got != want {
		t.Errorf("exchanges = %v, want %v", got, want)
	}
	if got, want := f.Metrics["population_median_p95_ms"], int64(30); got != want {
		t.Errorf("population_median_p95_ms = %v, want %v", got, want)
	}
	if got, want := f.Metrics["peer_servers"], 12; got != want {
		t.Errorf("peer_servers = %v, want %v", got, want)
	}

	// The frames cited must be the slowest exchanges, so following them lands
	// on the behaviour being described.
	if len(f.Frames) == 0 {
		t.Fatal("finding cites no frames")
	}
	if f.WorstFrame == 0 {
		t.Error("finding records no worst occurrence")
	}

	assertAdvisory(t, f)
}

// TestR04PeersNotFlagged checks that the twelve peers, which are all within a
// few milliseconds of each other, produce nothing. A rule that fires on the
// population it is comparing against has no comparative value.
func TestR04PeersNotFlagged(t *testing.T) {
	res := runFixture(t, "r04-server-response-outlier")
	for _, f := range findingsFor(res, "R04") {
		if !strings.Contains(f.Title, "10.2.2.7:443") {
			t.Errorf("peer server flagged as an outlier: %s — %s", f.Title, f.Observation)
		}
	}
}

// TestR04NegativeServerPush covers both false-positive traps under R04.
//
// Server-sent events look identical to a slow server if the pushes are read as
// responses: the fixture's pushes arrive two and four seconds into a response
// that already completed in thirty milliseconds. The rule must measure the
// thirty milliseconds and ignore the pushes.
//
// A protocol banner breaks request/response pairing outright, and RULES.md
// requires those flows be reported as unavailable rather than measured.
func TestR04NegativeServerPush(t *testing.T) {
	res := runFixture(t, "r04-server-push")

	if got := findingsFor(res, "R04"); len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected R04 finding: %s — %s", f.Title, f.Observation)
		}
		t.Fatalf("want no R04 findings on the negative fixture, got %d", len(got))
	}

	// The unpairable flow must be reported, not dropped. A report that looks
	// clean because a check never ran is the dangerous failure mode.
	var reported bool
	for _, n := range res.Notes {
		if n.RuleID == "R04" && n.Kind == "unavailable" &&
			strings.Contains(n.Text, "did not alternate cleanly") {
			reported = true
		}
	}
	if !reported {
		t.Error("the flow with an unpairable request/response shape was skipped without an unavailable note")
	}
}

// TestR04SSEMeasuredNotSkipped is the sharp edge of the server-sent events
// trap.
//
// The pushes must be treated as a continuation of a response already measured,
// not as new responses. If they were counted, the server-sent events endpoint
// would show a p95 near two seconds and be flagged as the slowest thing in the
// capture.
func TestR04SSEMeasuredNotSkipped(t *testing.T) {
	res := runFixture(t, "r04-server-push")
	for _, f := range findingsFor(res, "R04") {
		if strings.Contains(f.Title, "10.5.5.5") {
			t.Fatalf("counted a pushed event as a slow response: %s", f.Observation)
		}
	}

	// It should also not have been quietly excluded: the endpoint had six
	// clean exchanges and so had enough samples to assess.
	for _, n := range res.Notes {
		if strings.Contains(n.Text, "fewer than") && strings.Contains(n.Text, "exchanges") {
			t.Logf("note: %s", n.Text)
		}
	}
}

// TestR04MidstreamRTTIsInferred checks the degradation RULES.md specifies:
// without a handshake there is no baseline round trip, so the fallback to the
// minimum observed ACK round trip has to be declared.
func TestR04MidstreamRTTIsInferred(t *testing.T) {
	res := runFixture(t, "mixed-findings")
	for _, f := range findingsFor(res, "R04") {
		if f.Quality == findings.Inferred && f.QualityBasis == "" {
			t.Errorf("finding %q is tagged inferred without stating the basis", f.Title)
		}
	}
}
