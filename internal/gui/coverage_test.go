package gui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// The coverage builder itself — wording, gap collection, the no-TCP and
// evicted-flow cases — is tested in internal/report, where it now lives. The
// tests here are about the binding layer: that the document the frontend
// receives carries the coverage, and that what it carries survived the trip.

// TestCleanCaptureState drives a capture with nothing wrong with it all the way
// to the screen the user lands on, at the binding layer the frontend calls.
//
// This is the screen most likely to be believed about something it never
// checked, so the assertions are about what it discloses as much as what it
// reports.
func TestCleanCaptureState(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("clean-capture", "pcap"))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Report.Findings) != 0 {
		for _, f := range res.Report.Findings {
			t.Logf("unexpected finding: %s", f.Title)
		}
		t.Fatalf("the clean fixture produced %d findings; it is meant to be quiet", len(res.Report.Findings))
	}

	// Coverage rides inside the report document — the same one the exports
	// carry — so the screen and an export of the same run cannot disagree.
	cov := res.Report.Coverage
	if !cov.Clean {
		t.Error("a run with no findings was not marked clean")
	}

	// The statement must be calibrated, not congratulatory, and must not make a
	// claim about the network the tool has no basis for.
	if cov.Statement != "No significant problems found in what was checked" {
		t.Errorf("statement = %q", cov.Statement)
	}
	assertNoVerdict(t, cov.Statement)
	assertNoVerdict(t, cov.Qualifier)
	if cov.Qualifier == "" {
		t.Error("the statement carries no qualifier, so it reads as a verdict")
	}
	if !strings.Contains(cov.Qualifier, "not the same as") {
		t.Errorf("the qualifier does not distinguish this from a clean bill of health: %q", cov.Qualifier)
	}

	// What ran comes from the document's checks list, taken from the registry,
	// so the screen cannot claim a check the engine does not perform.
	if len(res.Report.Checks) != len(checkInfos()) || len(res.Report.Checks) == 0 {
		t.Fatalf("document lists %d checks, registry has %d", len(res.Report.Checks), len(checkInfos()))
	}
	for _, c := range res.Report.Checks {
		if c.ID == "" || c.Name == "" || c.Summary == "" {
			t.Errorf("check %+v is missing text the screen renders", c)
		}
	}
	if cov.UnbuiltChecks != 13 {
		t.Errorf("UnbuiltChecks = %d, want 13", cov.UnbuiltChecks)
	}

	// The part that earns the screen its place.
	if len(cov.NotChecked) == 0 {
		t.Fatal("nothing was listed as unchecked; on classic pcap the capture-host drop count cannot be known")
	}
	var sawDrops bool
	for _, g := range cov.NotChecked {
		if strings.Contains(g.Text, "dropped packets before writing them") {
			sawDrops = true
		}
		if strings.TrimSpace(g.Text) == "" {
			t.Error("a gap was listed with no explanation")
		}
	}
	if !sawDrops {
		t.Error("the capture-host drop gap is missing from a classic pcap run")
	}

	// No display floor exists yet, so nothing may be quietly held back.
	if cov.MinorObservations != 0 {
		t.Errorf("MinorObservations = %d; no display floor exists, so nothing should be hidden", cov.MinorObservations)
	}
}

// TestCleanStateListsMidstreamAndOneWayGaps checks the gaps that come from the
// per-flow completeness counters rather than from a rule's own note.
//
// The clean fixture has neither, by design — so this uses a fixture that does,
// or the code path would never be exercised.
func TestCleanStateListsMidstreamAndOneWayGaps(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("r01-brief-zero-windows", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Capture.FlowsMidstream == 0 {
		t.Skip("fixture no longer contains a midstream flow")
	}

	var sawMidstream bool
	for _, g := range res.Report.Coverage.NotChecked {
		if strings.Contains(g.Text, "began before the capture started") {
			sawMidstream = true
			// It must also say what is *not* affected, or the reader
			// over-discounts the findings that are still sound.
			if !strings.Contains(g.Text, "Zero-window detection") {
				t.Errorf("the midstream gap does not say what remains unaffected: %q", g.Text)
			}
		}
	}
	if !sawMidstream {
		t.Error("a capture with midstream flows did not list receive window sizing as unassessed")
	}
}

// TestEmptyCaptureIsAnErrorNotACleanResult is the edge case that matters most:
// an absence of data must never be presented as an absence of problems.
func TestEmptyCaptureIsAnErrorNotACleanResult(t *testing.T) {
	// A structurally valid pcap containing no packets at all.
	empty, err := synth.New().Pcap()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "empty.pcap")
	if err := os.WriteFile(path, empty, 0o644); err != nil {
		t.Fatal(err)
	}

	app := New("test")
	res, err := app.Analyze(path)
	if err == nil {
		t.Fatalf("an empty capture produced a result with %d findings instead of an error",
			len(res.Report.Findings))
	}
	if !strings.Contains(err.Error(), "no packets") {
		t.Errorf("the error does not say the capture is empty: %v", err)
	}
	// And it must suggest what to do, not merely refuse.
	if !strings.Contains(err.Error(), "capture") {
		t.Errorf("the error gives the user nothing to act on: %v", err)
	}
}

// TestUnparseableCaptureIsAnErrorNotACleanResult is the other half of the same
// edge case.
func TestUnparseableCaptureIsAnErrorNotACleanResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("this is not a capture"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := New("test")
	if _, err := New("test").Analyze(path); err == nil {
		t.Fatal("an unparseable file did not produce an error")
	}
	if app.OpenAnalysisCount() != 0 {
		t.Error("a failed analysis was added to the open list")
	}
}

// assertNoVerdict holds the clean-state wording to the same posture as the
// findings: it may say what was examined, never what it means.
//
// The ban list is the report package's — the same one its export-rendering
// tests use — so the in-app wording and the exported wording are held to one
// list rather than two copies that could drift.
func assertNoVerdict(t *testing.T, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, banned := range report.VerdictBans {
		if strings.Contains(lower, banned) {
			t.Errorf("wording contains a verdict %q:\n%s", banned, text)
		}
	}
}
