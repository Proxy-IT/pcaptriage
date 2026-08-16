package gui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

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

	cov := res.Coverage
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

	// What was checked comes from the registry, so it cannot claim a check the
	// engine does not run.
	if len(cov.Checked) != len(checkInfos()) || len(cov.Checked) == 0 {
		t.Fatalf("Checked has %d entries, registry has %d", len(cov.Checked), len(checkInfos()))
	}
	for _, c := range cov.Checked {
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
	for _, g := range res.Coverage.NotChecked {
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

// TestCaptureWithNoTCPIsNotReportedAsClean checks the third case: the file
// parses and holds packets, but none of them are TCP.
//
// Every check in this build looks at TCP, so "no significant problems found"
// would be the tool taking credit for work it never did.
func TestCaptureWithNoTCPIsNotReportedAsClean(t *testing.T) {
	// A run that read packets but formed no TCP flows from them — a capture
	// full of UDP, say. The file is fine and the run succeeded; there was
	// simply nothing any check in this build looks at.
	res := &analysis.Result{
		Capture: analysis.CaptureInfo{
			PacketsRead:   4096,
			PacketsNonTCP: 4096,
			TCPFlows:      0,
		},
	}

	cov := buildCoverage(res)
	if cov.Statement == "No significant problems found in what was checked" {
		t.Error("a capture with no TCP was reported as having no problems found")
	}
	if !strings.Contains(cov.Statement, "No TCP traffic") {
		t.Errorf("statement = %q", cov.Statement)
	}
	if !strings.Contains(cov.Qualifier, "anything to examine") {
		t.Errorf("the qualifier does not say the checks had nothing to look at: %q", cov.Qualifier)
	}
	// The packet count is stated, so the reader can tell this from an empty file.
	if !strings.Contains(cov.Qualifier, "4,096") {
		t.Errorf("the qualifier does not say how much was in the file: %q", cov.Qualifier)
	}
	assertNoVerdict(t, cov.Statement)
	assertNoVerdict(t, cov.Qualifier)
}

// TestEvictedFlowsAreDisclosed checks the gap that arises from the tool's own
// limits rather than the capture's: flows set aside because too many were open
// at once were only analysed up to that point.
func TestEvictedFlowsAreDisclosed(t *testing.T) {
	res := &analysis.Result{
		Capture: analysis.CaptureInfo{
			PacketsRead:  10000,
			TCPFlows:     500,
			FlowsEvicted: 120,
		},
	}

	var found bool
	for _, g := range buildCoverage(res).NotChecked {
		if strings.Contains(g.Text, "set aside before the capture ended") {
			found = true
			if !strings.Contains(g.Text, "120") {
				t.Errorf("the gap does not say how many: %q", g.Text)
			}
		}
	}
	if !found {
		t.Error("flows dropped for want of tracking capacity were not disclosed")
	}
}

// assertNoVerdict holds the clean-state wording to the same posture as the
// findings: it may say what was examined, never what it means.
func assertNoVerdict(t *testing.T, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, banned := range []string{
		"healthy", "all clear", "all-clear", "everything is fine", "no problems with",
		"your network", "is working correctly", "nothing is wrong",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("wording contains a verdict %q:\n%s", banned, text)
		}
	}
}
