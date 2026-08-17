package gui

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestCleanBannerIsNeutralWhenCoverageIsGappy is the neutral-not-green rule at
// the layer the frontend reads.
//
// The classic-pcap clean fixture is exactly the case the brief names: the
// capture is clean, but the format cannot report capture-host drops, so a check
// could not run. Green there would be a visual all-clear over a result the words
// deliberately decline to give.
func TestCleanBannerIsNeutralWhenCoverageIsGappy(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("clean-capture", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	cov := res.Coverage

	if !cov.Clean {
		t.Fatal("the clean fixture did not produce a clean result")
	}
	if len(cov.NotChecked) == 0 {
		t.Fatal("the classic-pcap clean fixture should have at least the drop gap")
	}
	if cov.CoverageStrong {
		t.Error("a clean capture with unrun checks was marked strong enough for green")
	}
	if cov.CoverageWeakReason == "" {
		t.Error("green was withheld without saying why")
	}
}

// TestCleanBannerIsNeutralAtTodaysBuildState checks the second, independent
// reason green is withheld: most of the rule set does not exist.
//
// Even a capture with no gaps at all must stay neutral while checks are
// unbuilt — "all clear" cannot be claimed from two checks out of fifteen.
func TestCleanBannerIsNeutralAtTodaysBuildState(t *testing.T) {
	// A clean run with every gap removed, leaving only the unbuilt-checks
	// reason in play.
	res := &analysis.Result{
		Capture: analysis.CaptureInfo{PacketsRead: 1000, TCPFlows: 10},
	}
	cov := buildCoverage(res)

	if len(cov.NotChecked) != 0 {
		t.Fatalf("constructed result unexpectedly has %d gaps", len(cov.NotChecked))
	}
	if cov.UnbuiltChecks == 0 {
		t.Skip("every planned check is now built; this test's premise is gone")
	}
	if cov.CoverageStrong {
		t.Error("green was allowed with 13 of 15 checks unbuilt")
	}
	if !strings.Contains(cov.CoverageWeakReason, "built") {
		t.Errorf("the reason does not mention the unbuilt checks: %q", cov.CoverageWeakReason)
	}
}

// TestErrorStatesNeverCarrySeverity checks the exclusion the brief calls out:
// unreadable, empty and no-TCP keep their own presentation and must not pick up
// the severity scheme.
func TestErrorStatesNeverCarrySeverity(t *testing.T) {
	// No-TCP is a result, not an error, but it is not a severity-bearing one
	// either: there are no findings to label.
	noTCP := buildCoverage(&analysis.Result{
		Capture: analysis.CaptureInfo{PacketsRead: 4096, PacketsNonTCP: 4096, TCPFlows: 0},
	})
	if noTCP.CoverageStrong {
		t.Error("a capture with nothing to examine was presented as strongly covered")
	}
	if !strings.Contains(noTCP.Statement, "No TCP traffic") {
		t.Errorf("statement = %q", noTCP.Statement)
	}

	// Empty and unparseable captures never reach a coverage view at all; they
	// error out before one is built. Asserted in coverage_test.go.
}

// TestSeverityReachesTheFrontendPayload checks the field the card renders is
// present on the result the binding hands over.
func TestSeverityReachesTheFrontendPayload(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("mixed-findings", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) == 0 {
		t.Fatal("no findings")
	}
	for i, f := range res.Report.Findings {
		if f.Severity == "" {
			t.Errorf("finding %d has no severity slug for the CSS class", i)
		}
		if f.SeverityLabel == "" {
			t.Errorf("finding %d has no severity word, so colour would carry it alone", i)
		}
	}
}
