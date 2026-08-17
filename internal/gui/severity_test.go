package gui

import (
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// The coverage-strength rules themselves — neutral at today's build state,
// neutral for error states, green never reachable while checks are unbuilt —
// are tested in internal/report beside the builder. What is tested here is
// that the signals survive the trip to the frontend payload.

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
	cov := res.Report.Coverage

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
