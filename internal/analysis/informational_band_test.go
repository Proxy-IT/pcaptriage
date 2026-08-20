package analysis_test

import (
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestInformationalBandIsAContiguousTail pins the property the GUI's
// informational fold is built on.
//
// The fold renders one row standing in for the informational findings. That is
// only correct if those findings are a contiguous run at the end of the ranked
// list — a scattered band would need a row per run, and one row would silently
// reorder the report by gathering findings from positions they did not occupy.
//
// It holds by construction rather than by luck: findings sort by significance
// descending, and rules.SeverityFor is a monotonic step function of
// significance, so severity can only fall as the list is read. Both halves are
// asserted, because either one changing alone would break the fold while
// leaving every other test green — a new sort key ahead of significance, or a
// severity rule that consulted anything else.
func TestInformationalBandIsAContiguousTail(t *testing.T) {
	// The monotonic half, checked directly against the mapping rather than
	// through a fixture: a higher score must never map to a weaker word.
	order := map[findings.Severity]int{
		findings.SeverityInformational: 0,
		findings.SeverityWorthNoting:   1,
		findings.SeveritySignificant:   2,
	}
	var prev = -1
	for score := 0.0; score <= 120.0; score += 0.5 {
		got, ok := order[rules.SeverityFor(score)]
		if !ok {
			t.Fatalf("SeverityFor(%.1f) returned an unknown severity", score)
		}
		if got < prev {
			t.Fatalf("SeverityFor is not monotonic: it weakens at score %.1f, so the informational "+
				"band could appear above a stronger finding and the fold would gather a scattered set",
				score)
		}
		prev = got
	}

	// The ordering half, over every fixture that produces findings at all.
	var checked int
	for _, fx := range allFixtures(t) {
		res, err := analysis.Run(synth.FixturePath(fx.Name, "pcapng"), analysis.Options{})
		if err != nil {
			t.Fatalf("analyse %s: %v", fx.Name, err)
		}
		// Through report.Build, because severity is derived there rather than
		// stored on the finding — so this checks the same list, in the same
		// order, with the same labels the GUI receives and folds.
		doc := report.Build(res, report.Invocation{}, "test")
		if len(doc.Findings) == 0 {
			continue
		}
		checked++

		// Once informational is seen, nothing stronger may follow.
		var seenInformational bool
		for i, f := range doc.Findings {
			if f.Severity == string(findings.SeverityInformational) {
				seenInformational = true
				continue
			}
			if seenInformational {
				t.Errorf("%s: finding %d is %s but follows an informational one — the informational "+
					"band is not a contiguous tail, and the GUI's single fold row would gather "+
					"findings from non-adjacent positions", fx.Name, i, f.Severity)
				break
			}
		}
	}
	if checked == 0 {
		t.Fatal("no fixture produced findings, so the ordering half asserted nothing")
	}
	t.Logf("checked ranked ordering across %d fixtures with findings", checked)
}
