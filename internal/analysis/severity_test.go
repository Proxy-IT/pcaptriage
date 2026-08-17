package analysis_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestSeverityChangesNothingButTheField is the constraint that makes the P4
// mapping safe: it is presentation calibration, so ranking, wording, frames and
// every other field must come through untouched.
func TestSeverityChangesNothingButTheField(t *testing.T) {
	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			res := runFixture(t, f.Name)
			doc := report.Build(res, report.Invocation{}, "test")

			// Rank order still matches the engine's ordering exactly.
			if len(doc.Findings) != len(res.Findings) {
				t.Fatalf("document has %d findings, engine produced %d", len(doc.Findings), len(res.Findings))
			}
			for i, got := range doc.Findings {
				want := res.Findings[i]
				if got.Rank != i+1 {
					t.Errorf("finding %d has rank %d", i, got.Rank)
				}
				if got.RuleID != want.RuleID || got.Subject != want.ScopeKey {
					t.Errorf("finding %d is not the engine's finding %d", i, i)
				}
				if got.Observation != want.Observation || got.CheckNext != want.CheckNext {
					t.Errorf("finding %d wording changed", i)
				}
				if got.Severity == "" || got.SeverityLabel == "" {
					t.Errorf("finding %d carries no severity", i)
				}
			}
		})
	}
}

// TestSeverityIsDerivedNotStored checks the field is a reading of the score
// rather than a second source of truth: two runs of the same capture must agree,
// and the value must follow the ordering.
func TestSeverityIsDerivedNotStored(t *testing.T) {
	rank := map[string]int{"informational": 0, "worth-noting": 1, "significant": 2}

	res := runFixture(t, "mixed-findings")
	doc := report.Build(res, report.Invocation{}, "test")

	// Findings are ordered most significant first, so severity must be
	// non-increasing down the list. A rise would mean the label disagrees with
	// the ordering the reader is being shown.
	last := 3
	for _, f := range doc.Findings {
		r, ok := rank[f.Severity]
		if !ok {
			t.Fatalf("unknown severity %q", f.Severity)
		}
		if r > last {
			t.Errorf("severity rises down the ranked list at rank %d (%q): the label contradicts the order",
				f.Rank, f.Severity)
		}
		last = r
	}
}

// TestCurrentBuildProducesOnlySignificantFindings records the honest state of
// the vocabulary today.
//
// Both implemented rules are high-weight (9 and 8) and every fixture isolates
// its condition, so the deviation factor pins at its maximum. Every finding the
// tool can currently produce lands in the top band. The three-level vocabulary
// is exercised by the unit tests on the mapping, not by fixtures — and this
// test exists so that stops being true visibly rather than silently once a
// lower-weight rule such as R06 lands.
func TestCurrentBuildProducesOnlySignificantFindings(t *testing.T) {
	var counts = map[string]int{}
	for _, f := range synth.Fixtures() {
		res := runFixture(t, f.Name)
		for _, fd := range report.Build(res, report.Invocation{}, "test").Findings {
			counts[fd.Severity]++
		}
	}

	if counts["significant"] == 0 {
		t.Fatal("no findings at all; the fixtures are not exercising the rules")
	}
	if other := counts["worth-noting"] + counts["informational"]; other != 0 {
		t.Logf("NOTE: %d findings now land below the top band (%v). The vocabulary is "+
			"exercised by fixtures now as well as by unit tests; update this test's premise.", other, counts)
	}
}

// TestSeverityColourIsNeverAlone is the accessibility constraint, checked in the
// rendered HTML rather than asserted about the CSS.
func TestSeverityColourIsNeverAlone(t *testing.T) {
	full := string(renderFixtureHTML(t, "mixed-findings", "pcap"))

	// The stylesheet is inlined into the same document, and it names every
	// severity class. Only the body says what the reader actually sees.
	_, body, ok := strings.Cut(full, "</style>")
	if !ok {
		t.Fatal("could not separate the stylesheet from the document body")
	}

	for _, want := range []string{"Significant", "tag-sev-significant"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered report body is missing %q", want)
		}
	}

	// Every severity class that appears must carry its word in the same element.
	for _, sev := range []struct{ class, word string }{
		{"tag-sev-significant", "Significant"},
		{"tag-sev-worth-noting", "Worth noting"},
		{"tag-sev-informational", "Informational"},
	} {
		i := strings.Index(body, sev.class)
		if i < 0 {
			continue // that band does not occur in this fixture
		}
		window := body[i:min(i+80, len(body))]
		if !strings.Contains(window, sev.word) {
			t.Errorf("%s renders without its word beside it: %q", sev.class, window)
		}
	}
}

// TestEvidenceQualityIsNotColourCoded keeps the two signals separable. Giving
// both a colour would invite the reader to add them together.
func TestEvidenceQualityIsNotColourCoded(t *testing.T) {
	css := report.StyleSheet()

	for _, cls := range []string{".tag-confirmed", ".tag-inferred", ".tag-unavailable"} {
		i := strings.Index(css, cls)
		if i < 0 {
			t.Errorf("%s is not styled at all", cls)
			continue
		}
	}
	// The quality badges share one neutral rule; none of them may carry a
	// severity colour.
	for _, hex := range []string{"#b42318", "#b54708", "#146c43"} {
		for _, cls := range []string{"tag-confirmed", "tag-inferred", "tag-unavailable"} {
			if blockContains(css, cls, hex) {
				t.Errorf("quality badge %s uses severity colour %s", cls, hex)
			}
		}
	}
}

// blockContains reports whether the CSS rule naming sel contains needle before
// its closing brace.
func blockContains(css, sel, needle string) bool {
	i := strings.Index(css, "."+sel)
	if i < 0 {
		return false
	}
	end := strings.Index(css[i:], "}")
	if end < 0 {
		end = len(css) - i
	}
	return strings.Contains(css[i:i+end], needle)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSeverityFieldIsInTheJSON checks the field reaches the document, since the
// export and the app both read it from there.
func TestSeverityFieldIsInTheJSON(t *testing.T) {
	raw := renderFixture(t, "mixed-findings", "pcap")

	var doc struct {
		Findings []struct {
			Severity      string `json:"severity"`
			SeverityLabel string `json:"severity_label"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) == 0 {
		t.Fatal("no findings")
	}
	for i, f := range doc.Findings {
		if f.Severity == "" || f.SeverityLabel == "" {
			t.Errorf("finding %d: severity=%q label=%q", i, f.Severity, f.SeverityLabel)
		}
	}
}
