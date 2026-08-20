package report

import (
	"regexp"
	"strings"
	"testing"
)

// cards returns just the finding articles, with the inlined stylesheet and the
// masthead excluded.
//
// Necessary, not fastidious: the report inlines its whole stylesheet, so a
// document containing ".basis-inferred { ... }" as a CSS rule matches a naive
// strings.Contains for the class whether or not any card uses it. The first
// version of the confirmed-case test below passed on exactly that, which would
// have made it assert nothing.
func cards(t *testing.T, html string) string {
	t.Helper()
	found := regexp.MustCompile(`(?s)<article class="finding.*?</article>`).FindAllString(html, -1)
	if len(found) == 0 {
		t.Fatal("the report rendered no finding cards")
	}
	return strings.Join(found, "\n")
}

// inferredResponseFinding is responseFinding as it already stands — inferred,
// with a basis — named here so the confirmed case below reads as the
// deliberate variation it is rather than as an unexplained edit.
func inferredResponseFinding() Finding {
	return responseFinding(1, "10.0.0.1:443", 1800, 2600, 40)
}

// TestExportLabelsTheInferredBasis is the export half of the session's Part 3.
//
// The basis used to render as a bare paragraph after "check next", where it
// read as a general caveat rather than as the reason the badge says
// "inferred". In the app a reader can now click the badge through to the
// concept page; an export reader cannot, so this label is the only account of
// the downgrade the document carries. That makes it worth asserting rather
// than reviewing.
func TestExportLabelsTheInferredBasis(t *testing.T) {
	html := cards(t, render(t, sampleDoc(inferredResponseFinding())))

	if !strings.Contains(html, "Marked inferred because:") {
		t.Fatal("an inferred finding renders no label tying its basis to the badge")
	}
	if !strings.Contains(html, "basis-inferred") {
		t.Error("the basis block carries no basis-inferred class, so it has no visual tie to the badge")
	}

	// The wording itself is the rule's and must survive untouched — this
	// session is presentation, and a label that quietly reworded the sentence
	// it introduces would be a rule-wording change made in the wrong place.
	if !strings.Contains(html, "RTT taken from minimum observed ACK round trip.") {
		t.Error("the rule's own basis sentence is not present verbatim")
	}

	// Placement: bound to the badge, above the observation, not stranded after
	// "check next" where it started.
	basisAt := strings.Index(html, "Marked inferred because:")
	obsAt := strings.Index(html, `class="observation"`)
	nextAt := strings.Index(html, "Check next:")
	if obsAt < 0 || nextAt < 0 {
		t.Fatal("the finding card did not render its observation or check-next line")
	}
	if basisAt > obsAt {
		t.Error("the basis renders after the observation; it explains the badge above, not the prose below")
	}
	if basisAt > nextAt {
		t.Error("the basis is still after the check-next line, which is the placement this replaced")
	}
}

// TestExportSaysNothingForConfirmedFindings is the other half of the rule:
// absence is the signal. "Marked confirmed because" would turn the quiet
// default into a claim on every card, and there is no basis text to put after
// it in any case.
func TestExportSaysNothingForConfirmedFindings(t *testing.T) {
	f := inferredResponseFinding()
	f.Quality = "confirmed"
	f.QualityBasis = ""

	html := cards(t, render(t, sampleDoc(f)))

	if strings.Contains(html, "Marked inferred because:") {
		t.Error("a confirmed finding renders the inferred-basis label")
	}
	if strings.Contains(html, "Marked confirmed because") {
		t.Error("a confirmed finding makes a positive claim about its own evidence; " +
			"the absence of a basis is what says confirmed")
	}
	if strings.Contains(html, "basis-inferred") {
		t.Error("a confirmed finding renders the inferred basis block")
	}
}

// TestExportCarriesTheBadgeLegendOnlyWhenBadgesAppear covers the note added
// for readers who cannot click a badge through to the guide. It is gated on
// there being findings: a clean capture shows no badge anywhere, and a legend
// for labels that do not appear is noise in a document meant to be short.
func TestExportCarriesTheBadgeLegendOnlyWhenBadgesAppear(t *testing.T) {
	const legend = "Two labels on every finding."

	if withFindings := render(t, sampleDoc(inferredResponseFinding())); !strings.Contains(withFindings, legend) {
		t.Error("a report with findings carries no explanation of the two badges, " +
			"and an export reader has no guide to reach for one")
	}

	if clean := render(t, sampleDoc()); strings.Contains(clean, legend) {
		t.Error("a clean report explains badges that do not appear in it")
	}
}
