package gui

import (
	"regexp"
	"strings"
	"testing"
)

// TestInformationalFoldIsPresentationOnly holds the fold to the line the
// session brief draws around it: collapsed is not hidden.
//
// The standing no-display-floor constraint says every finding the engine
// produces reaches the report. A fold is the first thing built that makes a
// finding not-immediately-visible, so the distinction between "folded away in
// this view" and "left out" has to be structural rather than remembered. What
// makes it safe is that the fold lives entirely in the renderer: it slices the
// list it was handed and never filters, drops, or re-requests anything.
func TestInformationalFoldIsPresentationOnly(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "renderFindingList")

	// The band is taken by slicing the ranked list, so every finding is still
	// in hand and still in order. A call that asked the backend for a subset,
	// or that dropped entries, would be a display floor wearing a fold's
	// clothes.
	if !strings.Contains(fn, "findings.slice(") {
		t.Error("renderFindingList does not slice the list it was given; the fold must partition " +
			"the ranked findings, not re-select them")
	}
	if strings.Contains(fn, "window.go.gui.App") {
		t.Error("renderFindingList calls a backend binding — the fold is presentation over findings " +
			"already delivered, never a second request for a subset")
	}
	if strings.Contains(fn, ".filter(") {
		t.Error("renderFindingList filters the findings; the fold folds, it does not select")
	}

	// Every finding reaches a card in exactly one of the two branches.
	if n := strings.Count(fn, "findingCard(f)"); n < 3 {
		t.Errorf("renderFindingList builds cards in %d places, want 3 (all-informational, "+
			"the leading band, and the folded band) — a missing one means findings that render nowhere", n)
	}
}

// TestInformationalFoldCountIsDerived guards the number in the row.
//
// The count is the whole honesty of the fold: it is the only thing telling a
// reader that findings exist below the seam. A hardcoded or narrated number
// would let the row say "3 informational findings" over four of them, which is
// a display floor that also lies about itself.
func TestInformationalFoldCountIsDerived(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "renderFindingList")

	if !regexp.MustCompile(`band\.length\s*\+\s*" informational finding"`).MatchString(fn) {
		t.Error("the fold row's count is not read from the band being folded")
	}
	// Singular and plural both, or the row reads "1 informational findings".
	if !strings.Contains(fn, `band.length === 1 ? "" : "s"`) {
		t.Error("the fold row does not handle the single-finding case")
	}
}

// TestAllInformationalReportDoesNotFold is the brief's explicit exception.
//
// A report whose findings are all informational would otherwise open as one
// collapsed row and nothing else, which reads as a broken screen rather than
// as a quiet result — and the quiet result is the honest message. The guard is
// asserted structurally because the condition only arises on captures where
// nothing scored above the floor, which is exactly when a reader is most
// likely to mistake an odd-looking screen for a failure.
func TestAllInformationalReportDoesNotFold(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "renderFindingList")

	m := regexp.MustCompile(`(?s)if\s*\(split === 0\)\s*\{(.*?)\n    \}`).FindStringSubmatch(fn)
	if m == nil {
		t.Fatal("renderFindingList has no split === 0 branch, so an all-informational report would fold")
	}
	body := m[1]
	if !strings.Contains(body, "findingCard(f)") {
		t.Error("the all-informational branch renders no cards")
	}
	if strings.Contains(body, "info-fold") {
		t.Error("the all-informational branch still builds a fold row")
	}
}

// TestInformationalFoldIsKeyboardOperable covers the brief's keyboard
// requirement without reimplementing what the platform already does.
//
// A <button> is focusable and activates on both Enter and Space by definition.
// A div with a click handler and a tabindex is the version that looks correct
// and silently drops Space, so what is asserted is the element choice rather
// than a pile of key handlers.
func TestInformationalFoldIsKeyboardOperable(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "renderFindingList")

	if !regexp.MustCompile(`el\("button", "info-fold"\)`).MatchString(fn) {
		t.Error("the fold row is not a <button>; focusability and Enter/Space activation would " +
			"have to be hand-rolled, which is how Space ends up unsupported")
	}
	if !strings.Contains(fn, `setAttribute("aria-expanded"`) {
		t.Error("the fold row does not report its expanded state to assistive technology")
	}
	if strings.Contains(fn, `"keydown"`) || strings.Contains(fn, `"keypress"`) {
		t.Error("the fold row hand-rolls key handling; a button already does this correctly")
	}
}

// TestFoldStateResetsOnANewCapture is the brief's scoping rule for the state.
//
// The fold is a reading position inside one report, not a preference. Carried
// across, it would open a fresh capture already folded on the strength of a
// decision made about a different set of findings — and the reader would have
// no reason to suspect the screen was showing them less than it had.
func TestFoldStateResetsOnANewCapture(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "analyze")

	if !regexp.MustCompile(`infoExpanded\s*=\s*false`).MatchString(fn) {
		t.Error("analyze() does not reset the fold state, so a new capture would inherit the " +
			"previous report's fold")
	}
}
