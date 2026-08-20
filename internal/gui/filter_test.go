package gui

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/report"
)

// TestFilteringIsPresentationOnly is the first of the brief's two hard rules,
// asserted rather than described.
//
// Everything else in this session bends around it: comparative wording like
// "the other 8 servers in this capture" stays true under any filter precisely
// because the population was measured before any filtering ran, and a view
// cannot change what was measured. The moment a filter re-requests or
// re-derives anything, that sentence becomes a claim about a subset while
// still reading as a claim about the whole capture.
func TestFilteringIsPresentationOnly(t *testing.T) {
	js := readFrontend(t, "app.js")

	for _, name := range []string{"repaintFindings", "filteredFindings", "findingMatches", "findingEndpoints"} {
		fn := extractFunction(t, js, name)
		if strings.Contains(fn, "window.go.gui.App") {
			t.Errorf("%s calls a backend binding; filtering is a view over completed results, "+
				"never a second analysis", name)
		}
	}

	// The repaint reads the held result rather than asking for one.
	repaint := extractFunction(t, js, "repaintFindings")
	if !strings.Contains(repaint, "currentResult") {
		t.Error("repaintFindings does not read the held report, so a filter change would need " +
			"the backend to re-deliver it")
	}
	// And nothing in the filter path rewrites a finding's own wording.
	for _, field := range []string{".observation =", ".title =", ".check_next =", ".severity ="} {
		if strings.Contains(repaint, field) {
			t.Errorf("repaintFindings assigns %s — filtering must not touch what a finding says", field)
		}
	}
}

// TestFilterNeverTouchesCoverage is 2c, and it is the same false-all-clear
// risk the clean banner was designed against, one layer up.
//
// Capture-quality warnings are statements about the whole file. A filter that
// could scope away "the capture host dropped packets" would manufacture
// confidence the capture does not support — the reader would be looking at a
// narrowed view believing it was fully assessed.
func TestFilterNeverTouchesCoverage(t *testing.T) {
	js := readFrontend(t, "app.js")
	repaint := extractFunction(t, js, "repaintFindings")

	// The coverage-bearing regions render outside the filtered repaint, so no
	// filter state can reach them.
	for _, id := range []string{"notes-section", "notes-list", "build-note-text"} {
		if strings.Contains(repaint, id) {
			t.Errorf("repaintFindings touches #%s; coverage and the not-assessed notes render in "+
				"full under every filter and must sit outside the filtered path", id)
		}
	}
	// And they render somewhere — outside it.
	full := extractFunction(t, js, "renderFindings")
	for _, id := range []string{"notes-section", "build-note-text"} {
		if !strings.Contains(full, id) {
			t.Errorf("#%s is not rendered by renderFindings either; it has to render somewhere "+
				"unconditional", id)
		}
	}
}

// TestFilteredEmptyIsNotTheCleanState is 2d — the load-bearing screen.
//
// The two states are opposite claims about an identical-looking blank result:
// one says the checks found nothing, the other says the checks found things
// and none of them are on screen. A reader who takes "clean" away from
// "filtered to nothing" closes a ticket on a live fault, so the separation is
// enforced in three places at once — different element, different wording, and
// a ban-list over both the static markup and the generated sentence.
func TestFilteredEmptyIsNotTheCleanState(t *testing.T) {
	html := readFrontend(t, "index.html")
	js := readFrontend(t, "app.js")

	block := regexp.MustCompile(`(?s)<section id="filtered-empty".*?</section>`).FindString(html)
	if block == "" {
		t.Fatal("there is no #filtered-empty section; filtering to nothing would fall through to " +
			"an empty list or, worse, the clean state")
	}

	// Its own element, never the clean state's.
	if strings.Contains(block, "clean-state") || strings.Contains(block, `class="clean"`) {
		t.Error("the filtered-empty state reuses the clean state's markup")
	}
	// It leads with the filter, and offers the one action available.
	if !strings.Contains(block, "No findings match this filter.") {
		t.Error("the filtered-empty heading does not lead with the filter")
	}
	if !strings.Contains(block, "filtered-empty-clear") {
		t.Error("the filtered-empty state offers no one-click way out, which is the only action " +
			"available to a reader whose screen is otherwise blank")
	}

	// The ban-list, over the static markup and over the generated sentence
	// both — the detail line is assembled in JS and would otherwise sit
	// outside the reach of a markup-only check.
	gen := extractFunction(t, js, "renderFilteredEmpty")
	for _, banned := range report.CleanStateBans {
		if strings.Contains(strings.ToLower(block), banned) {
			t.Errorf("the filtered-empty markup contains clean-capture wording %q", banned)
		}
		if strings.Contains(strings.ToLower(gen), banned) {
			t.Errorf("the filtered-empty sentence is built from clean-capture wording %q", banned)
		}
	}
	for _, banned := range report.VerdictBans {
		if strings.Contains(strings.ToLower(block), banned) {
			t.Errorf("the filtered-empty markup contains a verdict %q", banned)
		}
		if strings.Contains(strings.ToLower(gen), banned) {
			t.Errorf("the filtered-empty sentence contains a verdict %q", banned)
		}
	}

	// The generated line must state the capture's real total, or the screen
	// says only "nothing here" and leaves the reader to guess what that means.
	if !strings.Contains(gen, "total") {
		t.Error("the filtered-empty sentence does not state how many findings the capture holds")
	}
}

// TestCleanStateIsUnreachableByFiltering is the other half of 2d: the clean
// state must be gated on the capture, not on what survived a filter.
func TestCleanStateIsUnreachableByFiltering(t *testing.T) {
	js := readFrontend(t, "app.js")
	repaint := extractFunction(t, js, "repaintFindings")

	if !regexp.MustCompile(`reallyClean\s*=\s*all\.length === 0`).MatchString(repaint) {
		t.Error("the clean state is not gated on the unfiltered finding count; filtering to zero " +
			"could then present a capture with findings as clean")
	}
	if !regexp.MustCompile(`filteredToNothing\s*=\s*!reallyClean`).MatchString(repaint) {
		t.Error("the filtered-empty state is not mutually exclusive with the clean state")
	}
}

// TestFilterCountIsAlwaysShownWhileFiltering is 2b's mandatory admission.
//
// "Showing N of M" is the only thing on a filtered screen that says the screen
// is a subset. It is not an optional flourish on the chip bar: whenever the
// bar renders, the count renders, and both are gated on the same condition.
func TestFilterCountIsAlwaysShownWhileFiltering(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "renderFilterBar")

	if !regexp.MustCompile(`"Showing " \+ shown \+ " of " \+ total`).MatchString(fn) {
		t.Error("the chip bar does not render a Showing-N-of-M count derived from the two totals")
	}
	// One early return, the no-filter case, so there is no path that paints
	// chips without the count.
	if n := strings.Count(fn, "return"); n != 1 {
		t.Errorf("renderFilterBar has %d returns; more than one means a path that could show chips "+
			"without the count that qualifies them", n)
	}
	if !regexp.MustCompile(`filterTerms\.length === 0`).MatchString(fn) {
		t.Error("the chip bar is not gated on there being active terms, so it would be persistent " +
			"chrome implying the view is always filtered")
	}
}

// TestEndpointsComeFromTheSubjectNotTheWording is 2a's subject rule, held in
// place by construction rather than by care.
//
// A finding matches a host filter when that host is one of its own endpoints.
// Hosts named only as comparative context — R04's "the other 8 servers in this
// capture" — are not subjects. That holds because the endpoints are read from
// the structured subject field, and comparative hosts appear only in the
// observation. Scraping addresses out of the wording would quietly widen what
// "subject" means and make findings match filters they are not about.
func TestEndpointsComeFromTheSubjectNotTheWording(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "findingEndpoints")

	if !strings.Contains(fn, "f.subject") {
		t.Fatal("findingEndpoints does not read the structured subject")
	}
	for _, field := range []string{"observation", "check_next", "quality_basis"} {
		if strings.Contains(fn, field) {
			t.Errorf("findingEndpoints reads %s; comparative context lives there and must never "+
				"become a filter subject", field)
		}
	}
	if !strings.Contains(fn, `f.scope_kind === "flow"`) {
		t.Error("findingEndpoints does not split flow subjects, so one side of every conversation " +
			"would be unfilterable")
	}

	// The title's clickable spans are located by searching for the endpoints
	// already derived, not by pattern-matching address-shaped text.
	title := extractFunction(t, js, "findingTitle")
	if !strings.Contains(title, "findingEndpoints(f)") {
		t.Error("findingTitle does not build its candidates from the finding's own endpoints")
	}
	if strings.Contains(title, `\d{1,3}`) {
		t.Error("findingTitle pattern-matches address-shaped text; only the finding's own subject " +
			"endpoints may become controls")
	}
}

// TestConversationFilterIsBidirectional is BRIEF section 8's footgun, in the
// GUI.
//
// Two hosts mean the conversation between them, in both directions. Terms
// intersect, and each term matches an endpoint on either side — so which side
// of a conversation a host sits on cannot change whether it matches.
func TestConversationFilterIsBidirectional(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "findingMatches")

	if !strings.Contains(fn, "terms.every(") {
		t.Error("filter terms do not intersect, so a second host would widen the view rather than " +
			"scoping to the conversation")
	}
	if !strings.Contains(fn, "eps.some(") {
		t.Error("a term is not matched against every endpoint of the finding, so matching would " +
			"depend on which side of the conversation the host sits")
	}
	for _, directional := range []string{"src", "dst", "direction"} {
		if strings.Contains(fn, directional) {
			t.Errorf("findingMatches references %q; there is no directional filtering in the GUI",
				directional)
		}
	}
}

// TestReclickingAnActiveTermDoesNothing is 2a's interaction rule: one way to
// add, one way to remove. A control that added on first click and removed on
// the second is a hidden state machine the reader has to model, and the chip's
// close button already answers "how do I undo this".
func TestReclickingAnActiveTermDoesNothing(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "addFilterTerm")

	if !regexp.MustCompile(`if \(termKey\(filterTerms\[i\]\) === key\) return;`).MatchString(fn) {
		t.Error("addFilterTerm does not no-op on an already-active term")
	}
	if strings.Contains(fn, "splice") || strings.Contains(fn, "removeFilterTerm") {
		t.Error("addFilterTerm can also remove; adding and removing must be separate controls")
	}
}

// TestFilterResetsOnANewCapture guards a subtle way a subset could be read as
// the whole.
//
// Filter terms name hosts from the capture that was open when they were
// clicked. Carried into a new capture, they would scope it to addresses that
// may not appear in it at all — presenting a full report as empty, under a
// chip bar the reader never set on this file.
func TestFilterResetsOnANewCapture(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "analyze")

	if !regexp.MustCompile(`filterTerms\s*=\s*\[\]`).MatchString(fn) {
		t.Error("analyze() does not clear the filter, so a new capture would inherit terms naming " +
			"hosts from the previous one")
	}
}

// TestChipBarSticksWithTheNav is 2b's positioning rule.
//
// The brief says match the nav's behaviour rather than introduce a second one.
// Two separately-sticky boxes both pinned to the top of the viewport overlap,
// so the bar and the chips share one sticky wrapper — and the wrapper, like
// the bar before it, must not live inside a view that could hide it.
func TestChipBarSticksWithTheNav(t *testing.T) {
	html := readFrontend(t, "index.html")
	css := readFrontend(t, "app.css")

	if !strings.Contains(html, `id="sticky-head"`) {
		t.Fatal("there is no sticky wrapper around the bar and the chips")
	}
	views := regexp.MustCompile(`(?s)<main id="view-([a-z-]+)"[^>]*>(.*?)</main>`)
	for _, m := range views.FindAllStringSubmatch(html, -1) {
		if strings.Contains(m[2], `id="sticky-head"`) || strings.Contains(m[2], `id="filter-bar"`) {
			t.Errorf("the sticky head or filter bar is inside view-%s, so it would vanish with it", m[1])
		}
	}
	// Exactly one thing sticks, or the two fight over the same pinned spot.
	if !regexp.MustCompile(`\.sticky-head\s*\{[^}]*position:\s*sticky`).MatchString(css) {
		t.Error(".sticky-head is not the sticky element")
	}
	if regexp.MustCompile(`\.topbar\s*\{[^}]*position:\s*sticky`).MatchString(css) {
		t.Error(".topbar still sticks independently of its wrapper; the two would overlap")
	}
}
