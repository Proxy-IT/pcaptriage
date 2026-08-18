package gui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/rules"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// The frontend has no execution harness in this repo — no headless browser,
// no JS engine — so these tests hold the shipped source to structural
// properties rather than simulating clicks. That is a real gap (verified
// interactively instead, against a -preview render, for the two bugs these
// tests exist to catch) but the properties below are exactly the ones a
// regression would violate: a screen with no way home, or a link that
// silently renders without being wired.

func readFrontend(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Dir(filepath.Dir(synth.FixtureDir()))
	b, err := os.ReadFile(filepath.Join(root, "frontend", "dist", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEveryGuideAreaScreenHasAHomePath is the first bug: "← {label}" only
// ever undoes the last hop, so a reader several screens into the guide area
// had no way back to the drop zone except walking back through however many
// hops that was. Every guide/guide-index/about screen needs a direct,
// unconditional path to home, not just a context-sensitive one back.
func TestEveryGuideAreaScreenHasAHomePath(t *testing.T) {
	html := readFrontend(t, "index.html")
	js := readFrontend(t, "app.js")

	screens := []struct {
		view   string // the id suffix of the view container
		homeID string
	}{
		{"guide", "btn-guide-home"},
		{"guide-index", "btn-index-home"},
		{"about", "btn-about-home"},
	}

	for _, s := range screens {
		// The button must exist inside that view's container in the markup,
		// not merely exist somewhere in the document.
		container := regexp.MustCompile(`(?s)id="view-` + regexp.QuoteMeta(s.view) + `"[^>]*>(.*?)\n</main>`)
		m := container.FindStringSubmatch(html)
		if m == nil {
			t.Fatalf("view-%s container not found in index.html", s.view)
		}
		if !strings.Contains(m[1], `id="`+s.homeID+`"`) {
			t.Errorf("view-%s has no #%s — no direct path home from this screen", s.view, s.homeID)
		}

		// And it has to be wired to an unconditional jump to home, not to
		// goBack (which is the context-sensitive one-level-back button these
		// screens already have, and is not a substitute for this).
		wire := regexp.MustCompile(`\$\("` + regexp.QuoteMeta(s.homeID) + `"\)\.addEventListener\(\s*"click"\s*,\s*function\s*\(\)\s*\{\s*show\("home"\)`)
		if !wire.MatchString(js) {
			t.Errorf("#%s is not wired to an unconditional show(\"home\")", s.homeID)
		}
	}
}

// TestGuideIndexGatesBothTheHandlerAndTheAppearance is the second bug. The
// backend's has_page field was correct throughout — verified separately
// against the registry — but a disabled button whose only cue is a subtle
// opacity/border change reads as "works the same as the others" at a glance.
// This asserts the index rendering does not rely on colour/opacity alone:
// an entry without a page must be both inert (disabled, no listener attached)
// and say so in words, the same rule severity and evidence quality already
// follow elsewhere in this app.
func TestGuideIndexGatesBothTheHandlerAndTheAppearance(t *testing.T) {
	js := readFrontend(t, "app.js")

	fn := extractFunction(t, js, "openGuideIndex")

	// The click handler must be attached only inside the has_page branch —
	// not unconditionally with a later guard, which would still leave a
	// listener object attached to every button regardless of whether it does
	// anything once invoked.
	ifBlock := regexp.MustCompile(`(?s)if\s*\(e\.has_page\)\s*\{(.*?)\}\s*else\s*\{(.*?)\}`)
	m := ifBlock.FindStringSubmatch(fn)
	if m == nil {
		t.Fatal("openGuideIndex does not branch on e.has_page with both an if and an else — " +
			"cannot verify the handler and the disabled state are mutually exclusive")
	}
	ifBody, elseBody := m[1], m[2]

	if !strings.Contains(ifBody, "addEventListener") {
		t.Error("the has_page branch does not attach a click handler")
	}
	if strings.Contains(elseBody, "addEventListener") {
		t.Error("the no-page branch attaches a click handler; a disabled entry must not be wired to navigate")
	}
	if !strings.Contains(elseBody, ".disabled = true") {
		t.Error("the no-page branch does not disable the button")
	}
	// The words, not just the dimming: a reader must be able to tell an inert
	// row from a working one without relying on a subtle style difference.
	if !strings.Contains(elseBody, "tag-unavailable") && !strings.Contains(elseBody, "No guide yet") {
		t.Error("the no-page branch has no textual indicator — a disabled row that looks the same as a working one " +
			"is the bug this test exists to catch")
	}
}

// TestGuideLandingScrollsToAnchorOnlyFromAFinding is Part 3b's landing
// behaviour: arriving from a finding on a multi-rule page scrolls to that
// rule's anchored section; arriving from the index lands at the top. Both
// paths call the same openGuide(ruleID, finding), so the only signal
// available to tell them apart is whether finding is non-null — this asserts
// the scroll is conditioned on exactly that, not on the page shape alone
// (which would scroll on index arrival too, contradicting 3b).
func TestGuideLandingScrollsToAnchorOnlyFromAFinding(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "openGuide")

	if !strings.Contains(fn, "scrollIntoView") {
		t.Fatal("openGuide never scrolls to a section; a multi-rule page arrived at from a finding " +
			"would always land at the top, same as index arrival")
	}
	// The variable that ends up scrolled-to must only be assigned inside a
	// condition that includes `finding` — a page-only condition would scroll
	// on both arrival paths, and an unconditional one would fire even from
	// the index.
	assign := regexp.MustCompile(`(?s)if\s*\(finding\s*&&.*?\)\s*\{\s*landingSection\s*=`)
	if !assign.MatchString(fn) {
		t.Error("the scroll target is not gated on `finding` being present — index arrival would scroll too")
	}
	// And the index's own call site must pass null explicitly, not omit the
	// argument (which is also falsy, but a reader of the call site should not
	// have to know that to trust the landing behaviour is intentional).
	js2 := readFrontend(t, "app.js")
	indexCall := regexp.MustCompile(`openGuide\(e\.rule_id,\s*null\)`)
	if !indexCall.MatchString(js2) {
		t.Error("the index's click handler does not pass null explicitly for the finding argument")
	}
}

// TestR15HasAGuideLinkFromBothBannerLocations is Part 3c: R15 renders in the
// banner rather than as cards, so its guide entry needs a link from wherever
// its notices appear rather than from a per-finding button. Both locations —
// the clean-capture gaps column and the full findings view's "what wasn't
// checked" section — are checked, since R15's notices can land in either
// depending on whether the capture was clean.
func TestR15HasAGuideLinkFromBothBannerLocations(t *testing.T) {
	html := readFrontend(t, "index.html")
	js := readFrontend(t, "app.js")

	for _, id := range []string{"btn-clean-gaps-guide", "btn-notes-guide"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("index.html has no #%s", id)
		}
		wire := regexp.MustCompile(`\$\("` + regexp.QuoteMeta(id) + `"\)\.addEventListener\(\s*"click"`)
		if !wire.MatchString(js) {
			t.Errorf("#%s has no click handler wired", id)
		}
	}
	if !strings.Contains(js, `openGuide("R15", null)`) {
		t.Error(`no call site opens R15's guide page with openGuide("R15", null) — ` +
			"the banner link would either dangle or falsely imply a finding context")
	}
}

// TestGroupedIndexEntriesRenderTheirMembers is Part 3d: a page serving
// several rules is one row in the index, but the row must still say all four
// rules it covers — collapsing four checks into one visual row without
// disclosing what got folded in would be the registry-honesty failure this
// index exists to prevent, one level up.
func TestGroupedIndexEntriesRenderTheirMembers(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "openGuideIndex")

	if !strings.Contains(fn, "e.members") {
		t.Fatal("openGuideIndex never reads e.members — a page serving several rules would render as " +
			"one row with no indication of what else it covers")
	}
	if !regexp.MustCompile(`e\.members\s*&&\s*e\.members\.length`).MatchString(fn) {
		t.Error("the members branch is not gated on members actually being present")
	}
	if !strings.Contains(fn, "m.rule_id") || !strings.Contains(fn, "m.name") {
		t.Error("a member's own rule ID and name are not both rendered — the row would list a check without saying which")
	}
}

// TestCardLinkAvailabilityCoversGroupedMembers is the bug the R06-from-a-
// finding checkpoint render caught interactively: guideAvailable was built
// from e.rule_id alone, so a rule folded into a group as a Member (every
// served rule but the first) never got its card's "What does this mean?"
// link at all — not merely disabled, silently absent, because the code never
// considered it. R05 is the primary of the loss group and would have passed
// a check that only looked at rule_id; this asserts the sibling rules do too.
func TestCardLinkAvailabilityCoversGroupedMembers(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "start")

	guideBlock := regexp.MustCompile(`(?s)window\.go\.gui\.App\.Guide\(\).*?\.catch`)
	m := guideBlock.FindString(fn)
	if m == "" {
		t.Fatal("start() has no Guide() handler to check")
	}
	if !strings.Contains(m, "e.rule_id") {
		t.Error("the Guide() handler no longer marks the entry's own rule_id available")
	}
	if !strings.Contains(m, "e.members") {
		t.Fatal("the Guide() handler does not read e.members — a rule grouped into a page as anything " +
			"but the first served rule would never get a working card link")
	}
	if !regexp.MustCompile(`m\.rule_id`).MatchString(m) {
		t.Error("members are read but their own rule_id is never used to populate guideAvailable")
	}
}

// TestEveryBuiltRuleLinkActuallyNavigates walks the whole card-link path the
// way the frontend does, for every rule in the registry rather than for the
// ones a fixture happens to produce.
//
// The Batch 1 dead-link bug survived a test that only checked a page existed
// for each rule: the page existed, the index knew it, and the card still
// rendered no link, because the step in between — the frontend's own
// availability map, built from the index — considered only each entry's first
// rule. So this reproduces that step rather than trusting it, and then
// follows through to the page and its landing anchor. Everything short of
// executing the JavaScript, which this repo has no harness for.
func TestEveryBuiltRuleLinkActuallyNavigates(t *testing.T) {
	app := New("test")

	idx, err := app.Guide()
	if err != nil {
		t.Fatal(err)
	}

	// Step one, exactly as app.js's start() does it: an entry contributes its
	// own rule and every member. Getting this wrong is the original bug.
	available := map[string]bool{}
	for _, e := range idx.Entries {
		if !e.HasPage {
			continue
		}
		available[e.RuleID] = true
		for _, m := range e.Members {
			available[m.RuleID] = true
		}
	}

	metas := rules.AllMeta()
	if len(metas) == 0 {
		t.Fatal("no rules registered")
	}

	for _, m := range metas {
		// Step two: the card only renders a link when the map says so.
		if !available[m.ID] {
			t.Errorf("%s renders no card link: the index never marked it available, so a finding "+
				"from this rule offers the reader nothing to click", m.ID)
			continue
		}

		// Step three: the click resolves to a page.
		page, err := app.GuidePage(m.ID)
		if err != nil {
			t.Errorf("%s has an available link that does not resolve: %v", m.ID, err)
			continue
		}
		if !page.ServesRule(m.ID) {
			t.Errorf("%s resolved to page %q, which does not serve it", m.ID, page.Title)
			continue
		}

		// Step four: on a shared page, the click has somewhere to land. A
		// link that opens the right document at the wrong rule's section is
		// still a broken link to the reader who clicked it.
		if len(page.RuleIDs) > 1 {
			var anchored int
			for _, s := range page.Sections {
				if strings.EqualFold(s.Anchor, m.ID) {
					anchored++
				}
			}
			if anchored != 1 {
				t.Errorf("%s shares page %q with %d other rule(s) but has %d landing sections there, want 1",
					m.ID, page.Title, len(page.RuleIDs)-1, anchored)
			}
		}
	}
}

// extractFunction returns the source of a top-level `function name(...) { ... }`
// declaration, by brace counting from its opening brace. Good enough for this
// file's hand-written functions; not a general JS parser.
func extractFunction(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "function "+name+"(")
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	open := strings.IndexByte(src[start:], '{')
	if open < 0 {
		t.Fatalf("function %s has no body", name)
	}
	open += start

	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	t.Fatalf("function %s's body never closes", name)
	return ""
}
