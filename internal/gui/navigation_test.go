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

// TestTopBarIsOutsideEveryViewAndUniversallyWired is the structural half of
// the persistent bar.
//
// This replaces a test that checked for a per-screen Home button on each of
// the three guide-area views. That approach was the problem it was testing
// for: every screen grew its own way out, one at a time, and the test could
// only ever assert the instances someone had already remembered to add. A
// bar declared once outside all the views is universal by construction, and
// what needs asserting is precisely that — that it is not inside any view,
// so no view can be shown without it.
func TestTopBarIsOutsideEveryViewAndUniversallyWired(t *testing.T) {
	html := readFrontend(t, "index.html")
	js := readFrontend(t, "app.js")

	if !strings.Contains(html, `id="topbar"`) {
		t.Fatal("index.html has no #topbar")
	}

	// Not nested in any view container: a bar inside one would vanish with it.
	views := regexp.MustCompile(`(?s)<main id="view-([a-z-]+)"[^>]*>(.*?)</main>`)
	for _, m := range views.FindAllStringSubmatch(html, -1) {
		if strings.Contains(m[2], `id="topbar"`) {
			t.Errorf("#topbar is inside view-%s, so it would disappear whenever that view is hidden", m[1])
		}
	}

	// The three destinations, each wired.
	for _, id := range []string{"nav-home", "nav-guide", "nav-about"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("index.html has no #%s", id)
		}
		wire := regexp.MustCompile(`\$\("` + regexp.QuoteMeta(id) + `"\)\.addEventListener\(\s*"click"`)
		if !wire.MatchString(js) {
			t.Errorf("#%s has no click handler", id)
		}
	}

	// Home is the universal escape hatch, so it is an unconditional jump
	// rather than anything that depends on where the reader has been.
	if !regexp.MustCompile(`\$\("nav-home"\)\.addEventListener\(\s*"click"\s*,\s*goHome\s*\)`).MatchString(js) {
		t.Error("#nav-home is not wired to goHome")
	}
	goHome := extractFunction(t, js, "goHome")
	if !strings.Contains(goHome, `show("home")`) {
		t.Error(`goHome does not show the home view unconditionally`)
	}
	// Reaching a root ends the trail rather than suspending it: a back control
	// still offering "← Guide" after the reader has left for Home would return
	// them to a screen they deliberately walked out of.
	if !regexp.MustCompile(`backStack\s*=\s*\[\]`).MatchString(goHome) {
		t.Error("goHome does not clear the back stack, so the contextual return would survive leaving for a root")
	}

	// The active state is driven from show(), so revealing a view cannot
	// leave the bar disagreeing about where the reader is.
	showFn := extractFunction(t, js, "show")
	if !strings.Contains(showFn, "NAV_FOR") {
		t.Error("show() does not update the bar's active state; it would go stale on navigation")
	}
}

// TestContextualBackControlSurvivesTheTopBarAndIsNotUnderIt guards the
// coexistence the brief requires. The bar's Home and the "← {label}" return do
// different jobs — one is a universal escape hatch, the other restores the
// exact card and scroll position the reader left — and consolidating the
// one-off Home buttons must not have taken the contextual control with them.
//
// It also fixes the position, which is not cosmetic. The control used to sit
// in each view's own header, in normal flow, directly beneath a sticky bar.
// Scrolling slid it under: partly covered, still visibly a button, and the
// click landing on the bar instead — reported as "the back button doesn't work
// on the first attempt". Inside the bar it cannot be overlaid by the bar, and
// that is the property asserted here, not merely that some back control
// exists somewhere.
func TestContextualBackControlSurvivesTheTopBarAndIsNotUnderIt(t *testing.T) {
	html := readFrontend(t, "index.html")
	js := readFrontend(t, "app.js")

	bar := regexp.MustCompile(`(?s)<nav id="topbar".*?</nav>`).FindString(html)
	if bar == "" {
		t.Fatal("#topbar element not found")
	}
	if !strings.Contains(bar, `id="nav-back"`) {
		t.Fatal("the contextual return #nav-back is not inside #topbar; anywhere below the sticky bar " +
			"it can be scrolled under the bar and silently stop taking clicks")
	}

	wire := regexp.MustCompile(`\$\("nav-back"\)\.addEventListener\(\s*"click"\s*,\s*goBack\s*\)`)
	if !wire.MatchString(js) {
		t.Error("#nav-back is not wired to goBack, so it would stop restoring scroll position")
	}

	// The per-view controls it replaced must be gone rather than left
	// duplicated — a second copy in normal flow would reintroduce exactly the
	// swallowed-click bug this consolidation removes.
	for _, old := range []string{"btn-guide-back", "btn-index-back", "btn-about-back"} {
		if strings.Contains(html, old) || strings.Contains(js, old) {
			t.Errorf("%s still exists; the per-view back controls were superseded by #nav-back", old)
		}
	}

	// goBack itself must still restore the remembered position rather than
	// having quietly become a jump to the top.
	goBack := extractFunction(t, js, "goBack")
	if !strings.Contains(goBack, ".scrollY") || !strings.Contains(goBack, "window.scrollTo") {
		t.Error("goBack no longer restores the remembered scroll position")
	}
	// One shared control serving three views has to be repainted whenever a
	// view is revealed. Painted at open time instead, it would keep the label
	// and destination of whichever screen last set it — returning to the guide
	// page under a "← Guide" button that goes nowhere.
	showFn := extractFunction(t, js, "show")
	if !strings.Contains(showFn, `$("nav-back")`) {
		t.Error("show() does not repaint #nav-back; the shared control would carry another view's return target")
	}
	if !strings.Contains(showFn, "BACK_VIEWS") {
		t.Error("show() does not gate #nav-back on the view being one that can be returned from")
	}
	// And the memory has to be a stack, not one slot: returning from About to
	// a guide page has to restore the guide page's own way back, which a
	// single overwritten slot has by then destroyed.
	if !strings.Contains(goBack, "backStack.pop()") {
		t.Error("goBack does not pop a stack, so a two-hop trail would lose the earlier return target")
	}
}

// TestStickyBarDoesNotSwallowAnchorLandings is the interaction the bar
// introduces: scrollIntoView brings a section to the top of the viewport,
// which is exactly where a sticky bar sits. Without room reserved, arriving
// at a rule's section from a finding lands with its heading hidden behind
// the bar.
func TestStickyBarDoesNotSwallowAnchorLandings(t *testing.T) {
	css := readFrontend(t, "app.css")
	if !regexp.MustCompile(`\.guide-section\s*\{[^}]*scroll-margin-top`).MatchString(css) {
		t.Error("guide sections reserve no scroll margin, so an anchored landing would sit under the sticky bar")
	}
}

// TestBodyDoesNotBoxInTheStickyBar guards the reason the bar was not actually
// persistent, which the swallowed-click investigation turned up underneath it.
//
// `html, body { height: 100% }` with `body { overflow-y: auto }` makes body a
// viewport-sized scroll container. A sticky box cannot travel outside its
// containing block, and body's box was then one viewport tall while a guide
// page ran to three — so the bar held position for the first screenful and
// then scrolled away with the text. Measured in the browser before the fix:
// the bar's top was at -51px by 600px of scroll on a 1779px page.
//
// The property is structural and easy to reintroduce by copying a
// full-height-app layout idiom, so it is asserted rather than left to the
// next person to rediscover interactively.
func TestBodyDoesNotBoxInTheStickyBar(t *testing.T) {
	css := readFrontend(t, "app.css")

	bodyRules := regexp.MustCompile(`(?m)^\s*(?:html\s*,\s*)?body\s*\{([^}]*)\}`).FindAllStringSubmatch(css, -1)
	if len(bodyRules) == 0 {
		t.Fatal("no body rule found in app.css")
	}
	for _, r := range bodyRules {
		decls := r[1]
		// A fixed height is the half that shrinks the containing block.
		if regexp.MustCompile(`(?m)(^|;)\s*height\s*:\s*100%`).MatchString(decls) {
			t.Error("body has height: 100%, which caps the sticky bar's containing block at one viewport — " +
				"use min-height so the body grows with the page")
		}
		// And body owning the scroll is the half that makes it the scrollport.
		if regexp.MustCompile(`(?m)(^|;)\s*overflow(-y)?\s*:\s*(auto|scroll)`).MatchString(decls) {
			t.Error("body declares its own overflow, making it the scroll container rather than the document; " +
				"the sticky bar then sticks within body's box instead of the page")
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

	// The gating now lives in the shared renderer, which is what makes it
	// cover the home screen's list as well as the index's.
	fn := extractFunction(t, js, "renderCheckList")

	// The click handler must be attached only inside the has_page branch —
	// not unconditionally with a later guard, which would still leave a
	// listener object attached to every button regardless of whether it does
	// anything once invoked.
	ifBlock := regexp.MustCompile(`(?s)if\s*\(e\.has_page\)\s*\{(.*?)\}\s*else\s*\{(.*?)\}`)
	m := ifBlock.FindStringSubmatch(fn)
	if m == nil {
		t.Fatal("renderCheckList does not branch on e.has_page with both an if and an else — " +
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
	// Shared with the home screen's list, so this now covers both places a
	// grouped row is shown.
	fn := extractFunction(t, js, "renderCheckList")

	if !strings.Contains(fn, "e.members") {
		t.Fatal("renderCheckList never reads e.members — a page serving several rules would render as " +
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

// TestHomeChecksListIsTheSameComponentAsTheGuideIndex is the reuse the brief
// requires, asserted rather than assumed.
//
// The registry-walk test above proves the navigation data path works for
// every built rule. That proof carries to the home screen only if the home
// screen renders through the same code — so what is checked here is exactly
// that: one renderer, two call sites, and no second list-building loop that
// would need its own proof and could drift from this one.
func TestHomeChecksListIsTheSameComponentAsTheGuideIndex(t *testing.T) {
	js := readFrontend(t, "app.js")

	// Both call sites, naming the element each fills.
	calls := regexp.MustCompile(`renderCheckList\(\s*\$\("([a-z-]+)"\)`).FindAllStringSubmatch(js, -1)
	filled := map[string]bool{}
	for _, c := range calls {
		filled[c[1]] = true
	}
	for _, id := range []string{"checks-list", "guide-index-list"} {
		if !filled[id] {
			t.Errorf("#%s is not filled by renderCheckList; it would be a second, unproven list renderer", id)
		}
	}

	// And renderHome must not have kept a loop of its own over the checks.
	// This is the specific shape the brief warned against: a parallel
	// mechanism that looks fine and is never covered by the navigation test.
	home := extractFunction(t, js, "renderHome")
	if !strings.Contains(home, "renderCheckList") {
		t.Error("renderHome does not delegate to renderCheckList")
	}
	if strings.Contains(home, "implemented_checks || []).forEach") {
		t.Error("renderHome still builds the checks list itself, in parallel with the guide index's renderer")
	}

	// The rows differ between the two screens in exactly one respect — where
	// a click returns to — and that is a parameter, not a fork in the
	// renderer.
	fn := extractFunction(t, js, "renderCheckList")
	if !strings.Contains(fn, "rememberReturn(fromView, fromLabel)") {
		t.Error("renderCheckList does not take its return target as a parameter")
	}
	// Arrival from either list is a browse, not a finding, so neither may
	// pass a finding and summon the context block.
	if !regexp.MustCompile(`openGuide\(e\.rule_id,\s*null\)`).MatchString(fn) {
		t.Error("renderCheckList does not open guide pages with a null finding, so a browsed page " +
			"could render a finding-context block that no finding sent the reader to")
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
