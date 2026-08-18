package gui

import (
	"regexp"
	"strings"
	"testing"
)

// TestInkIsConfinedToTheBar is the scope rule for the dark treatment, asserted
// rather than left to discipline.
//
// The bar is where the visual weight is spent, deliberately: guide pages are
// long-form prose and findings views are dense, and both need to stay quiet. An
// ink panel, a dark section header or a dark sidebar in the content area would
// each look defensible on its own, which is exactly why the boundary is a test
// and not a note — the failure mode is a series of individually reasonable
// additions, not one obviously wrong one.
func TestInkIsConfinedToTheBar(t *testing.T) {
	css := readFrontend(t, "app.css")

	// Every rule in the sheet, as (selector, declarations).
	rule := regexp.MustCompile(`(?s)([^{}]+)\{([^{}]*)\}`)
	barToken := regexp.MustCompile(`var\(\s*--bar-[a-z-]+\s*\)`)

	for _, m := range rule.FindAllStringSubmatch(css, -1) {
		selector := strings.TrimSpace(m[1])
		decls := m[2]

		// Strip any comment text and at-rule preludes from the selector so the
		// check reads the actual selector, not the prose above it.
		if i := strings.LastIndex(selector, "*/"); i >= 0 {
			selector = strings.TrimSpace(selector[i+2:])
		}
		if selector == "" || strings.HasPrefix(selector, "@") {
			continue
		}
		if !barToken.MatchString(decls) {
			continue
		}
		for _, s := range strings.Split(selector, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.Contains(s, ".topbar") && !strings.Contains(s, "#topbar") {
				t.Errorf("%q uses a --bar-* token but is not part of the top bar; "+
					"the dark treatment is the bar only, and the content area stays quiet", s)
			}
		}
	}
}

// TestTheBarIsDarkOnEveryScreen pairs with the test above: the ink is confined
// to the bar, and the bar is on everything.
//
// The persistent-bar session already asserts the element sits outside every
// view. What this adds is that its darkness is unconditional — no screen-scoped
// override that would leave, say, the loading or error screen wearing a light
// bar while every other screen wears ink.
func TestTheBarIsDarkOnEveryScreen(t *testing.T) {
	css := readFrontend(t, "app.css")

	base := regexp.MustCompile(`(?s)\.topbar\s*\{([^}]*)\}`).FindStringSubmatch(css)
	if base == nil {
		t.Fatal("no .topbar rule found")
	}
	if !strings.Contains(base[1], "var(--bar-surface)") {
		t.Error(".topbar does not paint itself with --bar-surface")
	}

	// Any later rule that repaints the bar's background must not be scoped to a
	// particular view, which is the shape a per-screen exception would take.
	repaint := regexp.MustCompile(`(?s)([^{}]*\.topbar[^{}]*)\{([^{}]*background[^{}]*)\}`)
	for _, m := range repaint.FindAllStringSubmatch(css, -1) {
		selector := strings.TrimSpace(m[1])
		if i := strings.LastIndex(selector, "*/"); i >= 0 {
			selector = strings.TrimSpace(selector[i+2:])
		}
		if strings.Contains(selector, "#view-") {
			t.Errorf("%q repaints the bar for one view; the bar is the same bar on every screen", selector)
		}
	}
}

// TestThemePreferenceAppliesBeforeFirstRender checks the frontend half of the
// theme mechanism: applyTheme runs as soon as Info() resolves, before the home
// screen is shown, and it sets data-theme only for the two values that need
// it — "system" is deliberately left alone so tokens.css's own
// @media (prefers-color-scheme: dark) answers it, with no JavaScript in the
// loop at all.
func TestThemePreferenceAppliesBeforeFirstRender(t *testing.T) {
	js := readFrontend(t, "app.js")

	fn := extractFunction(t, js, "applyTheme")
	if !strings.Contains(fn, `setAttribute("data-theme"`) {
		t.Error("applyTheme does not set data-theme for an explicit choice")
	}
	if !strings.Contains(fn, `removeAttribute("data-theme")`) {
		t.Error(`applyTheme does not clear data-theme for "system" — ` +
			"leaving a stale attribute would keep the reader on whichever theme was set before, not their OS preference")
	}

	start := extractFunction(t, js, "start")
	call := regexp.MustCompile(`applyTheme\(\s*info\.theme\s*\)`)
	if !call.MatchString(start) {
		t.Error("start() does not call applyTheme(info.theme); the saved preference would never reach the screen")
	}

	// Applied from inside the Info()/Guide() .then(), not after renderHome —
	// a theme set after the first paint is the flash this session's own
	// applyTheme comment accepts as a known, narrow gap; setting it after
	// content has already rendered would widen that gap for no reason.
	callIdx := call.FindStringIndex(start)
	renderIdx := strings.Index(start, "renderHome(")
	if callIdx == nil || renderIdx < 0 || callIdx[0] > renderIdx {
		t.Error("applyTheme is not called before renderHome; the theme would apply after the first screen already painted")
	}
}
