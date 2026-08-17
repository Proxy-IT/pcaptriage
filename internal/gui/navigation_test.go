package gui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
