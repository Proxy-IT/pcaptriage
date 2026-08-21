package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// distPath returns a path under frontend/dist, located from the repository
// root the same way the preview harness finds it.
func distPath(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Dir(filepath.Dir(synth.FixtureDir()))
	return filepath.Join(root, "frontend", "dist", name)
}

// TestFrontendTokensAreByteIdentical is what makes "shared tokens" enforceable
// rather than aspirational.
//
// Go's embed cannot reach across package directories, so the app's copy of the
// tokens is a physical second file. This test is the reason that is safe: the
// same mechanism the guide uses for GUIDE-CONTENT.md. Editing one copy without
// the other fails here instead of drifting silently — which is exactly how the
// two palettes were kept in step before this file existed: by review, meaning
// eventually not at all.
func TestFrontendTokensAreByteIdentical(t *testing.T) {
	frontend, err := os.ReadFile(distPath(t, "tokens.css"))
	if err != nil {
		t.Fatal(err)
	}
	if string(frontend) != tokensSource {
		t.Error("frontend/dist/tokens.css differs from internal/report/tokens.css; " +
			"the two surfaces are no longer consuming the same tokens. " +
			"Copy the canonical internal/report/tokens.css over the frontend copy.")
	}
}

// TestTokensAreTheSingleSourceOfThePalette holds both consumer stylesheets to
// the contract their headers state: they declare no custom properties of their
// own, and no colour the tokens define appears in them as a literal.
//
// The severity palette landing in two places is the drift this guards against;
// this is the tripwire for it.
func TestTokensAreTheSingleSourceOfThePalette(t *testing.T) {
	appCSS, err := os.ReadFile(distPath(t, "app.css"))
	if err != nil {
		t.Fatal(err)
	}

	consumers := map[string]string{
		"internal/report/style.css": baseStyleSource,
		"frontend/dist/app.css":     string(appCSS),
	}

	// Comments stripped before any structural search over src: this
	// file's own header illustrates the dark-mode selectors and discusses
	// tokens by name in prose, and a comment-blind search cannot tell that
	// apart from a real declaration or a real selector. Two of the checks
	// below found exactly that the first time they ran, against this file's
	// own comments.
	src := stripCSSComments(tokensSource)

	// No custom-property declarations outside tokens.css. var(--x) references
	// are the point; `--x:` declarations are the violation.
	declaration := regexp.MustCompile(`--[a-zA-Z][a-zA-Z0-9-]*\s*:`)
	for name, css := range consumers {
		if decls := declaration.FindAllString(css, -1); len(decls) > 0 {
			t.Errorf("%s declares custom properties %v; tokens.css is the only place tokens are declared", name, decls)
		}
	}

	// Semantic-token discipline, the other direction: not just "no raw colour",
	// but "no reference to a token this file never declared". A rename that
	// misses a call site is exactly the failure this catches — var(--ink) left
	// behind after --ink became --ink-primary would resolve to nothing in a
	// real browser (a silently transparent colour), which no other test here
	// would notice, because none of them render the CSS.
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*--([a-zA-Z][a-zA-Z0-9-]*)\s*:`).FindAllStringSubmatch(src, -1) {
		declared[m[1]] = true
	}
	reference := regexp.MustCompile(`var\(\s*--([a-zA-Z][a-zA-Z0-9-]*)\s*[,)]`)
	for name, css := range consumers {
		seen := map[string]bool{}
		for _, m := range reference.FindAllStringSubmatch(css, -1) {
			tok := m[1]
			if declared[tok] || seen[tok] {
				continue
			}
			seen[tok] = true
			t.Errorf("%s references --%s, which tokens.css does not declare", name, tok)
		}
	}

	// Every hex colour the tokens define must be referenced through its token,
	// never restated. (Colours the tokens do not define — print-block
	// black-on-white, focus-ring rgba washes — are out of scope here.)
	// No raw colour anywhere in a consumer sheet, not merely no *restated*
	// token colour. The narrower rule let two rgba() literals live in app.css
	// unnoticed — a blue focus glow and a blue drop veil — which then had to be
	// found by eye when the accent changed hue, because nothing failed when the
	// palette moved out from under them. A colour worth writing is worth naming.
	//
	// The @media print block is the one exemption, and a real one: its
	// black-on-white is not a palette choice but the absence of one, picked so
	// a greyscale printer has something to work with.
	literal := regexp.MustCompile(`(?i)#[0-9a-f]{3,8}\b|\brgba?\(|\bhsla?\(`)
	for name, css := range consumers {
		for _, block := range outsidePrintBlocks(css) {
			if found := literal.FindAllString(block, -1); len(found) > 0 {
				t.Errorf("%s uses raw colour literals %v outside @media print; give them tokens and reference those",
					name, found)
			}
		}
	}

	hexes := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindAllString(src, -1)
	if len(hexes) < 15 {
		t.Fatalf("tokens.css defines only %d hex colours; the palette appears to have been emptied", len(hexes))
	}
	for name, css := range consumers {
		lower := strings.ToLower(css)
		for _, h := range hexes {
			if strings.Contains(lower, strings.ToLower(h)) {
				t.Errorf("%s restates the token colour %s as a literal; reference it through its var() instead", name, h)
			}
		}
	}

	// The signals this session exists for must actually be in the tokens, or
	// the two checks above pass vacuously.
	// These are semantic names — what a colour is *for* — not palette names.
	// That distinction is what lets a theme swap the values underneath without
	// touching a consumer sheet, and it is why there is no --cyan or --teal
	// below: a sheet asking for --cyan has already assumed it is on a dark
	// background, and would be wrong the moment it was not.
	for _, want := range []string{
		"--sev-significant:", "--sev-worth-noting:", "--sev-informational:",
		"--ok:", "--page:", "--surface:", "--font:",
		"--accent:", "--accent-strong:", "--accent-wash:", "--focus:", "--on-accent:",
		"--bar-surface:", "--bar-ink:", "--bar-accent:", "--bar-focus:",
		"--ink-primary:", "--ink-secondary:", "--ink-muted:", "--outline:",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("tokens.css does not declare %s", want)
		}
	}

	// No token named by an ordinal ("-2") either — the discipline the dark-mode
	// rename exists to establish. --ink-2 was the one token in this file that
	// failed the semantic-name rule for a different reason than a hue name
	// would: it said nothing about what the second ink was *for* until a
	// reader already knew the first one existed.
	if strings.Contains(src, "--ink-2:") {
		t.Error("tokens.css still declares --ink-2; it should be named for its role (--ink-secondary), not its ordinal")
	}
	if strings.Contains(src, "--axis:") {
		t.Error("tokens.css still declares --axis; it should be named for the role it is actually used in " +
			"throughout both sheets (--outline), not the one place it was first needed")
	}

	// And no palette-flavoured names, which is the shape the semantic layer is
	// defined against. A token called --cyan states a hue; a sheet consuming it
	// cannot be re-themed without either lying or being edited.
	for _, banned := range []string{
		"--cyan:", "--teal:", "--teal-deep:", "--blue:", "--red:",
		"--amber:", "--green:", "--white:", "--black:",
	} {
		if strings.Contains(src, banned) {
			t.Errorf("tokens.css declares %s, a palette name rather than a semantic one; "+
				"name what the colour is for, not what hue it happens to be", banned)
		}
	}
}

// outsidePrintBlocks returns the stylesheet split into the regions that are not
// inside an @media print block, brace-counted from each one. Enough for these
// two hand-written sheets; not a general CSS parser.
func outsidePrintBlocks(css string) []string {
	var out []string
	rest := css
	for {
		i := strings.Index(rest, "@media print")
		if i < 0 {
			return append(out, rest)
		}
		out = append(out, rest[:i])
		open := strings.IndexByte(rest[i:], '{')
		if open < 0 {
			return out
		}
		depth, j := 0, i+open
		for ; j < len(rest); j++ {
			if rest[j] == '{' {
				depth++
			} else if rest[j] == '}' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if j >= len(rest) {
			return out
		}
		rest = rest[j+1:]
	}
}

// TestDarkOverridesAgreeWithEachOther guards the one piece of duplication
// tokens.css carries on purpose.
//
// Plain CSS has no way to declare a themed value once and activate it from two
// selectors (the OS-preference media query and the explicit data-theme
// attribute) — the two blocks restate the same declarations. That is a
// hand-editing hazard with no other backstop: changing a hex in one block
// without the other would leave dark mode giving a different answer depending
// on whether the reader's OS prefers dark or they chose dark explicitly, and
// nothing about that would look wrong in either render alone.
func TestDarkOverridesAgreeWithEachOther(t *testing.T) {
	// Comments stripped first: the file's own header illustrates these two
	// selectors as a worked example, and a comment-blind search would find
	// that illustration — whose body is literally "..." — before the real
	// rule below it.
	src := stripCSSComments(tokensSource)

	media := declarationsIn(t, src,
		`@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\) \{`)
	explicit := declarationsIn(t, src, `:root\[data-theme="dark"\] \{`)

	if len(media) == 0 {
		t.Fatal("found no declarations in the @media (prefers-color-scheme: dark) block")
	}
	if len(explicit) == 0 {
		t.Fatal(`found no declarations in the :root[data-theme="dark"] block`)
	}

	for name, val := range media {
		if explicit[name] != val {
			t.Errorf("--%s is %q under @media dark but %q under [data-theme=dark]", name, val, explicit[name])
		}
	}
	for name, val := range explicit {
		if _, ok := media[name]; !ok {
			t.Errorf("--%s is declared under [data-theme=dark] (%q) but not under @media dark", name, val)
		}
	}
}

// stripCSSComments removes /* ... */ comments, non-greedily, so a structural
// search over the file cannot mistake a comment's illustrative example for the
// rule it is illustrating.
func stripCSSComments(css string) string {
	return regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, "")
}

// declarationsIn finds the first rule whose selector matches selectorPattern,
// brace-counts to its close, and returns its custom-property declarations as a
// name -> normalised-value map.
func declarationsIn(t *testing.T, css, selectorPattern string) map[string]string {
	t.Helper()

	sel := regexp.MustCompile(selectorPattern)
	loc := sel.FindStringIndex(css)
	if loc == nil {
		t.Fatalf("selector pattern %q not found", selectorPattern)
	}
	open := strings.IndexByte(css[loc[1]-1:], '{')
	if open < 0 {
		t.Fatalf("selector %q has no opening brace", selectorPattern)
	}
	start := loc[1] - 1 + open + 1

	depth := 1
	i := start
	for ; i < len(css) && depth > 0; i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	body := css[start : i-1]

	out := map[string]string{}
	for _, m := range regexp.MustCompile(`--([a-zA-Z][a-zA-Z0-9-]*)\s*:\s*([^;]+);`).FindAllStringSubmatch(body, -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}
	return out
}

// TestReportInlinesTheTokens checks the report's inlined stylesheet actually
// begins with the tokens — a report rendered without them would fall back to
// browser defaults for every colour, which no other test would notice.
func TestReportInlinesTheTokens(t *testing.T) {
	if !strings.Contains(StyleSheet(), "--sev-significant:") {
		t.Fatal("the report stylesheet does not contain the design tokens")
	}
	if !strings.HasPrefix(StyleSheet(), tokensSource) {
		t.Error("tokens must precede the report styles that reference them")
	}
}
