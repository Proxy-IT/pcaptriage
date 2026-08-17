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
// The severity palette landing in two places is the drift the BACKLOG names;
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

	// No custom-property declarations outside tokens.css. var(--x) references
	// are the point; `--x:` declarations are the violation.
	declaration := regexp.MustCompile(`--[a-zA-Z][a-zA-Z0-9-]*\s*:`)
	for name, css := range consumers {
		if decls := declaration.FindAllString(css, -1); len(decls) > 0 {
			t.Errorf("%s declares custom properties %v; tokens.css is the only place tokens are declared", name, decls)
		}
	}

	// Every hex colour the tokens define must be referenced through its token,
	// never restated. (Colours the tokens do not define — print-block
	// black-on-white, focus-ring rgba washes — are out of scope here.)
	hexes := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindAllString(tokensSource, -1)
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
	for _, want := range []string{
		"--sev-significant:", "--sev-worth-noting:", "--sev-informational:",
		"--ok:", "--page:", "--font:",
	} {
		if !strings.Contains(tokensSource, want) {
			t.Errorf("tokens.css does not declare %s", want)
		}
	}
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
