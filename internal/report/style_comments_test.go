package report

import (
	"regexp"
	"strings"
	"testing"
)

// TestExportStylesheetCommentsDoNotSwallowRules is the export-side twin of
// internal/gui's TestStylesheetCommentsDoNotSwallowRules, and exists for the
// same reason: a CSS comment containing a star followed by a slash closes
// early, and the parser then discards whole rules while the sheet still loads
// and everything else still applies.
//
// That happened once already, in app.css, to a comment naming the selectors
// ".tag-sev-*" and ".tag-confirmed" together. The export's stylesheet is
// commented in the same voice and names the same selectors, so it has the same
// exposure — and less chance of being noticed, since nobody opens an exported
// report to check its CSS parsed.
func TestExportStylesheetCommentsDoNotSwallowRules(t *testing.T) {
	// styleSource, not baseStyleSource: the tokens are prepended into the same
	// sheet, so a comment that closes early in either half can swallow a rule
	// from the other.
	src := styleSource

	// Strip comments the way a parser resolves them: the first "*/" after a
	// "/*" ends it, wherever that lands.
	stripped := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")

	if strings.Contains(stripped, "*/") {
		t.Error("the export stylesheet has an unbalanced */ after comment stripping — a comment " +
			"closed early and the declarations after it are being parsed as CSS")
	}

	// The selectors whose loss would be silent in a document nobody inspects.
	for _, sel := range []string{".basis-inferred", ".basis-label", ".tag-inferred", ".tag-sev-significant"} {
		if !strings.Contains(stripped, sel) {
			t.Errorf("the export stylesheet declares no %s outside a comment; the rule is either "+
				"missing or swallowed by a comment that closed early", sel)
		}
	}
}
