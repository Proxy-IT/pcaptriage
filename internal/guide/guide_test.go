package guide

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// specPath resolves GUIDE-CONTENT.md at the repository root.
func specPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the repository root")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(file))), "GUIDE-CONTENT.md")
}

// TestEmbeddedContentMatchesTheSpec is what makes "verbatim" enforceable rather
// than aspirational.
//
// The authored document lives at the repository root; Go cannot embed above its
// own package, so the package carries a copy. This asserts the copy is
// byte-identical, so an edit to one and not the other fails here instead of
// shipping prose nobody approved.
func TestEmbeddedContentMatchesTheSpec(t *testing.T) {
	want, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if Source() != string(want) {
		t.Errorf("internal/guide/content.md has drifted from GUIDE-CONTENT.md.\n"+
			"embedded %d bytes, authored %d bytes — copy the authored file over the "+
			"embedded one; never the other way round, the root file is the specification",
			len(Source()), len(want))
	}
}

// TestPagesParseWithTheRequiredSkeleton checks the structural half of the spec.
// The section order is the answer-first design; a page that reordered it would
// bury the answer a mid-incident reader came for.
func TestPagesParseWithTheRequiredSkeleton(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatalf("the authored content did not parse: %v", err)
	}
	if len(pages) != 2 {
		t.Fatalf("got %d pages, want 2 (R01 and R04)", len(pages))
	}

	for _, p := range pages {
		if p.Title == "" {
			t.Errorf("%s has no title", p.RuleID)
		}
		if len(p.Sections) != len(Skeleton) {
			t.Fatalf("%s has %d sections, want %d", p.RuleID, len(p.Sections), len(Skeleton))
		}
		for i, s := range p.Sections {
			if s.Heading != Skeleton[i] {
				t.Errorf("%s section %d = %q, want %q", p.RuleID, i, s.Heading, Skeleton[i])
			}
			if len(s.Blocks) == 0 {
				t.Errorf("%s section %q parsed to nothing", p.RuleID, s.Heading)
			}
		}
		// The summary and what it usually means are the answer; they never hide.
		if !p.Sections[0].NeverCollapse || !p.Sections[1].NeverCollapse {
			t.Errorf("%s: the summary and 'usually means' sections must never collapse", p.RuleID)
		}
		if p.Summary() == "" {
			t.Errorf("%s has an empty one-line summary", p.RuleID)
		}
	}
}

// TestProseIsVerbatim spot-checks that parsing reproduces the authored sentences
// rather than paraphrasing or dropping them.
func TestProseIsVerbatim(t *testing.T) {
	spec, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatal(err)
	}
	flat := flattenWhitespace(string(spec))

	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}

	var checked int
	for _, p := range pages {
		for _, s := range p.Sections {
			for _, blk := range s.Blocks {
				switch blk.Kind {
				// Compared in source form — emphasis markers restored — so this
				// asserts the parse round-trips rather than that the rendered
				// text happens to appear in the document.
				case BlockParagraph:
					checked++
					if txt := flattenWhitespace(runsSource(blk.Runs)); !strings.Contains(flat, txt) {
						t.Errorf("%s / %s: paragraph is not present verbatim in the spec:\n  %q",
							p.RuleID, s.Heading, txt)
					}
				case BlockBullets:
					for _, item := range blk.Items {
						checked++
						if txt := flattenWhitespace(runsSource(item)); !strings.Contains(flat, txt) {
							t.Errorf("%s / %s: bullet is not present verbatim in the spec:\n  %q",
								p.RuleID, s.Heading, txt)
						}
					}
				default:
					t.Errorf("unknown block kind %q", blk.Kind)
				}
			}
		}
	}
	if checked < 20 {
		t.Errorf("only %d blocks checked; the parse is probably dropping content", checked)
	}
}

// TestEmphasisIsCarriedNotFlattened checks the one place the authored content
// uses emphasis. Dropping it would change a sentence whose whole point is the
// stress on one word.
func TestEmphasisIsCarriedNotFlattened(t *testing.T) {
	p, ok := Lookup("R01")
	if !ok {
		t.Fatal("R01 has no guide page")
	}

	var found bool
	for _, s := range p.Sections {
		for _, blk := range s.Blocks {
			for _, item := range blk.Items {
				for _, r := range item {
					if r.Emphasis && r.Text == "why" {
						found = true
					}
					if strings.Contains(r.Text, "*") {
						t.Errorf("an asterisk survived into rendered text: %q", r.Text)
					}
				}
			}
			for _, r := range blk.Runs {
				if strings.Contains(r.Text, "*") {
					t.Errorf("an asterisk survived into rendered text: %q", r.Text)
				}
			}
		}
	}
	if !found {
		t.Error(`R01's "it can't say *why*" emphasis was not carried through`)
	}
}

// TestInlineRuns covers the transform directly, including the malformed cases.
func TestInlineRuns(t *testing.T) {
	cases := []struct {
		in   string
		want []Inline
	}{
		{"plain text", []Inline{{Text: "plain text"}}},
		{"say *why* it is", []Inline{{Text: "say "}, {Text: "why", Emphasis: true}, {Text: " it is"}}},
		{"*leading* rest", []Inline{{Text: "leading", Emphasis: true}, {Text: " rest"}}},
		// An unpaired asterisk stays literal rather than eating the sentence.
		{"unpaired * asterisk", []Inline{{Text: "unpaired * asterisk"}}},
	}
	for _, c := range cases {
		got := inlineRuns(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%q -> %d runs, want %d: %+v", c.in, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q run %d = %+v, want %+v", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestGuideProseKeepsTheTwoRegistersApart is the posture test the authored
// content itself asks for.
//
// Guide pages may say what a pattern usually means. They may not say what is
// happening in the reader's capture — that is the card's job, and the card does
// not do it either.
func TestGuideProseKeepsTheTwoRegistersApart(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}

	// From GUIDE-CONTENT.md's own instruction: ban verdict phrasing about the
	// reader's own capture.
	banned := []string{
		"your server is", "your network is", "this means your",
		"your application is", "your capture shows", "you have a problem",
		"the cause is", "this proves", "definitely",
	}

	for _, p := range pages {
		body := strings.ToLower(pageText(p))
		for _, phrase := range banned {
			if strings.Contains(body, phrase) {
				t.Errorf("%s guide prose contains verdict phrasing %q", p.RuleID, phrase)
			}
		}

		// The hedges are load-bearing: they are what make general teaching
		// something other than a specific verdict.
		if !strings.Contains(body, "usually") && !strings.Contains(body, "typically") {
			t.Errorf("%s guide prose contains no hedging language, which is what keeps "+
				"a general explanation from reading as a verdict", p.RuleID)
		}
	}
}

// runsSource re-emits the authored form, emphasis markers included, so a
// verbatim comparison against the document is exact.
func runsSource(runs []Inline) string {
	var b strings.Builder
	for _, r := range runs {
		if r.Emphasis {
			b.WriteString("*" + r.Text + "*")
			continue
		}
		b.WriteString(r.Text)
	}
	return b.String()
}

func runsText(runs []Inline) string {
	var b strings.Builder
	for _, r := range runs {
		b.WriteString(r.Text)
	}
	return b.String()
}

func pageText(p Page) string {
	var b strings.Builder
	b.WriteString(p.Title)
	for _, s := range p.Sections {
		b.WriteString(" " + s.Heading + " ")
		for _, blk := range s.Blocks {
			b.WriteString(" " + runsText(blk.Runs))
			for _, item := range blk.Items {
				b.WriteString(" " + runsText(item))
			}
		}
	}
	return b.String()
}

func flattenWhitespace(s string) string { return strings.Join(strings.Fields(s), " ") }
