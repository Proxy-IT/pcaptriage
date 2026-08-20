package guide

import (
	"strings"
	"testing"
)

// TestConceptsFollowAnswerFirst is TestPagesFollowAnswerFirst's counterpart:
// the same answer-first principle (summary leads, never collapses), checked
// against Concepts() rather than Pages(). A separate test rather than folding
// concepts into the rule-page loop, because that loop's exact invariants
// (section 1 starts "What this usually means", the last section is "What to
// check next, in more depth") are rule-page conventions the concept pages do
// not follow and are not asked to.
func TestConceptsFollowAnswerFirst(t *testing.T) {
	concepts, err := Concepts()
	if err != nil {
		t.Fatalf("the concepts content did not parse: %v", err)
	}
	if len(concepts) != 2 {
		t.Fatalf("got %d concepts, want 2 (evidence-quality, severity)", len(concepts))
	}

	for _, c := range concepts {
		if c.Title == "" {
			t.Errorf("%s has no title", c.Slug)
		}
		if c.Sections[0].Heading != "One-line summary" {
			t.Errorf("%s section 0 = %q, want %q", c.Slug, c.Sections[0].Heading, "One-line summary")
		}
		if !c.Sections[0].NeverCollapse || !c.Sections[1].NeverCollapse {
			t.Errorf("%s: the summary and the section after it must never collapse", c.Slug)
		}
		for _, s := range c.Sections {
			if len(s.Blocks) == 0 {
				t.Errorf("%s section %q parsed to nothing", c.Slug, s.Heading)
			}
			if s.Anchor != "" {
				t.Errorf("%s section %q has an anchor; concept pages carry none", c.Slug, s.Heading)
			}
		}
		if c.Summary() == "" {
			t.Errorf("%s has an empty one-line summary", c.Slug)
		}
	}
}

// TestConceptSlugsAreStable pins the two identifiers Part 2's badge links
// depend on. A slug is a URL-shaped commitment once something links to it —
// this is what makes an accidental rename in conceptSlugs (or in the authored
// title, which conceptSlugs would then fail to recognise) a test failure
// rather than a silently broken link discovered later.
func TestConceptSlugsAreStable(t *testing.T) {
	for _, want := range []string{"evidence-quality", "severity"} {
		if _, ok := LookupConcept(want); !ok {
			t.Errorf("no concept page has slug %q", want)
		}
	}
}

// TestEveryConceptIsReachableFromLookup is the concept side of the bijection
// every guide page holds: Concepts() and LookupConcept must agree on what
// exists, in both directions — nothing Concepts() lists is unreachable by its
// own slug, and nothing reachable is missing from the list. The other half of
// this bijection — reachable from a badge link — is Part 2's, once badges
// exist to check.
func TestEveryConceptIsReachableFromLookup(t *testing.T) {
	concepts, err := Concepts()
	if err != nil {
		t.Fatal(err)
	}
	if len(concepts) == 0 {
		t.Fatal("no concepts registered")
	}
	for _, c := range concepts {
		got, ok := LookupConcept(c.Slug)
		if !ok {
			t.Errorf("Concepts() lists slug %q but LookupConcept cannot find it", c.Slug)
			continue
		}
		if got.Title != c.Title {
			t.Errorf("LookupConcept(%q).Title = %q, want %q", c.Slug, got.Title, c.Title)
		}
	}
}

// TestConceptProseIsVerbatim is TestProseIsVerbatim's counterpart, run
// against ConceptsSource() rather than allSources() — a separate check
// because Concepts() is a separate parse path from Pages(), not because the
// property being checked (parsing reproduces the authored sentences) is any
// different.
func TestConceptProseIsVerbatim(t *testing.T) {
	flat := flattenWhitespace(ConceptsSource())

	concepts, err := Concepts()
	if err != nil {
		t.Fatal(err)
	}

	var checked int
	for _, c := range concepts {
		for _, s := range c.Sections {
			for _, blk := range s.Blocks {
				switch blk.Kind {
				case BlockParagraph:
					checked++
					if txt := flattenWhitespace(runsSource(blk.Runs)); !strings.Contains(flat, txt) {
						t.Errorf("%s / %s: paragraph is not present verbatim in the spec:\n  %q",
							c.Slug, s.Heading, txt)
					}
				case BlockBullets:
					for _, item := range blk.Items {
						checked++
						if txt := flattenWhitespace(runsSource(item)); !strings.Contains(flat, txt) {
							t.Errorf("%s / %s: bullet is not present verbatim in the spec:\n  %q",
								c.Slug, s.Heading, txt)
						}
					}
				default:
					t.Errorf("unknown block kind %q", blk.Kind)
				}
			}
		}
	}
	if checked < 15 {
		t.Errorf("only %d blocks checked; the parse is probably dropping content", checked)
	}
}

// TestConceptProseKeepsTheTwoRegistersApart is TestGuideProseKeepsTheTwoRegistersApart's
// counterpart: the brief's own two-register rule applies to this document too
// (GUIDE-CONTENT-CONCEPTS.md says so explicitly), and concept prose has the
// same chance to slip into verdict phrasing rule prose does — "a serious
// problem" is one paragraph away from "your problem" if a future edit is not
// careful.
func TestConceptProseKeepsTheTwoRegistersApart(t *testing.T) {
	concepts, err := Concepts()
	if err != nil {
		t.Fatal(err)
	}

	banned := []string{
		"your server is", "your network is", "this means your",
		"your application is", "your capture shows", "you have a problem",
		"the cause is", "this proves", "definitely",
	}

	for _, c := range concepts {
		body := strings.ToLower(conceptText(c))
		for _, phrase := range banned {
			if strings.Contains(body, phrase) {
				t.Errorf("%s concept prose contains verdict phrasing %q", c.Slug, phrase)
			}
		}
	}
}

func conceptText(c Concept) string {
	var b strings.Builder
	b.WriteString(c.Title)
	for _, s := range c.Sections {
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
