package guide

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoFile resolves a file at the repository root.
func repoFile(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the repository root")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(file))), name)
}

// TestEmbeddedContentMatchesTheSpec is what makes "verbatim" enforceable rather
// than aspirational, for both authored documents.
//
// The authored documents live at the repository root; Go cannot embed above its
// own package, so the package carries a copy of each. This asserts every copy is
// byte-identical, so an edit to one and not the other fails here instead of
// shipping prose nobody approved.
func TestEmbeddedContentMatchesTheSpec(t *testing.T) {
	cases := []struct {
		name     string
		specFile string
		embedded string
	}{
		{"GUIDE-CONTENT.md", "GUIDE-CONTENT.md", Source()},
		{"GUIDE-CONTENT-BATCH1.md", "GUIDE-CONTENT-BATCH1.md", Batch1Source()},
		{"GUIDE-CONTENT-BATCH2.md", "GUIDE-CONTENT-BATCH2.md", Batch2Source()},
		// Concepts is a different type from Page and never appears in Pages(),
		// but the embed-and-compare mechanism this test checks does not care
		// what the content parses into — it is the same property regardless.
		{"GUIDE-CONTENT-CONCEPTS.md", "GUIDE-CONTENT-CONCEPTS.md", ConceptsSource()},
	}
	for _, c := range cases {
		want, err := os.ReadFile(repoFile(t, c.specFile))
		if err != nil {
			t.Fatal(err)
		}
		if c.embedded != string(want) {
			t.Errorf("internal/guide's copy of %s has drifted from the root file.\n"+
				"embedded %d bytes, authored %d bytes — copy the authored file over the "+
				"embedded one; never the other way round, the root file is the specification",
				c.name, len(c.embedded), len(want))
		}
	}
}

// TestPagesFollowAnswerFirst checks the structural half of the spec that holds
// across every page shape: the summary and what the pattern usually means lead
// and never collapse, and the deep-dive check-next section closes the page.
// Batch 1 introduced a page shape (the loss cluster's) that does not repeat
// R01/R04's exact five-heading list — see finishPage — so this checks the
// principle the shapes share, not one fixed list.
func TestPagesFollowAnswerFirst(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatalf("the authored content did not parse: %v", err)
	}
	// R01 and R04 (GUIDE-CONTENT.md), the loss cluster and R15 (BATCH1), the
	// connecting and ending pairs (BATCH2): six Page values, eleven rules
	// served between them.
	if len(pages) != 6 {
		t.Fatalf("got %d pages, want 6 (R01, R04, loss cluster, R15, R02/R03, R09/R14)", len(pages))
	}

	var servedTotal int
	for _, p := range pages {
		label := strings.Join(p.RuleIDs, "/")
		if p.Title == "" {
			t.Errorf("%s has no title", label)
		}
		servedTotal += len(p.RuleIDs)

		if p.Sections[0].Heading != "One-line summary" {
			t.Errorf("%s section 0 = %q, want %q", label, p.Sections[0].Heading, "One-line summary")
		}
		if !strings.HasPrefix(p.Sections[1].Heading, "What this usually means") {
			t.Errorf("%s section 1 = %q, want it to start with %q", label, p.Sections[1].Heading, "What this usually means")
		}
		last := p.Sections[len(p.Sections)-1]
		if last.Heading != "What to check next, in more depth" {
			t.Errorf("%s last section = %q, want %q", label, last.Heading, "What to check next, in more depth")
		}
		for _, s := range p.Sections {
			if len(s.Blocks) == 0 {
				t.Errorf("%s section %q parsed to nothing", label, s.Heading)
			}
		}
		if !p.Sections[0].NeverCollapse || !p.Sections[1].NeverCollapse {
			t.Errorf("%s: the summary and 'usually means' sections must never collapse", label)
		}
		if p.Summary() == "" {
			t.Errorf("%s has an empty one-line summary", label)
		}
	}
	if servedTotal != 11 {
		t.Errorf("pages serve %d rules between them, want 11 — every built rule", servedTotal)
	}
}

// TestOriginalPagesMatchTheirSkeleton pins R01 and R04 — the two pages that
// predate Batch 1 — to the original fixed heading list, byte for byte,
// unchanged by the multi-rule addition alongside them.
func TestOriginalPagesMatchTheirSkeleton(t *testing.T) {
	for _, id := range []string{"R01", "R04"} {
		p, ok := Lookup(id)
		if !ok {
			t.Fatalf("%s has no guide page", id)
		}
		if len(p.Sections) != len(Skeleton) {
			t.Fatalf("%s has %d sections, want the original %d-section skeleton", id, len(p.Sections), len(Skeleton))
		}
		for i, s := range p.Sections {
			if s.Heading != Skeleton[i] {
				t.Errorf("%s section %d = %q, want %q", id, i, s.Heading, Skeleton[i])
			}
		}
	}
}

// TestR15HasItsOwnShapeWithoutAnchors documents that R15's page — single-rule,
// like R01 and R04, but authored with a different heading list ("What the
// individual notices mean" instead of "The pattern in a capture") — is real,
// not a parsing defect, and carries no anchors, same as every single-rule page.
func TestR15HasItsOwnShapeWithoutAnchors(t *testing.T) {
	p, ok := Lookup("R15")
	if !ok {
		t.Fatal("R15 has no guide page")
	}
	want := []string{
		"One-line summary",
		"What this usually means",
		"What the individual notices mean",
		"What it doesn't mean, and what this check can't tell you",
		"What to check next, in more depth",
	}
	if len(p.Sections) != len(want) {
		t.Fatalf("R15 has %d sections, want %d: %v", len(p.Sections), len(want), want)
	}
	for i, s := range p.Sections {
		if s.Heading != want[i] {
			t.Errorf("R15 section %d = %q, want %q", i, s.Heading, want[i])
		}
		if s.Anchor != "" {
			t.Errorf("R15 section %q has anchor %q; single-rule pages should have none", s.Heading, s.Anchor)
		}
	}
}

// TestMultiRulePageHasOneAnchorPerServedRule is the bijection the loss page
// depends on: every rule it claims to serve has exactly one landing spot in
// the document, in served order, and no anchor points at a rule the page does
// not claim.
func TestMultiRulePageHasOneAnchorPerServedRule(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}

	// The three pages that serve more than one rule, and exactly which rules
	// each is expected to carry — so a page quietly losing or gaining one is
	// a failure rather than something this test adapts to.
	want := map[string][]string{
		"Packet loss, retransmission, and reordering": {"R05", "R06", "R07", "R08"},
		"Connecting — and failing to connect":         {"R02", "R03"},
		"Connections that end early, or too often":    {"R09", "R14"},
	}

	seen := map[string]bool{}
	for i := range pages {
		p := &pages[i]
		if len(p.RuleIDs) == 1 {
			continue
		}
		expect, known := want[p.Title]
		if !known {
			t.Errorf("unexpected multi-rule page %q serving %v", p.Title, p.RuleIDs)
			continue
		}
		seen[p.Title] = true

		if len(p.RuleIDs) != len(expect) {
			t.Errorf("%q serves %v, want %v", p.Title, p.RuleIDs, expect)
		}
		for _, id := range expect {
			if !p.ServesRule(id) {
				t.Errorf("%q does not list %s as served", p.Title, id)
			}
		}

		anchored := map[string]int{}
		for _, s := range p.Sections {
			if s.Anchor == "" {
				continue
			}
			anchored[strings.ToUpper(s.Anchor)]++
		}
		for _, id := range p.RuleIDs {
			if anchored[id] != 1 {
				t.Errorf("%s has %d anchored sections in %q, want exactly 1", id, anchored[id], p.Title)
			}
		}
		for anchor := range anchored {
			if !p.ServesRule(anchor) {
				t.Errorf("%q has an anchor pointing at %s, which it does not list as served", p.Title, anchor)
			}
		}
	}

	for title := range want {
		if !seen[title] {
			t.Errorf("the multi-rule page %q is missing entirely", title)
		}
	}
}

// TestProseIsVerbatim spot-checks that parsing reproduces the authored
// sentences rather than paraphrasing or dropping them, across both documents.
func TestProseIsVerbatim(t *testing.T) {
	// Compared against every embedded source, whose byte-identity to the
	// authored files at the repository root is proven by
	// TestEmbeddedContentMatchesTheSpec. Taking them from allSources rather
	// than naming files here means a document added to the parser cannot be
	// left out of this check by omission.
	var flat string
	for _, src := range allSources() {
		flat += flattenWhitespace(src) + " "
	}

	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}

	var checked int
	for _, p := range pages {
		label := strings.Join(p.RuleIDs, "/")
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
							label, s.Heading, txt)
					}
				case BlockBullets:
					for _, item := range blk.Items {
						checked++
						if txt := flattenWhitespace(runsSource(item)); !strings.Contains(flat, txt) {
							t.Errorf("%s / %s: bullet is not present verbatim in the spec:\n  %q",
								label, s.Heading, txt)
						}
					}
				default:
					t.Errorf("unknown block kind %q", blk.Kind)
				}
			}
		}
	}
	if checked < 40 {
		t.Errorf("only %d blocks checked; the parse is probably dropping content", checked)
	}
}

// TestEmphasisIsCarriedNotFlattened checks the one place the original content
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

// TestBatch1EmphasisIsCarried checks the same property against the new
// document's own uses of emphasis (the loss page and the R15 page both use
// it), so the round-trip is proven on Batch 1's content too, not only R01's.
func TestBatch1EmphasisIsCarried(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range pages {
		if len(p.RuleIDs) == 1 && p.RuleIDs[0] == "R01" {
			continue // covered by TestEmphasisIsCarriedNotFlattened
		}
		for _, s := range p.Sections {
			for _, blk := range s.Blocks {
				for _, r := range blk.Runs {
					if r.Emphasis {
						found = true
					}
				}
				for _, item := range blk.Items {
					for _, r := range item {
						if r.Emphasis {
							found = true
						}
					}
				}
			}
		}
	}
	if !found {
		t.Error("no emphasis run found anywhere in Batch 1's pages; GUIDE-CONTENT-BATCH1.md uses *removes* and " +
			"*questions* — the round-trip may be silently dropping emphasis")
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
// content itself asks for, run over every page — Batch 1's included.
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
		label := strings.Join(p.RuleIDs, "/")
		body := strings.ToLower(pageText(p))
		for _, phrase := range banned {
			if strings.Contains(body, phrase) {
				t.Errorf("%s guide prose contains verdict phrasing %q", label, phrase)
			}
		}

		// The hedges are load-bearing: they are what make general teaching
		// something other than a specific verdict.
		if !strings.Contains(body, "usually") && !strings.Contains(body, "typically") {
			t.Errorf("%s guide prose contains no hedging language, which is what keeps "+
				"a general explanation from reading as a verdict", label)
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
