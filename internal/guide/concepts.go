package guide

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed content_concepts.md
var conceptsSource string

// ConceptsSource returns the embedded concepts content, for the test that
// checks it against GUIDE-CONTENT-CONCEPTS.md.
func ConceptsSource() string { return conceptsSource }

// Concept is background a reader needs regardless of which check produced a
// finding — what a badge means, not what a rule detects.
//
// This is deliberately not a Page with an empty RuleIDs. A concept has no
// rule ID, is not registry-derived, and takes no part in the rule bijection
// (GuideIndex's Entries, the built/planned counts, TestEveryBuiltRuleLinkActuallyNavigates) — special-casing
// two pages into the rule mechanism was the shape session-brief-evidence-quality.md
// asks not to build, so Concept gets its own type, its own parse path, and
// its own lookup, and the two never merge into one list anywhere they are
// consumed.
type Concept struct {
	// Slug is the stable identifier used to look this page up and to link to
	// it — see conceptSlugs for where it comes from.
	Slug     string    `json:"slug"`
	Title    string    `json:"title"`
	Sections []Section `json:"sections"`
}

// Summary returns the one-line summary, the first section.
//
// Duplicated from Page.Summary rather than shared: a helper generic enough to
// serve both types is exactly the content-type abstraction this package is
// avoiding for two pages. Three duplicated lines cost less than the
// abstraction would.
func (c Concept) Summary() string {
	if len(c.Sections) == 0 {
		return ""
	}
	var b strings.Builder
	for _, blk := range c.Sections[0].Blocks {
		for _, r := range blk.Runs {
			b.WriteString(r.Text)
		}
	}
	return b.String()
}

// conceptSlugs maps each concept page's authored title to its stable
// identifier.
//
// Hand-maintained rather than derived from the title text. The title is
// spec'd prose — GUIDE-CONTENT-CONCEPTS.md, implemented verbatim — and a
// slug is a code-side concern the content is not written to carry, the same
// reason a multi-rule page states its served rules on an explicit
// "(serves ...)" line rather than have the parser guess them from a title.
// Two entries today, one line each; a third concept page (capture
// completeness is named as plausible) costs a third line here, which is the
// price session-brief-evidence-quality.md accepts in exchange for not
// building a slug-derivation system for two pages.
var conceptSlugs = map[string]string{
	"How sure the tool is — confirmed and inferred": "evidence-quality",
	"What the tool ranks first — severity":          "severity",
}

var parsedConcepts []Concept
var conceptParseErr error

func init() {
	concepts, err := parseConcepts(conceptsSource)
	if err != nil {
		conceptParseErr = fmt.Errorf("GUIDE-CONTENT-CONCEPTS.md: %w", err)
		return
	}
	parsedConcepts = concepts
}

// Concepts returns every concept page, ordered by slug — the two entries
// today sort as evidence-quality, severity, which also happens to be their
// authored order; the sort is what keeps that from being an accident a third
// page could silently break.
func Concepts() ([]Concept, error) {
	if conceptParseErr != nil {
		return nil, conceptParseErr
	}
	out := append([]Concept(nil), parsedConcepts...)
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// LookupConcept returns the concept page identified by slug.
func LookupConcept(slug string) (Concept, bool) {
	if conceptParseErr != nil {
		return Concept{}, false
	}
	for _, c := range parsedConcepts {
		if c.Slug == slug {
			return c, true
		}
	}
	return Concept{}, false
}

// parseConcepts reads the concepts document into pages.
//
// Splits on the same "## Guide page:" boundary the rule documents use — the
// authored heading convention is shared even though what identifies a page
// after that boundary is not (a title, not a rule ID).
func parseConcepts(src string) ([]Concept, error) {
	var concepts []Concept
	chunks := strings.Split(src, "\n## Guide page:")
	for _, chunk := range chunks[1:] {
		c, err := parseConceptPage(chunk)
		if err != nil {
			return nil, err
		}
		concepts = append(concepts, c)
	}
	if len(concepts) == 0 {
		return nil, fmt.Errorf("guide: no concept pages found in the authored content")
	}
	return concepts, nil
}

func parseConceptPage(chunk string) (Concept, error) {
	lines := strings.Split(chunk, "\n")
	if len(lines) == 0 {
		return Concept{}, fmt.Errorf("guide: empty concept page")
	}

	title := strings.TrimSpace(lines[0])
	if title == "" {
		return Concept{}, fmt.Errorf("guide: concept page has no title")
	}
	slug, known := conceptSlugs[title]
	if !known {
		return Concept{}, fmt.Errorf(
			"guide: concept page %q has no entry in conceptSlugs — a new or renamed concept page "+
				"needs a slug added there", title)
	}

	c := Concept{Slug: slug, Title: title}
	c.Sections = parseSectionBody(lines[1:])
	return finishConcept(c)
}

// finishConcept validates a concept page against the answer-first principle
// rule pages follow too — the summary leads and never collapses — without
// the rule-specific half of finishPage's checks: no RuleIDs to validate
// anchors against, and no anchors expected at all, since nothing ever lands
// on a concept page from a specific rule.
func finishConcept(c Concept) (Concept, error) {
	if len(c.Sections) < 2 {
		return Concept{}, fmt.Errorf("guide: concept page %q has only %d sections, want at least 2",
			c.Title, len(c.Sections))
	}
	if c.Sections[0].Heading != "One-line summary" {
		return Concept{}, fmt.Errorf("guide: concept page %q section 0 is %q, want %q",
			c.Title, c.Sections[0].Heading, "One-line summary")
	}
	for i, s := range c.Sections {
		if len(s.Blocks) == 0 {
			return Concept{}, fmt.Errorf("guide: concept page %q section %q is empty", c.Title, s.Heading)
		}
		if s.Anchor != "" {
			return Concept{}, fmt.Errorf("guide: concept page %q section %q has an anchor; "+
				"concept pages are never landed on for a specific rule, so anchors have nothing to mean here",
				c.Title, s.Heading)
		}
		c.Sections[i].NeverCollapse = i < 2
	}
	return c, nil
}
