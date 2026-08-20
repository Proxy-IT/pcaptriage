// Package guide holds the in-app explanations of what each check means.
//
// The prose is authored content with the same status as the finding wording in
// RULES.md: it is implemented as written, and changes are proposed rather than
// applied. It is therefore not transcribed into Go source, where it could drift
// from the authored document without anything failing. The documents themselves
// are embedded and parsed, and a test asserts each embedded copy is
// byte-identical to its source at the repository root: GUIDE-CONTENT.md and,
// added in Batch 1, GUIDE-CONTENT-BATCH1.md.
//
// # One page, several rules
//
// Most pages document one rule. Batch 1 introduced the first exception: one
// page can serve several rules at once (the loss cluster's R05/R06/R07/R08
// share a page, because the four conditions are meant to be read as one
// picture — see GUIDE-CONTENT-BATCH1.md's own framing). A Page therefore
// carries RuleIDs, not a single RuleID, and a Section carries an optional
// Anchor: on a multi-rule page, each served rule has exactly one anchored
// section, which is what "arriving from a finding lands on that rule's part
// of the page" scrolls to. Single-rule pages have no anchors — landing at that
// rule's spot and landing at the top are the same place.
//
// # The two registers
//
// The guide and the finding cards speak differently, and the difference is
// load-bearing. A card states observations about *this capture* and never makes
// a causal claim. A guide page teaches a pattern in general, and may say what
// that pattern usually means — because it is describing the pattern, not the
// reader's capture. "Usually", "typically" and "often" are what keep general
// teaching from becoming a specific verdict, and a test bans verdict phrasing
// about the reader's own capture from guide prose.
package guide

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed content.md
var contentSource string

//go:embed content_batch1.md
var batch1Source string

//go:embed content_batch2.md
var batch2Source string

// Source returns the original embedded guide content, for the test that checks
// it against GUIDE-CONTENT.md.
func Source() string { return contentSource }

// Batch1Source returns the Batch 1 embedded guide content, for the test that
// checks it against GUIDE-CONTENT-BATCH1.md.
func Batch1Source() string { return batch1Source }

// Batch2Source returns the Batch 2 embedded guide content, for the test that
// checks it against GUIDE-CONTENT-BATCH2.md.
func Batch2Source() string { return batch2Source }

// allSources returns every embedded document in parse order, so a test that
// has to cover all of them cannot miss one by being written against a list of
// filenames that a later batch forgets to extend.
func allSources() []string {
	return []string{contentSource, batch1Source, batch2Source}
}

// Skeleton is the section order a single-rule guide page follows — R01, R04
// and R15 all have exactly this shape.
//
// The order is part of the specification, not a rendering preference: the
// anxious reader's answer is at the top and the depth is below, so a page that
// reordered these would defeat the structure. A multi-rule page (the loss
// cluster) does not follow this exact heading list — it has per-rule sections
// where a single-rule page has none — but keeps the same answer-first
// principle: see finishPage, which validates every page against that
// principle directly rather than against one hardcoded heading list.
var Skeleton = []string{
	"One-line summary",
	"What this usually means",
	"What it doesn't mean, and what this check can't tell you",
	"The pattern in a capture",
	"What to check next, in more depth",
}

// Inline is a run of text, optionally emphasised.
//
// Emphasis is carried through rather than flattened: the authored content uses
// it once, in "it can't say *why* the application isn't keeping up", where the
// stress is the point of the sentence. Runs are rendered as separate DOM nodes,
// so no markup is ever interpolated into the page.
type Inline struct {
	Text     string `json:"text"`
	Emphasis bool   `json:"emphasis,omitempty"`
}

// Block is a paragraph or a bullet list.
type Block struct {
	// Kind is "paragraph" or "bullets".
	Kind string `json:"kind"`
	// Runs is the paragraph's text, for Kind == "paragraph".
	Runs []Inline `json:"runs,omitempty"`
	// Items is one entry per bullet, for Kind == "bullets".
	Items [][]Inline `json:"items,omitempty"`
}

const (
	BlockParagraph = "paragraph"
	BlockBullets   = "bullets"
)

// Section is one headed part of a page.
type Section struct {
	Heading string  `json:"heading"`
	Blocks  []Block `json:"blocks"`
	// NeverCollapse marks the sections that must always be visible. The summary
	// and what the pattern usually means are the answer a mid-incident reader
	// came for; hiding either behind a click defeats the page.
	NeverCollapse bool `json:"never_collapse"`
	// Anchor is the in-page target for this section, non-empty only on a
	// multi-rule page's per-rule sections (e.g. "r06"). Arriving from a
	// finding for that rule scrolls here; arriving from the index does not.
	Anchor string `json:"anchor,omitempty"`
}

// Page is a guide page. Most document one rule; RuleIDs holds more than one
// entry only for a page like the loss cluster's, authored to be read as a
// single document.
type Page struct {
	RuleIDs  []string  `json:"rule_ids"`
	Title    string    `json:"title"`
	Sections []Section `json:"sections"`
}

// ServesRule reports whether this page documents ruleID.
func (p Page) ServesRule(ruleID string) bool {
	for _, id := range p.RuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

// Summary returns the one-line summary, which is the first section.
func (p Page) Summary() string {
	if len(p.Sections) == 0 {
		return ""
	}
	var b strings.Builder
	for _, blk := range p.Sections[0].Blocks {
		for _, r := range blk.Runs {
			b.WriteString(r.Text)
		}
	}
	return b.String()
}

var parsed []Page
var parseErr error

func init() {
	// One entry per authored document. Parsed separately so a failure names
	// the file it came from — the documents are specification, and "the guide
	// did not parse" is not enough to act on.
	for _, doc := range []struct {
		name string
		src  string
	}{
		{"GUIDE-CONTENT.md", contentSource},
		{"GUIDE-CONTENT-BATCH1.md", batch1Source},
		{"GUIDE-CONTENT-BATCH2.md", batch2Source},
	} {
		pages, err := parse(doc.src)
		if err != nil {
			parsed, parseErr = nil, fmt.Errorf("%s: %w", doc.name, err)
			return
		}
		parsed = append(parsed, pages...)
	}
}

// Pages returns every guide page, ordered by the page's first served rule ID.
func Pages() ([]Page, error) {
	if parseErr != nil {
		return nil, parseErr
	}
	out := append([]Page(nil), parsed...)
	sort.Slice(out, func(i, j int) bool { return out[i].RuleIDs[0] < out[j].RuleIDs[0] })
	return out, nil
}

// Lookup returns the page documenting a rule ID — the page containing it in
// RuleIDs, whether or not that page documents others too.
func Lookup(ruleID string) (Page, bool) {
	if parseErr != nil {
		return Page{}, false
	}
	for _, p := range parsed {
		if p.ServesRule(ruleID) {
			return p, true
		}
	}
	return Page{}, false
}

// ruleIDPattern matches a bare rule ID token, e.g. "R06".
var ruleIDPattern = regexp.MustCompile(`\bR\d{2}\b`)

// servesLinePattern matches the second heading line of a multi-rule page:
// "### (serves R05 · R06 · R07 · R08)".
var servesLinePattern = regexp.MustCompile(`^\(serves ((?:R\d{2})(?: · R\d{2})*)\)$`)

// anchorPrefixPattern matches an empty named anchor opening a section heading:
// "<a name=\"r06\"></a>Quick recovery ...".
var anchorPrefixPattern = regexp.MustCompile(`^<a name="([a-zA-Z0-9_-]+)"></a>`)

// parse reads one authored document into pages.
//
// Deliberately strict: an unexpected heading, a missing section, or sections out
// of order are errors rather than something to render around. The content is
// specification, so a mismatch means the code and the specification have
// diverged and that should be loud.
func parse(src string) ([]Page, error) {
	var pages []Page

	// Everything before the first page heading is front matter (the
	// two-registers rule, or Batch 1's structural note), which governs the
	// prose but is not itself a page.
	chunks := strings.Split(src, "\n## Guide page:")
	for _, chunk := range chunks[1:] {
		page, err := parsePage(chunk)
		if err != nil {
			return nil, err
		}
		pages = append(pages, page)
	}

	if len(pages) == 0 {
		return nil, fmt.Errorf("guide: no pages found in the authored content")
	}
	return pages, nil
}

func parsePage(chunk string) (Page, error) {
	lines := strings.Split(chunk, "\n")
	if len(lines) == 0 {
		return Page{}, fmt.Errorf("guide: empty page")
	}

	head := strings.TrimSpace(lines[0])
	ruleIDs, title := extractRuleIDs(head), ""
	bodyStart := 1

	switch len(ruleIDs) {
	case 1:
		// "RNN — Title" or "Title — RNN": the established single-rule form,
		// in either field order — R15's page reverses it relative to R01/R04,
		// and this is read from what is actually written, not assumed.
		rest := ruleIDPattern.ReplaceAllString(head, "")
		title = strings.Trim(rest, " —")

	case 0:
		// No rule ID on the title line: a multi-rule page states it on the
		// next line instead — "### (serves R05 · R06 · R07 · R08)".
		if len(lines) < 2 {
			return Page{}, fmt.Errorf("guide: page %q has no rule ID and no second line to find one on", head)
		}
		second := strings.TrimSpace(lines[1])
		second = strings.TrimSpace(strings.TrimPrefix(second, "###"))
		m := servesLinePattern.FindStringSubmatch(second)
		if m == nil {
			return Page{}, fmt.Errorf(
				"guide: page %q has no rule ID in its heading, and the next line %q is not a "+
					"\"(serves RNN · RNN ...)\" declaration", head, lines[1])
		}
		for _, id := range strings.Split(m[1], " · ") {
			ruleIDs = append(ruleIDs, id)
		}
		title = head
		bodyStart = 2

	default:
		return Page{}, fmt.Errorf("guide: page heading %q names more than one rule ID; "+
			"a multi-rule page states its rules on the following \"(serves ...)\" line instead", head)
	}

	if title == "" {
		return Page{}, fmt.Errorf("guide: page %q has no title", head)
	}
	for _, id := range ruleIDs {
		if len(id) != 3 || id[0] != 'R' {
			return Page{}, fmt.Errorf("guide: %q is not a rule ID", id)
		}
	}

	page := Page{RuleIDs: ruleIDs, Title: title}
	page.Sections = parseSectionBody(lines[bodyStart:])
	return finishPage(page)
}

// parseSectionBody parses the section/block content shared by every guide
// page — headings, paragraphs and bullets parse identically whether the page
// is about a rule or a concept. Only how a page's identity is established
// before this runs (extractRuleIDs vs a plain title line) and what gets
// validated after (finishPage vs finishConcept) differ between the two, which
// is exactly the split a concepts mechanism should not blur: this function
// stays ignorant of which kind of page called it.
func parseSectionBody(lines []string) []Section {
	var sections []Section

	var cur *Section
	flush := func() {
		if cur != nil {
			sections = append(sections, *cur)
			cur = nil
		}
	}

	var para []string
	var bullets []string
	closeBlocks := func() {
		if cur == nil {
			para, bullets = nil, nil
			return
		}
		if len(para) > 0 {
			cur.Blocks = append(cur.Blocks, Block{
				Kind: BlockParagraph,
				Runs: inlineRuns(strings.Join(para, " ")),
			})
			para = nil
		}
		if len(bullets) > 0 {
			blk := Block{Kind: BlockBullets}
			for _, b := range bullets {
				blk.Items = append(blk.Items, inlineRuns(b))
			}
			cur.Blocks = append(cur.Blocks, blk)
			bullets = nil
		}
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t")

		switch {
		case strings.HasPrefix(line, "### "):
			closeBlocks()
			flush()
			heading := strings.TrimSpace(strings.TrimPrefix(line, "### "))
			anchor := ""
			if m := anchorPrefixPattern.FindStringSubmatch(heading); m != nil {
				anchor = m[1]
				heading = strings.TrimSpace(heading[len(m[0]):])
			}
			cur = &Section{Heading: heading, Anchor: anchor}

		case strings.HasPrefix(line, "## "):
			// A stray heading at this level would mean the chunk boundary
			// (split on "\n## Guide page:") missed something; end the page
			// defensively rather than swallow it as prose. The caller's
			// validation is what turns a truncated result into a loud error.
			closeBlocks()
			flush()
			return sections

		case strings.TrimSpace(line) == "", strings.TrimSpace(line) == "---":
			// Blank lines end an open paragraph. "---" is the authored
			// divider between a page's sections — GUIDE-CONTENT-BATCH1.md's
			// loss page uses it between each rule's subsection, not only
			// between pages, so it cannot mean "end of page" here; the chunk
			// split on "\n## Guide page:" already found the true page
			// boundary before this loop ever runs.
			closeBlocks()

		case strings.HasPrefix(line, "- "):
			// A bullet starts; any open paragraph ends first.
			if len(para) > 0 {
				blkRuns := inlineRuns(strings.Join(para, " "))
				cur.Blocks = append(cur.Blocks, Block{Kind: BlockParagraph, Runs: blkRuns})
				para = nil
			}
			bullets = append(bullets, strings.TrimSpace(strings.TrimPrefix(line, "- ")))

		case strings.HasPrefix(raw, "  ") && len(bullets) > 0:
			// Continuation of the current bullet.
			bullets[len(bullets)-1] += " " + strings.TrimSpace(line)

		default:
			// Ordinary prose. A non-indented line after bullets starts a new
			// paragraph, which is how the authored content returns to prose
			// after a list.
			if len(bullets) > 0 {
				blk := Block{Kind: BlockBullets}
				for _, b := range bullets {
					blk.Items = append(blk.Items, inlineRuns(b))
				}
				cur.Blocks = append(cur.Blocks, blk)
				bullets = nil
			}
			para = append(para, strings.TrimSpace(line))
		}
	}

	closeBlocks()
	flush()
	return sections
}

// extractRuleIDs finds rule ID tokens in a heading line.
func extractRuleIDs(head string) []string {
	return ruleIDPattern.FindAllString(head, -1)
}

// finishPage validates a parsed page against the answer-first principle every
// page follows, whatever its exact heading list: the summary and what the
// pattern usually means lead, unhidden; the deep-dive check-next section
// closes it; every rule the page claims to serve has exactly one place in the
// document a reader arriving for that rule lands on.
func finishPage(p Page) (Page, error) {
	label := strings.Join(p.RuleIDs, "/")

	if len(p.Sections) < 3 {
		return Page{}, fmt.Errorf("guide: page %s has only %d sections, want at least 3", label, len(p.Sections))
	}
	if p.Sections[0].Heading != "One-line summary" {
		return Page{}, fmt.Errorf("guide: page %s section 0 is %q, want %q",
			label, p.Sections[0].Heading, "One-line summary")
	}
	if !strings.HasPrefix(p.Sections[1].Heading, "What this usually means") {
		return Page{}, fmt.Errorf("guide: page %s section 1 is %q, want it to start with %q",
			label, p.Sections[1].Heading, "What this usually means")
	}
	last := p.Sections[len(p.Sections)-1]
	if last.Heading != "What to check next, in more depth" {
		return Page{}, fmt.Errorf("guide: page %s's last section is %q, want %q",
			label, last.Heading, "What to check next, in more depth")
	}
	for i, s := range p.Sections {
		if len(s.Blocks) == 0 {
			return Page{}, fmt.Errorf("guide: page %s section %q is empty", label, s.Heading)
		}
		// The first two sections are the answer the reader came for.
		p.Sections[i].NeverCollapse = i < 2
	}

	// Anchors: a multi-rule page must give every served rule exactly one
	// landing spot; a single-rule page has no anchors to give, since landing
	// at "that rule's spot" and landing at the top are the same place there.
	anchored := map[string]int{}
	for _, s := range p.Sections {
		if s.Anchor != "" {
			anchored[strings.ToUpper(s.Anchor)]++
		}
	}
	if len(p.RuleIDs) == 1 {
		if len(anchored) != 0 {
			return Page{}, fmt.Errorf("guide: single-rule page %s has anchored sections; "+
				"anchors are only meaningful on a page serving several rules", label)
		}
		return p, nil
	}
	for _, id := range p.RuleIDs {
		switch anchored[id] {
		case 0:
			return Page{}, fmt.Errorf("guide: page %s serves %s but has no section anchored to it", label, id)
		case 1:
			// exactly right
		default:
			return Page{}, fmt.Errorf("guide: page %s has %d sections anchored to %s, want exactly 1",
				label, anchored[id], id)
		}
	}
	for anchor := range anchored {
		if !p.ServesRule(anchor) {
			return Page{}, fmt.Errorf("guide: page %s has a section anchored to %s, which it does not list as served",
				label, anchor)
		}
	}
	return p, nil
}

// inlineRuns splits authored text into plain and emphasised runs.
//
// Only single-asterisk emphasis is recognised, which is all the authored content
// uses. An unpaired asterisk is left as literal text rather than swallowed, so a
// typo in the source shows up as itself instead of silently eating a sentence.
func inlineRuns(text string) []Inline {
	var out []Inline
	rest := text
	for {
		open := strings.Index(rest, "*")
		if open < 0 {
			break
		}
		close := strings.Index(rest[open+1:], "*")
		if close < 0 {
			break
		}
		close += open + 1

		if open > 0 {
			out = append(out, Inline{Text: rest[:open]})
		}
		out = append(out, Inline{Text: rest[open+1 : close], Emphasis: true})
		rest = rest[close+1:]
	}
	if rest != "" {
		out = append(out, Inline{Text: rest})
	}
	if len(out) == 0 {
		out = []Inline{{Text: text}}
	}
	return out
}
