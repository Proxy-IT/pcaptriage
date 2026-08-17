// Package guide holds the in-app explanations of what each check means.
//
// The prose is authored content with the same status as the finding wording in
// RULES.md: it is implemented as written, and changes are proposed rather than
// applied. It is therefore not transcribed into Go source, where it could drift
// from the authored document without anything failing. The document itself is
// embedded and parsed, and a test asserts the embedded copy is byte-identical to
// GUIDE-CONTENT.md at the repository root.
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
	"sort"
	"strings"
)

//go:embed content.md
var contentSource string

// Source returns the embedded guide content, for the test that checks it against
// the authored document.
func Source() string { return contentSource }

// Skeleton is the section order every guide page follows.
//
// The order is part of the specification, not a rendering preference: the
// anxious reader's answer is at the top and the depth is below, so a page that
// reordered these would defeat the structure. Parsing fails rather than
// silently accepting a page that does not match.
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
}

// Page is the guide entry for one rule.
type Page struct {
	RuleID   string    `json:"rule_id"`
	Title    string    `json:"title"`
	Sections []Section `json:"sections"`
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

func init() { parsed, parseErr = parse(contentSource) }

// Pages returns every guide page, ordered by rule ID.
func Pages() ([]Page, error) {
	if parseErr != nil {
		return nil, parseErr
	}
	out := append([]Page(nil), parsed...)
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out, nil
}

// Lookup returns the page for a rule ID.
func Lookup(ruleID string) (Page, bool) {
	if parseErr != nil {
		return Page{}, false
	}
	for _, p := range parsed {
		if p.RuleID == ruleID {
			return p, true
		}
	}
	return Page{}, false
}

// parse reads the authored document into pages.
//
// Deliberately strict: an unexpected heading, a missing section, or sections out
// of order are errors rather than something to render around. The content is
// specification, so a mismatch means the code and the specification have
// diverged and that should be loud.
func parse(src string) ([]Page, error) {
	var pages []Page

	// Everything before the first page heading is the two-registers rule, which
	// governs the prose but is not itself a page.
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

	// "R01 — Receiver stopped accepting data (zero window)"
	head := strings.TrimSpace(lines[0])
	id, title, ok := strings.Cut(head, "—")
	if !ok {
		return Page{}, fmt.Errorf("guide: page heading %q is not of the form 'RNN — Title'", head)
	}
	page := Page{
		RuleID: strings.TrimSpace(id),
		Title:  strings.TrimSpace(title),
	}
	if len(page.RuleID) != 3 || page.RuleID[0] != 'R' {
		return Page{}, fmt.Errorf("guide: %q is not a rule ID", page.RuleID)
	}

	var cur *Section
	flush := func() {
		if cur != nil {
			page.Sections = append(page.Sections, *cur)
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

	for _, raw := range lines[1:] {
		line := strings.TrimRight(raw, " \t")

		switch {
		case strings.HasPrefix(line, "### "):
			closeBlocks()
			flush()
			cur = &Section{Heading: strings.TrimSpace(strings.TrimPrefix(line, "### "))}

		case strings.HasPrefix(line, "## "), strings.TrimSpace(line) == "---":
			// End of this page.
			closeBlocks()
			flush()
			return finishPage(page)

		case strings.TrimSpace(line) == "":
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
	return finishPage(page)
}

// finishPage checks the page against the required skeleton.
func finishPage(p Page) (Page, error) {
	if len(p.Sections) != len(Skeleton) {
		got := make([]string, 0, len(p.Sections))
		for _, s := range p.Sections {
			got = append(got, s.Heading)
		}
		return Page{}, fmt.Errorf("guide: page %s has %d sections %v, want the %d-section skeleton %v",
			p.RuleID, len(p.Sections), got, len(Skeleton), Skeleton)
	}
	for i, s := range p.Sections {
		if s.Heading != Skeleton[i] {
			return Page{}, fmt.Errorf("guide: page %s section %d is %q, want %q",
				p.RuleID, i, s.Heading, Skeleton[i])
		}
		if len(s.Blocks) == 0 {
			return Page{}, fmt.Errorf("guide: page %s section %q is empty", p.RuleID, s.Heading)
		}
		// The first two sections are the answer the reader came for.
		p.Sections[i].NeverCollapse = i < 2
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
