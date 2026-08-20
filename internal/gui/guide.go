package gui

import (
	"errors"
	"fmt"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Proxy-IT/pcaptriage/internal/guide"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// ProjectURL is where the source lives, and the attribution target.
//
// It is opened in the user's own browser, never fetched. Nothing in this app
// makes a network request — see the About text, which says so to the user, and
// the test that asserts this package cannot.
const ProjectURL = "https://proxy-it.co"

// GuideEntry is one line of the guide index. Most represent a single rule; an
// entry whose page serves several rules (the loss cluster's) lists them as
// Members instead of appearing as several separate entries — one row per
// PAGE, not one row per rule, which is what keeps a reader from clicking four
// nearly-identical rows before realising they all open the same document.
type GuideEntry struct {
	// RuleID is the lookup key this entry navigates with when clicked from
	// the index — GuidePage(RuleID). For a multi-rule entry it is the first
	// served rule encountered in registry order; which one does not matter
	// for that click, since arriving from the index always lands at the page
	// top, never scrolled to a particular rule's section.
	RuleID string `json:"rule_id"`
	// RuleIDs is every rule this entry represents, in the page's own
	// document order. Length 1 for an ordinary entry.
	RuleIDs []string `json:"rule_ids"`
	// Name is the page's title for a multi-rule entry, and the rule's own
	// registry name otherwise — a title naming one of four rules would
	// misrepresent what the row actually covers.
	Name string `json:"name"`
	// Summary is the page's own one-line summary for built checks, and the
	// registry's one-liner for the rest.
	Summary string `json:"summary"`
	// Built reports whether every rule this entry represents exists. Planned
	// entries have no page.
	Built bool `json:"built"`
	// HasPage reports whether there is guide prose to link to.
	HasPage bool `json:"has_page"`
	// Members lists every rule this entry represents, beyond the first, for a
	// page that serves more than one — so the index can say what is actually
	// covered without the reader opening the page first. Empty for an
	// ordinary single-rule entry.
	Members []GuideEntryMember `json:"members,omitempty"`
}

// GuideEntryMember is one rule within a multi-rule GuideEntry.
type GuideEntryMember struct {
	RuleID  string `json:"rule_id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

// GuideIndex is the answer to "what does this tool check?" — and, in
// Concepts, to the two questions every finding asks the reader to answer
// about it, which are not checks and must not read as one more row in
// Entries.
type GuideIndex struct {
	Entries []GuideEntry `json:"entries"`
	// PlannedCount is how many of the planned v1 checks are not built.
	PlannedCount int `json:"planned_count"`
	// PlannedNote states the shortfall in words, since a list of two entries
	// would otherwise imply the tool checks two things and that is all there is.
	PlannedNote string `json:"planned_note"`
	// Concepts is the guide's second, separate section: background that
	// applies across every finding rather than documenting one check. Kept
	// apart from Entries deliberately — a concept has no rule ID, is not
	// registry-derived, and does not count toward PlannedCount or the
	// built/planned totals the home screen states. See internal/guide.Concept.
	Concepts []ConceptEntry `json:"concepts"`
}

// ConceptEntry is one row in the guide index's Concepts section.
//
// Deliberately smaller than GuideEntry: a concept has no rule ID, no built/
// planned distinction (a concept that parsed exists; there is no "not built
// yet" state for prose), and never groups several of anything into one row,
// so it carries none of the fields those situations need.
type ConceptEntry struct {
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

// Guide returns the index, built from the rule registry.
//
// Entries come from the registry rather than a hand-written list, for the same
// reason the home screen's check list does: two lists of what the tool checks
// would eventually disagree, and this one is what a reader consults to decide
// whether the tool looked at their problem. Rules that share a guide page are
// grouped into one entry while the grouping itself — which rules share which
// page — still comes from the guide content, not a hand-maintained list here.
func (a *App) Guide() (GuideIndex, error) {
	pages, err := guide.Pages()
	if err != nil {
		return GuideIndex{}, fmt.Errorf("the guide content could not be read: %w", err)
	}
	// pageFor maps a rule ID to the page that documents it, so building each
	// registry rule's entry is one lookup regardless of how many rules that
	// page serves.
	pageFor := make(map[string]guide.Page, len(pages)*2)
	for _, p := range pages {
		for _, id := range p.RuleIDs {
			pageFor[id] = p
		}
	}

	metas := rules.AllMeta()
	byID := make(map[string]rules.Meta, len(metas))
	for _, m := range metas {
		byID[m.ID] = m
	}

	idx := GuideIndex{Entries: make([]GuideEntry, 0, len(metas))}
	grouped := make(map[string]bool, len(metas)) // rule IDs already folded into an earlier entry

	for _, m := range metas {
		if grouped[m.ID] {
			continue
		}

		page, hasPage := pageFor[m.ID]
		entry := GuideEntry{
			RuleID: m.ID, RuleIDs: []string{m.ID},
			Name: m.Name, Summary: m.Summary, Built: true, HasPage: hasPage,
		}
		if hasPage {
			// Prefer the authored one-liner, which is written for this reader.
			entry.Summary = page.Summary()
		}

		if hasPage && len(page.RuleIDs) > 1 {
			// A multi-rule page: the row represents the page, not any one of
			// its rules, so it takes the page's own title rather than the
			// first rule's registry name. Every rule after the first that
			// triggered this entry becomes a Member instead of its own
			// top-level entry, and is marked grouped so the loop above skips
			// it when it comes up.
			entry.Name = page.Title
			entry.RuleIDs = append([]string(nil), page.RuleIDs...)
			for _, id := range page.RuleIDs {
				grouped[id] = true
				if id == m.ID {
					continue
				}
				mm, ok := byID[id]
				if !ok {
					// The page claims a rule the registry does not have; the
					// bijection test catches this, but an entry here must not
					// silently drop it either.
					continue
				}
				entry.Members = append(entry.Members, GuideEntryMember{
					RuleID: mm.ID, Name: mm.Name, Summary: mm.Summary,
				})
			}
		}

		idx.Entries = append(idx.Entries, entry)
	}

	if planned := rules.TotalV1Rules - len(metas); planned > 0 {
		idx.PlannedCount = planned
		idx.PlannedNote = fmt.Sprintf(
			"%d further checks are planned and not built yet. Nothing they would cover has been "+
				"examined in any capture this build has read.", planned)
	}

	// A second, unrelated loop rather than folded into the one above: concepts
	// do not come from the rule registry, so there is nothing about them to
	// walk metas for. Built from guide.Concepts() the same way Entries is
	// built from guide.Pages() — the index cannot claim a concept the guide
	// content does not have, or omit one it does.
	concepts, err := guide.Concepts()
	if err != nil {
		return GuideIndex{}, fmt.Errorf("the concepts content could not be read: %w", err)
	}
	for _, c := range concepts {
		idx.Concepts = append(idx.Concepts, ConceptEntry{
			Slug: c.Slug, Title: c.Title, Summary: c.Summary(),
		})
	}

	return idx, nil
}

// GuidePage returns the guide page documenting a rule. For a rule whose page
// serves several rules, this returns the whole page — every section, not
// only that rule's — since the page is authored to be read as one document;
// the frontend scrolls to that rule's anchored section rather than being
// handed a slice of the page.
func (a *App) GuidePage(ruleID string) (guide.Page, error) {
	p, ok := guide.Lookup(ruleID)
	if !ok {
		return guide.Page{}, fmt.Errorf("there is no guide page for %s", ruleID)
	}
	return p, nil
}

// GuideConcept returns the concept page identified by slug — the parallel
// lookup to GuidePage, for the guide's other section. A separate method
// rather than GuidePage accepting either kind of identifier: the two id
// spaces (rule IDs, concept slugs) are unrelated, and a caller should not be
// able to pass one where the other belongs without the compiler noticing.
func (a *App) GuideConcept(slug string) (guide.Concept, error) {
	c, ok := guide.LookupConcept(slug)
	if !ok {
		return guide.Concept{}, fmt.Errorf("there is no concept page for %s", slug)
	}
	return c, nil
}

// AboutInfo is the About page's content.
//
// The prose lives here rather than in the HTML so that the version numbers come
// from the same constants the reports are stamped with, and cannot drift into
// saying something the build does not do.
type AboutInfo struct {
	Name    string `json:"name"`
	Tagline string `json:"tagline"`
	// What is two or three sentences on what the tool is for.
	What []string `json:"what"`
	// Privacy is the data story, in plain sentences rather than a policy.
	Privacy []string `json:"privacy"`
	// Posture is the advisory line, in one sentence.
	Posture string `json:"posture"`
	// OpenSource states the licence and where the source is.
	OpenSource string `json:"open_source"`
	SourceURL  string `json:"source_url"`

	Version        string `json:"version"`
	RulesetVersion string `json:"ruleset_version"`
	SchemaVersion  string `json:"schema_version"`

	// Attribution is the credit line, and AttributionURL is opened in the
	// user's browser rather than fetched.
	Attribution    string `json:"attribution"`
	AttributionURL string `json:"attribution_url"`

	// Coverage states how much of the planned rule set exists, so the About
	// page cannot imply a finished tool.
	Coverage string `json:"coverage"`
}

// About returns the About page content.
func (a *App) About() AboutInfo {
	built := len(rules.AllMeta())

	return AboutInfo{
		Name:    "pcaptriage",
		Tagline: "A second set of eyes for packet captures.",
		What: []string{
			"pcaptriage reads a capture file and points out what looks unusual in it, " +
				"ranked so the thing most worth your attention is first.",
			"It is built for the situation where you can open a capture but do not know what " +
				"to look for, and would not be sure what the answer meant if you found it. " +
				"Wireshark already shows you everything, which is the problem.",
		},
		Privacy: []string{
			"Everything happens on this machine. The capture is read from disk and analysed " +
				"here; nothing is uploaded, and there is no telemetry, no crash reporting and " +
				"no update check.",
			"This application makes no network calls of any kind. Not to check for a new " +
				"version, and not to look up a hostname — resolving addresses would send your " +
				"internal network's names to a resolver, so it is deliberately not done.",
			"The only things written to disk are your settings, in one readable file you can " +
				"open and inspect. Analysis results are never saved automatically: the capture " +
				"file is the record, and reopening it produces the same answer.",
			"Reports contain frame numbers, headers and derived measurements — never the " +
				"contents of your traffic. That is what makes one safe to attach to a ticket.",
		},
		Posture: "This tool highlights what is unusual and shows the frames it is based on. " +
			"It does not tell you what broke — that conclusion stays with you.",
		OpenSource: "Open source under the MIT licence. The detection rules are published, " +
			"so any finding can be audited and disagreed with.",
		SourceURL:      ProjectURL,
		Version:        a.Version,
		RulesetVersion: report.RulesetVersion,
		SchemaVersion:  report.SchemaVersion,
		Attribution:    "Built by Proxy-IT",
		AttributionURL: ProjectURL,
		Coverage: fmt.Sprintf(
			"%d of %d planned checks are built in this version. A capture with nothing reported "+
				"has been examined by those %d checks and no others.", built, rules.TotalV1Rules, built),
	}
}

// OpenExternal opens a link in the user's own browser.
//
// This is the only outward-facing action in the application, and it is a handoff
// rather than a request: the URL is given to the operating system, and this
// process never fetches it. An in-app fetch would contradict the no-network
// claim the About page makes two paragraphs above the link.
func (a *App) OpenExternal(url string) error {
	if url != ProjectURL {
		// Only the app's own link is openable. Nothing in a capture can reach
		// this method, but a capture is attacker-controlled data and this is the
		// one method that hands a string to the operating system.
		return errors.New("only the project link can be opened")
	}
	if a.openExternal == nil {
		if a.ctx == nil {
			return errors.New("the application is still starting up")
		}
		wruntime.BrowserOpenURL(a.ctx, url)
		return nil
	}
	a.openExternal(url)
	return nil
}
