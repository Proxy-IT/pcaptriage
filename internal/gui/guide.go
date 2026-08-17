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

// GuideEntry is one line of the guide index.
type GuideEntry struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name"`
	// Summary is the one-line explanation for built checks, and the registry's
	// own one-liner for the rest.
	Summary string `json:"summary"`
	// Built reports whether the check exists. Planned entries have no page.
	Built bool `json:"built"`
	// HasPage reports whether there is guide prose to link to.
	HasPage bool `json:"has_page"`
}

// GuideIndex is the answer to "what does this tool check?".
type GuideIndex struct {
	Entries []GuideEntry `json:"entries"`
	// PlannedCount is how many of the planned v1 checks are not built.
	PlannedCount int `json:"planned_count"`
	// PlannedNote states the shortfall in words, since a list of two entries
	// would otherwise imply the tool checks two things and that is all there is.
	PlannedNote string `json:"planned_note"`
}

// Guide returns the index, built from the rule registry.
//
// Entries come from the registry rather than a hand-written list, for the same
// reason the home screen's check list does: two lists of what the tool checks
// would eventually disagree, and this one is what a reader consults to decide
// whether the tool looked at their problem.
func (a *App) Guide() (GuideIndex, error) {
	pages, err := guide.Pages()
	if err != nil {
		return GuideIndex{}, fmt.Errorf("the guide content could not be read: %w", err)
	}
	hasPage := make(map[string]bool, len(pages))
	for _, p := range pages {
		hasPage[p.RuleID] = true
	}

	metas := rules.AllMeta()
	idx := GuideIndex{Entries: make([]GuideEntry, 0, len(metas))}
	for _, m := range metas {
		entry := GuideEntry{
			RuleID:  m.ID,
			Name:    m.Name,
			Summary: m.Summary,
			Built:   true,
			HasPage: hasPage[m.ID],
		}
		if p, ok := guide.Lookup(m.ID); ok {
			// Prefer the authored one-liner, which is written for this reader.
			entry.Summary = p.Summary()
		}
		idx.Entries = append(idx.Entries, entry)
	}

	if planned := 15 - len(metas); planned > 0 {
		idx.PlannedCount = planned
		idx.PlannedNote = fmt.Sprintf(
			"%d further checks are planned and not built yet. Nothing they would cover has been "+
				"examined in any capture this build has read.", planned)
	}
	return idx, nil
}

// GuidePage returns the guide entry for a rule.
func (a *App) GuidePage(ruleID string) (guide.Page, error) {
	p, ok := guide.Lookup(ruleID)
	if !ok {
		return guide.Page{}, fmt.Errorf("there is no guide page for %s", ruleID)
	}
	return p, nil
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
			"%d of 15 planned checks are built in this version. A capture with nothing reported "+
				"has been examined by those %d checks and no others.", built, built),
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
