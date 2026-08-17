package gui

import (
	"fmt"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Coverage is what a run examined and what it could not, assembled for the
// screen shown when nothing was found.
//
// That screen is the most dangerous one in the application. An empty findings
// list reads as either "nothing is wrong" or "the tool didn't work", and the
// user this is built for cannot tell which. Worse, a quiet result invites the
// reader to close the ticket — so the checks that could not run have to be as
// prominent as the reassurance, not tucked behind a disclosure.
//
// Assembled here in the app rather than in the report document, matching the
// decision made for packet evidence: the exported JSON and HTML do not carry
// it yet.
type Coverage struct {
	// Clean reports that the run completed and surfaced nothing.
	Clean bool `json:"clean"`
	// Statement is the headline, calibrated rather than congratulatory.
	Statement string `json:"statement"`
	// Qualifier is the sentence that stops the headline being read as a verdict.
	Qualifier string `json:"qualifier"`

	// Checked is what actually ran, taken from the rule registry so the screen
	// cannot claim a check the engine does not perform.
	Checked []CheckInfo `json:"checked"`
	// NotChecked is what could not be assessed and why. This is the section
	// that earns the screen its place.
	NotChecked []CoverageGap `json:"not_checked"`
	// UnbuiltChecks is how many of the planned v1 rules do not exist yet.
	UnbuiltChecks int `json:"unbuilt_checks"`

	// CoverageStrong permits the clean banner to be presented positively — in
	// green. It is false whenever checks could not run or do not yet exist,
	// because green reads as an all-clear and this screen's wording is
	// explicitly tested against claiming one. Colour must not say what the
	// words are forbidden from saying.
	CoverageStrong bool `json:"coverage_strong"`
	// CoverageWeakReason states why the presentation is neutral rather than
	// positive. Empty when CoverageStrong is true.
	CoverageWeakReason string `json:"coverage_weak_reason,omitempty"`

	// MinorObservations counts findings held back from the list because they
	// fell below the display floor.
	//
	// Always zero today: no display floor exists. Every finding a rule emits is
	// shown, and rules suppress their own trivia at detection time instead —
	// R01's hundred-millisecond floor, for example. The field is here because
	// the screen has to say "there are minor observations you are not seeing"
	// the moment such a floor is introduced, and a screen that silently omits
	// findings is the same false-all-clear failure in a new place.
	MinorObservations int `json:"minor_observations"`
}

// CoverageGap is one thing the run could not assess.
type CoverageGap struct {
	// RuleID is the rule that could not run, where one owns the gap.
	RuleID string `json:"rule_id,omitempty"`
	Text   string `json:"text"`
}

// buildCoverage assembles the coverage summary for a completed run.
//
// If presentation-layer filtering is ever added (BRIEF.md section 8), this
// screen must state the active filter alongside the gaps below: a report that
// looks clean because the filter excluded the problem is the same failure mode
// as one that looks clean because a check never ran. Not built here — there is
// no filtering yet — but this is where it belongs.
func buildCoverage(res *analysis.Result) Coverage {
	c := Coverage{
		Clean:      len(res.Findings) == 0,
		Checked:    checkInfos(),
		NotChecked: coverageGaps(res),
	}

	if total := 15; total > len(c.Checked) {
		c.UnbuiltChecks = total - len(c.Checked)
	}

	strength := rules.AssessCoverage(len(c.NotChecked), c.UnbuiltChecks)
	c.CoverageStrong = strength.Strong
	c.CoverageWeakReason = strength.Reason

	c.Statement, c.Qualifier = cleanWording(res, c)
	return c
}

// cleanWording is the headline and its qualifier.
//
// Two distinct situations produce an empty findings list, and telling the
// reader the wrong one is worse than saying nothing. A capture full of TCP that
// no rule matched is a result. A capture with no TCP in it at all is not — the
// checks had nothing to look at, and reporting that as "no problems found"
// would be the tool taking credit for work it never did.
func cleanWording(res *analysis.Result, c Coverage) (statement, qualifier string) {
	if res.Capture.TCPFlows == 0 {
		return "No TCP traffic to examine",
			fmt.Sprintf(
				"This capture holds %s packets, but none of them form a TCP conversation. "+
					"Every check in this build looks at TCP, so none of them had anything to examine — "+
					"this is not a result about the traffic, it is the absence of anything to assess.",
				formatCount(res.Capture.PacketsRead))
	}

	qualifier = fmt.Sprintf(
		"That is not the same as the capture being problem-free. "+
			"%d of 15 planned checks are built, and what they do not cover has not been examined. "+
			"What each check looked at, and what could not be assessed on this capture, is below.",
		len(c.Checked))

	return "No significant problems found in what was checked", qualifier
}

// coverageGaps collects everything the run could not assess.
//
// Two sources feed it. The rules and the capture-quality reporting emit
// `unavailable` notes as they go, and the per-flow completeness counters record
// conditions that limit what could be assessed without any rule having said so.
// Both belong on this screen; a reader cannot be expected to know which
// mechanism produced which gap.
func coverageGaps(res *analysis.Result) []CoverageGap {
	var gaps []CoverageGap

	// Whatever the rules and the capture-quality checks already said.
	for _, n := range res.Notes {
		if n.Kind != "unavailable" {
			continue
		}
		gaps = append(gaps, CoverageGap{RuleID: n.RuleID, Text: n.Text})
	}

	c := res.Capture

	// Flows already established when the capture began. Their window scale
	// factor was never negotiated in view, so anything sized in bytes is
	// unavailable for them — while zero-window detection, which does not
	// depend on the scale factor, is not affected.
	if c.MidstreamFlows > 0 && c.TCPFlows > 0 {
		gaps = append(gaps, CoverageGap{
			RuleID: "R15",
			Text: fmt.Sprintf(
				"Not assessed: receive window sizing. %d of %d flows (%s) began before the capture started, "+
					"so the window scale factor for them is unknown. Zero-window detection does not depend on it "+
					"and was performed on every flow.",
				c.MidstreamFlows, c.TCPFlows,
				formatSharePercent(c.MidstreamFlows, c.TCPFlows)),
		})
	}

	// Only one direction captured. Anything that compares the two directions
	// has nothing to compare, which is a common consequence of a one-way SPAN
	// configuration rather than anything wrong with the network.
	if c.OneWayFlows > 0 {
		gaps = append(gaps, CoverageGap{
			RuleID: "R15",
			Text: fmt.Sprintf(
				"Not assessed: anything comparing the two directions of a conversation. "+
					"%d of %d flows were captured in one direction only, which usually means the capture point "+
					"saw traffic going one way. Loss direction analysis is unavailable for those.",
				c.OneWayFlows, c.TCPFlows),
		})
	}

	// Flows discarded mid-run because the concurrency cap was reached: those
	// were analysed only up to the point they were dropped.
	if c.FlowsEvicted > 0 {
		gaps = append(gaps, CoverageGap{
			RuleID: "R15",
			Text: fmt.Sprintf(
				"Partly assessed: %s of %s flows were set aside before the capture ended, because more "+
					"conversations were open at once than this run tracks. Those flows were examined only up to "+
					"that point.",
				formatCount(c.FlowsEvicted), formatCount(uint64(c.TCPFlows))),
		})
	}

	return gaps
}

// checkInfos is the implemented rule set, from the registry.
//
// Shared with the home screen rather than restated: two lists of what the tool
// checks would eventually disagree, and the one on this screen is the one a
// reader is relying on when they decide the capture is fine.
func checkInfos() []CheckInfo {
	metas := rules.AllMeta()
	out := make([]CheckInfo, 0, len(metas))
	for _, m := range metas {
		out = append(out, CheckInfo{ID: m.ID, Name: m.Name, Summary: m.Summary})
	}
	return out
}

// formatSharePercent renders part of whole as a percentage, never rounding a
// real proportion down to nothing.
func formatSharePercent(part, whole int) string {
	if whole <= 0 {
		return "0%"
	}
	pct := float64(part) * 100 / float64(whole)
	if pct > 0 && pct < 1 {
		return "under 1%"
	}
	return fmt.Sprintf("%.0f%%", pct)
}

// formatCount renders a count with thousands separators.
func formatCount(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}
