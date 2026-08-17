package report

import (
	"fmt"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Coverage is what a run examined and what it could not.
//
// It lives in the report document rather than in the app because the exported
// report is read by people with zero context — a vendor, a ticket queue —
// and an export that looks clean because half the checks never ran will close
// a ticket on a fault that is still live. The in-app clean screen renders this
// same struct; the two surfaces cannot disagree because neither assembles its
// own copy. (It was assembled in the app first; it moved here when the exports
// gained the same false-all-clear exposure the app screen was built to fix.)
//
// The checked list is deliberately not duplicated here: Document.Checks is the
// record of what ran, and a second list of the same rules could drift from it.
type Coverage struct {
	// Clean reports that the run completed and surfaced nothing.
	Clean bool `json:"clean"`
	// Statement is the headline, calibrated rather than congratulatory.
	Statement string `json:"statement"`
	// Qualifier is the sentence that stops the headline being read as a verdict.
	Qualifier string `json:"qualifier"`

	// NotChecked is what could not be assessed and why. On the clean screen
	// this is the section that earns the screen its place; in an export it is
	// the section a stranger needs most.
	NotChecked []CoverageGap `json:"not_checked"`
	// UnbuiltChecks is how many of the planned v1 rules do not exist yet.
	UnbuiltChecks int `json:"unbuilt_checks"`

	// CoverageStrong permits a clean result to be presented positively — in
	// green. It is false whenever checks could not run or do not yet exist,
	// because green reads as an all-clear and this wording is explicitly
	// tested against claiming one. Colour must not say what the words are
	// forbidden from saying.
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
	// every rendering has to say "there are minor observations you are not
	// seeing" the moment such a floor is introduced, and a report that silently
	// omits findings is the same false-all-clear failure in a new place.
	MinorObservations int `json:"minor_observations"`
}

// CoverageGap is one thing the run could not assess.
type CoverageGap struct {
	// RuleID is the rule that could not run, where one owns the gap.
	RuleID string `json:"rule_id,omitempty"`
	Text   string `json:"text"`
}

// VerdictBans lists phrasing the coverage wording must never contain.
//
// This is the P3 posture ban: the clean-capture statement may say what was
// examined, never what it means. Exported for the same reason StyleSheet is —
// the GUI binding hands this wording to the frontend and the report renders it
// into exports, and both sets of tests must hold it to the same ban without a
// second copy of the list to drift from.
var VerdictBans = []string{
	"healthy", "all clear", "all-clear", "everything is fine", "no problems with",
	"your network", "is working correctly", "nothing is wrong",
}

// buildCoverage assembles the coverage summary for a completed run.
//
// If presentation-layer filtering is ever added (BRIEF.md section 8), the
// coverage must state the active filter alongside the gaps below: a report that
// looks clean because the filter excluded the problem is the same failure mode
// as one that looks clean because a check never ran. Not built here — there is
// no filtering yet — but this is where it belongs.
func buildCoverage(res *analysis.Result) Coverage {
	c := Coverage{
		Clean: len(res.Findings) == 0,
		// Emitted as [] rather than null, so an export consumer reading an
		// empty list can tell "no gaps" from "field absent".
		NotChecked: coverageGaps(res),
	}

	if built := len(rules.AllMeta()); rules.TotalV1Rules > built {
		c.UnbuiltChecks = rules.TotalV1Rules - built
	}

	strength := rules.AssessCoverage(len(c.NotChecked), c.UnbuiltChecks)
	c.CoverageStrong = strength.Strong
	c.CoverageWeakReason = strength.Reason

	c.Statement, c.Qualifier = cleanWording(res)
	return c
}

// cleanWording is the headline and its qualifier.
//
// Two distinct situations produce an empty findings list, and telling the
// reader the wrong one is worse than saying nothing. A capture full of TCP that
// no rule matched is a result. A capture with no TCP in it at all is not — the
// checks had nothing to look at, and reporting that as "no problems found"
// would be the tool taking credit for work it never did.
func cleanWording(res *analysis.Result) (statement, qualifier string) {
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
			"%d of %d planned checks are built, and what they do not cover has not been examined. "+
			"What each check looked at, and what could not be assessed on this capture, is below.",
		len(rules.AllMeta()), rules.TotalV1Rules)

	return "No significant problems found in what was checked", qualifier
}

// coverageGaps collects everything the run could not assess.
//
// Two sources feed it. The rules and the capture-quality reporting emit
// `unavailable` notes as they go, and the per-flow completeness counters record
// conditions that limit what could be assessed without any rule having said so.
// Both belong in the coverage; a reader cannot be expected to know which
// mechanism produced which gap.
func coverageGaps(res *analysis.Result) []CoverageGap {
	gaps := make([]CoverageGap, 0, 4)

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
