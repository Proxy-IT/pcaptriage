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

// CleanStateBans lists phrasing that belongs only to a genuinely clean
// capture, and must never appear on a screen that reached emptiness some other
// way.
//
// The filtered-to-nothing view is the case this exists for. "No findings match
// this filter" and "no significant problems found" are opposite statements
// about the same blank screen, and a reader who takes the second away from the
// first closes a ticket on a live fault. The two states are already built to
// look different; this is what keeps them reading differently as the wording
// is edited.
var CleanStateBans = []string{
	"no significant problems",
	"found in what was checked",
	"nothing was surfaced",
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
// BRIEF.md section 8 requires a report to state its active filter alongside
// the gaps, on the grounds that a report looking clean because the filter
// excluded the problem is the same failure mode as one looking clean because a
// check never ran. Presentation-layer filtering now exists, and this function
// still has no filter to state — deliberately.
//
// The filter is a view over a completed report and never reaches this
// document: the export and the JSON are always the full, unfiltered result, so
// a "filter applied" line here would always read "none" and would be false the
// moment filtered export is built. The requirement is met where the filtering
// actually happens — the app's chip bar carries a mandatory "Showing N of M"
// for as long as any filter is active. When filtered export arrives, its
// provenance banner belongs here, and section 8 specifies what it must say.
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

	// A third condition, and it only became reachable when the rule set was
	// completed. Until then UnbuiltChecks was always non-zero, so green was
	// unreachable by construction and nothing else needed to gate it.
	//
	// With all fifteen rules built, a capture containing nothing for them to
	// examine now satisfies both existing conditions — no gaps, no unbuilt
	// checks — and would be presented as strongly covered. It is the opposite:
	// the checks did not find nothing, they had nothing to look at. The
	// wording already says so, and colour must not contradict the words.
	if c.Clean && res.Capture.TCPFlows == 0 && res.Capture.DNSMessages == 0 {
		c.CoverageStrong = false
		c.CoverageWeakReason = "the capture contained no conversations for the checks to examine"
	}

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
		// A capture with no TCP is not automatically a capture with nothing in
		// it. That was true while every rule read TCP; R11 reads DNS over UDP,
		// so a file of name lookups now has something the tool genuinely
		// examined and must not be told otherwise.
		if res.Capture.DNSMessages > 0 {
			return "No problems found in what was checked",
				fmt.Sprintf(
					"This capture holds %s packets and no TCP conversations, so only the name-lookup "+
						"checks had anything to read — %s DNS message%s. Everything else this build looks "+
						"for needs TCP and had nothing to examine here.",
					formatCount(res.Capture.PacketsRead),
					formatCount(res.Capture.DNSMessages), plural(int(res.Capture.DNSMessages)))
		}
		return "No traffic this build examines",
			fmt.Sprintf(
				"This capture holds %s packets, but none of them form a TCP conversation and none are "+
					"name lookups. Every check in this build reads one or the other, so none of them had "+
					"anything to examine — this is not a result about the traffic, it is the absence of "+
					"anything to assess.",
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
// Every gap here comes from a rule's own unavailable note — R15's drop,
// midstream, one-way and eviction notes among them. This function used to
// also synthesise the midstream/one-way/eviction text itself, directly from
// capture counters, because R15 didn't exist to own that reporting; now that
// it does, this is nothing more than the filter every other rule's
// unavailable notes already went through.
func coverageGaps(res *analysis.Result) []CoverageGap {
	gaps := make([]CoverageGap, 0, 4)
	for _, n := range res.Notes {
		if n.Kind != "unavailable" {
			continue
		}
		gaps = append(gaps, CoverageGap{RuleID: n.RuleID, Text: n.Text})
	}
	return gaps
}
