package report

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// buildFixtureDoc analyses a committed fixture and builds the full document,
// coverage included — the exact object both the app binding and the exports
// render.
func buildFixtureDoc(t *testing.T, name string) *Document {
	t.Helper()
	res, err := analysis.Run(synth.FixturePath(name, "pcap"), analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", name, err)
	}
	return Build(res, Invocation{Input: name}, "test")
}

// bodyOf strips the inlined stylesheet, so wording assertions run against what
// the reader sees rather than matching CSS class names and comments.
func bodyOf(t *testing.T, html string) string {
	t.Helper()
	_, body, found := strings.Cut(html, "</style>")
	if !found {
		t.Fatal("no inlined stylesheet found; the render is not the shipped page")
	}
	return body
}

// TestCaptureWithNoTCPIsNotReportedAsClean checks the case where the file
// parses and holds packets, but none of them are TCP.
//
// Every check in this build looks at TCP, so "no significant problems found"
// would be the tool taking credit for work it never did.
func TestCaptureWithNoTCPIsNotReportedAsClean(t *testing.T) {
	// A run that read packets but formed no TCP flows from them — a capture
	// full of UDP, say. The file is fine and the run succeeded; there was
	// simply nothing any check in this build looks at.
	res := &analysis.Result{
		Capture: analysis.CaptureInfo{
			PacketsRead:   4096,
			PacketsNonTCP: 4096,
			TCPFlows:      0,
		},
	}

	cov := buildCoverage(res)
	if cov.Statement == "No significant problems found in what was checked" {
		t.Error("a capture with no TCP was reported as having no problems found")
	}
	// "No traffic this build examines", not "No TCP traffic".
	//
	// The wording was TCP-specific while every rule read TCP. R11 reads DNS
	// over UDP, so a capture with no TCP is no longer automatically a capture
	// with nothing in it — this one has neither, and the statement has to be
	// about what the build examines rather than about one protocol.
	if !strings.Contains(cov.Statement, "No traffic this build examines") {
		t.Errorf("statement = %q", cov.Statement)
	}
	if !strings.Contains(cov.Qualifier, "anything to examine") {
		t.Errorf("the qualifier does not say the checks had nothing to look at: %q", cov.Qualifier)
	}
	// The packet count is stated, so the reader can tell this from an empty file.
	if !strings.Contains(cov.Qualifier, "4,096") {
		t.Errorf("the qualifier does not say how much was in the file: %q", cov.Qualifier)
	}
	assertNoVerdict(t, cov.Statement)
	assertNoVerdict(t, cov.Qualifier)

	// Nothing to examine is not strong coverage, and must never pick up the
	// green treatment.
	if cov.CoverageStrong {
		t.Error("a capture with nothing to examine was presented as strongly covered")
	}
}

// TestEvictedFlowsAreDisclosed checks that buildCoverage surfaces an
// eviction gap R15 reported, the same way it surfaces any other rule's
// unavailable note. The wording itself — and the "120 of 500" figure — is
// R15's to get right and is tested where R15 lives (internal/rules); this is
// only the pass-through, hand-supplying the note the way R15's Emit would
// have, since this test builds a Result directly rather than through
// analysis.Run.
func TestEvictedFlowsAreDisclosed(t *testing.T) {
	res := &analysis.Result{
		Capture: analysis.CaptureInfo{PacketsRead: 10000, TCPFlows: 500, FlowsEvicted: 120},
		Notes: []findings.Note{
			{Kind: "unavailable", RuleID: "R15",
				Text: "Partly assessed: 120 of 500 flows were set aside before the capture ended, " +
					"because more conversations were open at once than this run tracks."},
		},
	}

	var found bool
	for _, g := range buildCoverage(res).NotChecked {
		if strings.Contains(g.Text, "set aside before the capture ended") {
			found = true
			if !strings.Contains(g.Text, "120") {
				t.Errorf("the gap does not say how many: %q", g.Text)
			}
		}
	}
	if !found {
		t.Error("flows dropped for want of tracking capacity were not disclosed")
	}
}

// TestCleanCoverageIsNeutralAtTodaysBuildState checks the reason green is
// withheld even from a capture with no gaps at all: most of the rule set does
// not exist. "All clear" cannot be claimed from two checks out of fifteen.
func TestCleanCoverageIsNeutralAtTodaysBuildState(t *testing.T) {
	// A clean run with every gap removed, leaving only the unbuilt-checks
	// reason in play.
	res := &analysis.Result{
		Capture: analysis.CaptureInfo{PacketsRead: 1000, TCPFlows: 10},
	}
	cov := buildCoverage(res)

	if len(cov.NotChecked) != 0 {
		t.Fatalf("constructed result unexpectedly has %d gaps", len(cov.NotChecked))
	}
	if cov.UnbuiltChecks == 0 {
		t.Skip("every planned check is now built; this test's premise is gone")
	}
	if cov.CoverageStrong {
		t.Error("green was allowed with most of the rule set unbuilt")
	}
	if !strings.Contains(cov.CoverageWeakReason, "built") {
		t.Errorf("the reason does not mention the unbuilt checks: %q", cov.CoverageWeakReason)
	}
}

// TestExportCarriesTheCleanCoverage renders the artifact the brief worries
// about: the exported HTML of a gappy clean capture, read by someone with zero
// context. The statement, its qualifier, and the gaps must all be in the
// rendered page, and the banner must stay neutral.
func TestExportCarriesTheCleanCoverage(t *testing.T) {
	doc := buildFixtureDoc(t, "clean-capture")
	if len(doc.Findings) != 0 {
		t.Fatalf("the clean fixture produced %d findings", len(doc.Findings))
	}

	body := bodyOf(t, render(t, doc))

	// The calibrated statement and its qualifier lead the findings section.
	for _, want := range []string{
		"No significant problems found in what was checked",
		"That is not the same as the capture being problem-free",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the export does not carry the clean statement wording: missing %q", want)
		}
	}

	// The gaps — here, classic pcap's inability to report capture-host drops —
	// render beside the result, not only in the app.
	if !strings.Contains(body, "dropped packets before writing them") {
		t.Error("the capture-host drop gap is missing from the exported report")
	}

	// Neutral, not green: coverage is weak (gaps exist and most checks are
	// unbuilt), so the all-clear colour must not appear.
	if strings.Contains(body, "coverage-strong") {
		t.Error("a gappy clean export carries the green banner class")
	}

	// The unbuilt count is stated from data, not prose that can go stale.
	unbuilt := rules.TotalV1Rules - len(rules.AllMeta())
	if !strings.Contains(body, fmt.Sprintf("%d of the fifteen v1 rules are not implemented", unbuilt)) {
		t.Error("the export does not state how much of the rule set does not exist")
	}
}

// TestExportBannerGreenRequiresStrongCoverage is the other half of the
// neutral-not-green rule: the class appears when — and only when — the
// document says coverage is strong. Only-when is covered by the test above on
// a real run; this constructs the unreachable strong state to prove the green
// path is live rather than dead code.
func TestExportBannerGreenRequiresStrongCoverage(t *testing.T) {
	doc := buildFixtureDoc(t, "clean-capture")
	doc.Coverage.CoverageStrong = true
	doc.Coverage.CoverageWeakReason = ""

	if !strings.Contains(render(t, doc), `clean-banner coverage-strong`) {
		t.Error("a strongly-covered clean document did not render the green banner treatment")
	}
}

// TestExportWordingCarriesNoVerdict applies the P3 banned-phrase test to the
// export rendering, not just the in-app struct: what a stranger reads in the
// attached report is held to the same posture as the screen.
//
// The scan is scoped to the regions the coverage wording renders into — the
// clean banner and the checks-not-performed section — because that is what the
// P3 ban governs. The masthead's posture paragraph legitimately contains the
// word "healthy" in negation ("…not that the capture is healthy"), which a
// whole-page substring scan cannot tell from a claim.
func TestExportWordingCarriesNoVerdict(t *testing.T) {
	// Both clean shapes: a genuinely quiet capture, and one with nothing to
	// examine at all.
	docs := map[string]*Document{
		"clean-fixture": buildFixtureDoc(t, "clean-capture"),
		"no-tcp": Build(&analysis.Result{
			Capture: analysis.CaptureInfo{PacketsRead: 4096, PacketsNonTCP: 4096},
		}, Invocation{}, "test"),
	}

	banner := regexp.MustCompile(`(?s)<div class="clean-banner.*?</div>`)
	// From the coverage section's heading to the next heading after it.
	gaps := regexp.MustCompile(`(?s)<h2>Checks not performed.*?<h2 `)

	for name, doc := range docs {
		body := bodyOf(t, render(t, doc))

		var regions []string
		if m := banner.FindString(body); m != "" {
			regions = append(regions, m)
		} else {
			t.Errorf("%s: no clean banner rendered, so the wording scan has nothing to check", name)
		}
		if m := gaps.FindString(body); m != "" {
			regions = append(regions, m)
		} else {
			t.Errorf("%s: no coverage section rendered", name)
		}

		for _, region := range regions {
			lower := strings.ToLower(region)
			for _, banned := range VerdictBans {
				if strings.Contains(lower, banned) {
					t.Errorf("%s: the exported coverage wording contains a verdict %q", name, banned)
				}
			}
		}
	}
}

// assertNoVerdict holds coverage wording to the same posture as the findings:
// it may say what was examined, never what it means.
func assertNoVerdict(t *testing.T, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, banned := range VerdictBans {
		if strings.Contains(lower, banned) {
			t.Errorf("wording contains a verdict %q:\n%s", banned, text)
		}
	}
}
