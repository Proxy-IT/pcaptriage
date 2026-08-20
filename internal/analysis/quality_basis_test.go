package analysis_test

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestInferredFindingsAlwaysStateTheirBasis is the invariant the labelled
// basis depends on.
//
// The app and the export now render an inferred finding's basis under the
// heading "Marked inferred because:". That label makes an empty basis a
// visible defect rather than a quiet omission: the card would promise a
// reason and then supply nothing, which reads worse than the unlabelled
// paragraph it replaced. So "inferred implies a basis" stops being a
// convention the rules happen to follow and becomes a property under test.
//
// Every fixture, not a chosen few — an inferred path added later with no
// basis is exactly the case this exists to catch, and it will not be in a
// list anyone remembered to update.
func TestInferredFindingsAlwaysStateTheirBasis(t *testing.T) {
	var checked int

	for _, fx := range synth.Fixtures() {
		for _, format := range []string{"pcap", "pcapng"} {
			res, err := analysis.Run(synth.FixturePath(fx.Name, format), analysis.Options{})
			if err != nil {
				t.Fatalf("analyse %s.%s: %v", fx.Name, format, err)
			}
			for _, f := range res.Findings {
				if f.Quality != findings.Inferred {
					// The other half of the rule: a confirmed finding renders
					// no basis block at all, because absence is the signal.
					// Carrying basis text it never shows would mean the two
					// could disagree without anything noticing.
					if f.QualityBasis != "" {
						t.Errorf("%s/%s: %s finding %q is %s but carries basis text; only an inferred "+
							"finding states a basis, and nothing renders this one",
							fx.Name, format, f.RuleID, f.Title, f.Quality)
					}
					continue
				}
				checked++
				if strings.TrimSpace(f.QualityBasis) == "" {
					t.Errorf("%s/%s: %s finding %q is inferred with no basis — the card would render "+
						"\"Marked inferred because:\" followed by nothing",
						fx.Name, format, f.RuleID, f.Title)
				}
			}
		}
	}

	// A guard on the guard. If no fixture produces an inferred finding at all,
	// the loop above is vacuous and would keep passing after the invariant
	// broke — which is the failure mode TestR04MidstreamRTTIsInferred already
	// has, since it iterates R04 findings in a fixture whose R04 findings are
	// all confirmed.
	if checked == 0 {
		t.Fatal("no fixture produced an inferred finding, so this test asserted nothing")
	}
	t.Logf("checked %d inferred findings across %d fixtures", checked, len(synth.Fixtures()))
}

// TestEveryInferredRulePathHasAFixture records which rules can reach inferred
// and which of those any committed fixture actually exercises.
//
// It does not fail on a gap. Building a capture that reaches R04's midstream
// degradation is rule-fixture work under RULES.md's handoff notes, not
// something to invent while changing how the basis is displayed. What it does
// is make the gap visible in test output instead of leaving it to be
// rediscovered: R04 is the rule the origin screenshot came from, and no
// fixture reaches either of its inferred branches today.
//
// "No committed fixture" is not the same as "untested", and the difference
// matters when reading this output. R05, R06 and R08 all degrade through one
// seam — pop.Quality.KernelDropsSignificant, with the basis sentence written
// once in dropQuality — and TestKernelDropGatingReachesTheLossRules exercises
// that seam for R05 against a pcapng built at run time rather than committed.
// R04's two branches are the ones with no coverage anywhere: the test named
// for the midstream case iterates R04 findings in a fixture whose R04
// findings are all confirmed, so its body never runs.
func TestEveryInferredRulePathHasAFixture(t *testing.T) {
	// Rules whose source has a path assigning findings.Inferred.
	canInfer := []string{"R03", "R04", "R05", "R06", "R07", "R08"}

	seen := map[string][]string{}
	for _, fx := range synth.Fixtures() {
		res, err := analysis.Run(synth.FixturePath(fx.Name, "pcapng"), analysis.Options{})
		if err != nil {
			t.Fatalf("analyse %s: %v", fx.Name, err)
		}
		for _, f := range res.Findings {
			if f.Quality == findings.Inferred {
				seen[f.RuleID] = append(seen[f.RuleID], fx.Name)
			}
		}
	}

	var covered, missing []string
	for _, id := range canInfer {
		if len(seen[id]) > 0 {
			covered = append(covered, id)
		} else {
			missing = append(missing, id)
		}
	}
	t.Logf("inferred path exercised by a fixture: %v", covered)
	if len(missing) > 0 {
		t.Logf("inferred path NOT exercised by any fixture: %v — reported, not fixed: "+
			"a fixture for these is rule work under RULES.md, not display work", missing)
	}
}
