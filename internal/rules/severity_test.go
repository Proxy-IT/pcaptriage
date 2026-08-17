package rules

import (
	"math"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/findings"
)

// TestSeverityAnchors checks the mapping against the reference findings the
// thresholds were derived from, rather than against the thresholds themselves —
// which would only assert that a number equals itself.
//
// The middle anchor is the important one: RULES.md's own R06 example describes
// that case as "worth noting", so the boundary is read off the specification.
func TestSeverityAnchors(t *testing.T) {
	impact := func(seconds float64) float64 {
		v := 1 + 2*math.Log10(1+seconds)
		return math.Min(5, math.Max(1, v))
	}

	cases := []struct {
		name string
		// base weight, seconds lost, scope, deviation
		base, seconds, scope, deviation float64
		want                            findings.Severity
	}{
		{
			name: "mid-weight rule, one second lost, one host, peers clean",
			base: 7, seconds: 1, scope: 1.2, deviation: 3.0,
			want: findings.SeveritySignificant,
		},
		{
			name: "R06 fast retransmit 0.9% against a 0.1% median, 340ms cost",
			base: 4, seconds: 0.34, scope: 1.2, deviation: 3.0,
			want: findings.SeverityWorthNoting,
		},
		{
			name: "R06 at a healthy 0.3%, uniform across the capture",
			base: 4, seconds: 0.04, scope: 1.2, deviation: 1.0,
			want: findings.SeverityInformational,
		},
	}

	for _, c := range cases {
		got := SeverityFor(c.base * impact(c.seconds) * c.scope * c.deviation)
		if got != c.want {
			t.Errorf("%s\n  score %.1f mapped to %q, want %q",
				c.name, c.base*impact(c.seconds)*c.scope*c.deviation, got, c.want)
		}
	}
}

// TestSeverityIsMonotoneAndTotal checks the mapping is a function of the score
// alone, covers every value, and never inverts.
func TestSeverityIsMonotoneAndTotal(t *testing.T) {
	rank := map[findings.Severity]int{
		findings.SeverityInformational: 0,
		findings.SeverityWorthNoting:   1,
		findings.SeveritySignificant:   2,
	}

	last := -1
	for score := 0.0; score <= 400; score += 0.5 {
		got := SeverityFor(score)
		r, ok := rank[got]
		if !ok {
			t.Fatalf("score %.1f produced %q, which is not one of the three", score, got)
		}
		if r < last {
			t.Fatalf("severity went backwards at score %.1f: %q", score, got)
		}
		last = r
		if got.Label() == "" {
			t.Fatalf("severity %q has no word to show beside its colour", got)
		}
	}

	// Negative and absurd scores still resolve rather than falling through.
	for _, s := range []float64{-1, 0, math.MaxFloat64} {
		if SeverityFor(s).Label() == "" {
			t.Errorf("score %v produced no severity", s)
		}
	}
}

// TestSeverityIsNotAFloor is the constraint the BACKLOG P4 note and the RULES.md
// addendum both state: severity labels map onto existing scores and change
// nothing about what is shown.
//
// A future change that made the lowest band mean "hidden" would be a display
// floor introduced as a side effect of badge work, which is the specific thing
// those notes forbid.
func TestSeverityIsNotAFloor(t *testing.T) {
	// Every band resolves to a renderable label. Nothing maps to a sentinel
	// meaning "omit", and there is no fourth state.
	seen := map[findings.Severity]bool{}
	for score := 0.0; score <= 200; score += 0.25 {
		seen[SeverityFor(score)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("expected exactly three severities across the range, got %d: %v", len(seen), seen)
	}
	for s := range seen {
		if s.Label() == "" {
			t.Errorf("severity %q renders as nothing, which would hide a finding", s)
		}
	}
}

// TestCoverageStrengthWithholdsGreen is the neutral-not-green rule.
//
// Green is a visual all-clear. The clean screen's wording is tested against
// claiming one, so colour must not claim it either.
func TestCoverageStrengthWithholdsGreen(t *testing.T) {
	cases := []struct {
		name            string
		gaps, unbuilt   int
		wantStrong      bool
		reasonMustMatch string
	}{
		{"gaps and unbuilt checks — today's state", 1, 13, false, "could not run"},
		{"no gaps but the rule set is incomplete", 0, 13, false, "built"},
		{"complete rule set but this capture had gaps", 1, 0, false, "could not run"},
		{"no gaps, every check built", 0, 0, true, ""},
	}

	for _, c := range cases {
		got := AssessCoverage(c.gaps, c.unbuilt)
		if got.Strong != c.wantStrong {
			t.Errorf("%s: Strong = %v, want %v", c.name, got.Strong, c.wantStrong)
		}
		if c.wantStrong && got.Reason != "" {
			t.Errorf("%s: strong coverage carried a reason %q", c.name, got.Reason)
		}
		if !c.wantStrong && got.Reason == "" {
			t.Errorf("%s: withheld green without saying why", c.name)
		}
	}
}
