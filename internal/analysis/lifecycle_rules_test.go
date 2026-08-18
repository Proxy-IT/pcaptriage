package analysis_test

// Fixture-level tests for R09 and R14: the wording each card renders, the
// severity it lands at, and the three cases where these rules must decline to
// report something that superficially matches their condition.

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/report"
)

// TestR09FixtureWordingAndSeverity holds the R09 card to RULES.md's wording.
func TestR09FixtureWordingAndSeverity(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r09-reset-mid-transfer"))

	r09 := byRule["R09"]
	if len(r09) != 1 {
		t.Fatalf("R09 findings = %d, want 1 (one per resetting host)", len(r09))
	}
	f := r09[0]

	if f.Title != "Connections reset during active transfer — 10.2.2.7" {
		t.Errorf("title = %q", f.Title)
	}
	for _, want := range []string{
		"8 connections terminated by RST while data was still in flight",
		"transferred before the reset.",
		"The remaining 12 connections in this capture closed normally with FIN.",
	} {
		if !strings.Contains(f.Observation, want) {
			t.Errorf("observation is missing the specified wording %q:\n%s", want, f.Observation)
		}
	}
	if !strings.HasPrefix(f.CheckNext, "an application-side abort, a resource limit, or a stateful device on the path dropping the session.") {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}
	// The TTL sentence is part of the specified wording and is stated only
	// when the comparison was actually made.
	if !strings.Contains(f.CheckNext, "TTL on these resets matches the peer's other traffic") {
		t.Errorf("check-next omits the TTL comparison: %q", f.CheckNext)
	}

	// A real interruption, not a habit: this host closed other connections
	// cleanly, so the uniformity downgrade must not apply.
	if f.Severity != string(findings.SeverityWorthNoting) {
		t.Errorf("severity = %q; eight interrupted transfers against clean closes on the same host "+
			"is the worth-noting band", f.Severity)
	}
	if f.Metrics["uniform_reset_habit"] != false {
		t.Errorf("uniform_reset_habit = %v on a host that also closed connections cleanly",
			f.Metrics["uniform_reset_habit"])
	}
}

// TestR09IgnoresEndingsThatAreNotInterruptions covers the two cases RULES.md
// carves out of this rule, both of which look superficially like its
// condition.
func TestR09IgnoresEndingsThatAreNotInterruptions(t *testing.T) {
	// A reset ten seconds after the last data segment ended an idle
	// connection, and a reset standing in for a FIN once everything had been
	// acknowledged is a way of closing rather than an interruption. The
	// negative fixture holds both.
	if got := findingsByRule(runLossFixture(t, "r09-clean-close"))["R09"]; len(got) != 0 {
		t.Errorf("R09 fired on connections that were not interrupted: %d findings", len(got))
	}

	// The same carve-out, reached from the other direction: R03's negative
	// fixture closes one completed transfer with a reset, and R09 must not
	// claim it either. This is the cross-rule case the tshark harness caught.
	if got := findingsByRule(runLossFixture(t, "r03-syn-accepted"))["R09"]; len(got) != 0 {
		t.Errorf("R09 read a reset that closed a fully-acknowledged transfer as an interruption: %d findings",
			len(got))
	}
}

// TestR09UniformResetHabitIsDowngraded is RULES.md's false-positive trap:
// some applications close with RST deliberately, and a host that does it to
// every connection is exhibiting a habit rather than failing repeatedly.
func TestR09UniformResetHabitIsDowngraded(t *testing.T) {
	r09 := findingsByRule(runLossFixture(t, "r09-uniform-reset"))["R09"]
	if len(r09) != 1 {
		t.Fatalf("R09 findings = %d, want 1", len(r09))
	}
	f := r09[0]

	// Downgraded, not suppressed: every reset is still counted and shown.
	if f.TotalCount != 14 {
		t.Errorf("TotalCount = %d, want all 14 resets still reported", f.TotalCount)
	}
	if f.Severity != string(findings.SeverityInformational) {
		t.Errorf("severity = %q; a host that resets every connection is a pattern, not a fault", f.Severity)
	}
	if f.Metrics["uniform_reset_habit"] != true {
		t.Errorf("uniform_reset_habit = %v on a host with no clean close anywhere",
			f.Metrics["uniform_reset_habit"])
	}
	// And it must say why it is being presented as context, or a reader has no
	// way to tell this apart from fourteen ordinary failures.
	if !strings.Contains(f.Observation, "a consistent habit rather than something that went wrong") {
		t.Errorf("the finding does not explain the downgrade:\n%s", f.Observation)
	}
}

// TestR14FixtureWordingAndSeverity holds the R14 card to RULES.md's wording.
func TestR14FixtureWordingAndSeverity(t *testing.T) {
	r14 := findingsByRule(runLossFixture(t, "r14-connection-churn"))["R14"]
	if len(r14) != 1 {
		t.Fatalf("R14 findings = %d, want 1 (one per server:port)", len(r14))
	}
	f := r14[0]

	if f.Title != "Rapid connection cycling — 10.1.1.5 → 10.2.2.7:5432" {
		t.Errorf("title = %q", f.Title)
	}
	for _, want := range []string{
		"60 connections opened and closed in",
		"median lifetime",
		"Each connection completed a full handshake and teardown, adding roughly",
		"of setup overhead per request.",
	} {
		if !strings.Contains(f.Observation, want) {
			t.Errorf("observation is missing the specified wording %q:\n%s", want, f.Observation)
		}
	}
	if f.CheckNext != "connection pooling configuration on the client, or an idle timeout closing pooled connections sooner than expected. Functionally working, but the handshake overhead is measurable at this rate." {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}

	// The long-lived connection to another port on the same host is being
	// reused properly and must not have been swept in.
	if f.TotalCount != 60 {
		t.Errorf("TotalCount = %d, want 60 — the reused connection is not churn", f.TotalCount)
	}
	// "Functionally working" is RULES.md's own framing, so this belongs in the
	// bottom band however many connections there are.
	if f.Severity != string(findings.SeverityInformational) {
		t.Errorf("severity = %q; RULES.md calls this functionally working", f.Severity)
	}
}

// TestR14DoesNotFireOnHealthyReuse is the negative case.
func TestR14DoesNotFireOnHealthyReuse(t *testing.T) {
	if got := findingsByRule(runLossFixture(t, "r14-connection-reuse"))["R14"]; len(got) != 0 {
		t.Errorf("R14 fired on connections that were being reused: %d findings", len(got))
	}
}

// TestR14MidstreamIsUnavailableNotSilent is RULES.md's specified degradation:
// lifetime cannot be measured without the opening handshake, so a capture that
// missed them reports that the check could not run rather than reporting
// nothing.
func TestR14MidstreamIsUnavailableNotSilent(t *testing.T) {
	doc := runLossFixture(t, "r14-midstream")

	if got := findingsByRule(doc)["R14"]; len(got) != 0 {
		t.Errorf("R14 reported a finding from connections whose lifetimes it could not measure: %d", len(got))
	}

	var note *report.Note
	for i := range doc.Notes {
		if doc.Notes[i].RuleID == "R14" {
			note = &doc.Notes[i]
		}
	}
	if note == nil {
		t.Fatal("no R14 note; a check that could not run must say so rather than staying quiet")
	}
	if note.Kind != "unavailable" {
		t.Errorf("note kind = %q, want unavailable", note.Kind)
	}
	// The proportion excluded is what RULES.md specifically requires be
	// reported, so a reader can tell how much of the picture is missing.
	for _, want := range []string{"55 of 60", "10.10.10.7:5432", "opening handshake"} {
		if !strings.Contains(note.Text, want) {
			t.Errorf("the note does not state %q: %q", want, note.Text)
		}
	}
}
