package analysis_test

// Fixture-level tests for the connection-lifecycle rules: the wording each
// card renders, the severity it lands at, and the two suppressions that stop
// R02 and R03 reporting things they cannot actually support.

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/report"
)

// TestR02FixtureWordingAndSeverity holds the R02 card to RULES.md's wording.
func TestR02FixtureWordingAndSeverity(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r02-syn-unanswered"))

	if len(byRule["R03"]) != 0 {
		t.Errorf("the unanswered fixture produced %d R03 findings; nothing was refused here", len(byRule["R03"]))
	}
	r02 := byRule["R02"]
	if len(r02) != 1 {
		t.Fatalf("R02 findings = %d, want 1", len(r02))
	}
	f := r02[0]

	if f.Title != "Connection attempts received no response — 10.1.1.5 → 10.4.4.9:8443" {
		t.Errorf("title = %q", f.Title)
	}
	for _, want := range []string{
		"5 SYN attempts over 15.0s, no SYN/ACK and no RST returned.",
		"The client retried with standard backoff.",
		"Other services on 10.4.4.9 responded normally.",
	} {
		if !strings.Contains(f.Observation, want) {
			t.Errorf("observation is missing the specified wording %q:\n%s", want, f.Observation)
		}
	}
	if f.CheckNext != "a silent drop, not a closed port — a closed port returns RST. Look at firewall or security group rules on the path, or whether the listener is bound to a different interface." {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}
	if f.Quality != string(findings.Confirmed) {
		t.Errorf("quality = %q, want confirmed", f.Quality)
	}
	if f.Severity != string(findings.SeverityWorthNoting) {
		t.Errorf("severity = %q; fifteen seconds of unanswered attempts against clean peers is the worth-noting band", f.Severity)
	}
}

// TestR02SaysNothingItCannotSupport covers the two conditional clauses. Each
// is stated only when true of the capture, per the standing rule that a
// measured claim is never a fixed string.
func TestR02SaysNothingItCannotSupport(t *testing.T) {
	// The asymmetric-routing caveat is the interesting one: an unanswered
	// attempt is one-way by construction — that is the condition being
	// reported — so the finding must not cite its own flow as evidence that
	// the capture point misses reply paths. This fixture has no independently
	// one-way flow, so the caveat must be absent.
	f := findingsByRule(runLossFixture(t, "r02-syn-unanswered"))["R02"][0]
	if strings.Contains(f.Observation, "one direction only") {
		t.Errorf("R02 cited its own one-way flow as evidence of asymmetric routing — circular:\n%s",
			f.Observation)
	}
}

// TestR02NegativeAndSuppression covers both cases where R02 must stay quiet.
func TestR02NegativeAndSuppression(t *testing.T) {
	// Answered attempts, including one retried before being answered.
	if got := findingsByRule(runLossFixture(t, "r02-syn-answered"))["R02"]; len(got) != 0 {
		t.Errorf("R02 fired on answered connections: %d findings", len(got))
	}

	// RULES.md's suppression: the capture stopped while the handshake was
	// still in flight, so silence was never observed.
	doc := runLossFixture(t, "r02-capture-truncated")
	if got := findingsByRule(doc)["R02"]; len(got) != 0 {
		t.Errorf("R02 fired on attempts inside the capture-end window: %d findings", len(got))
	}
	// Suppressed, not silent: a reader must be able to tell that something was
	// set aside and why.
	var note *report.Note
	for i := range doc.Notes {
		if doc.Notes[i].RuleID == "R02" {
			note = &doc.Notes[i]
		}
	}
	if note == nil {
		t.Fatal("nothing was said about the suppressed attempts; a quiet result must not hide them")
	}
	if !strings.Contains(note.Text, "capture ended") {
		t.Errorf("the note does not explain why the attempts were not reported: %q", note.Text)
	}
}

// TestR03FixtureWordingAndSeverity holds the R03 card to RULES.md's wording.
func TestR03FixtureWordingAndSeverity(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r03-syn-rejected"))

	if len(byRule["R02"]) != 0 {
		t.Errorf("a refused attempt also produced %d R02 findings; a refusal is an answer, "+
			"and reporting it twice under two names would double-count it", len(byRule["R02"]))
	}
	r03 := byRule["R03"]
	if len(r03) != 1 {
		t.Fatalf("R03 findings = %d, want 1 (one per refusing server:port)", len(r03))
	}
	f := r03[0]

	if f.Title != "Connections actively refused — 10.4.4.9:8443" {
		t.Errorf("title = %q", f.Title)
	}
	if !strings.Contains(f.Observation, "9 connection attempts from 3 clients answered with RST.") ||
		!strings.Contains(f.Observation, "The host is reachable and responding; nothing is listening on that port.") {
		t.Errorf("observation drifted from RULES.md:\n%s", f.Observation)
	}
	if f.CheckNext != "whether the service is running and bound to the expected port and address. Distinct from R02 — the host itself is up and answering." {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}
	if f.ScopeKind != string(findings.ScopeEndpoint) {
		t.Errorf("scope kind = %q; the wording counts attempts and clients per server:port", f.ScopeKind)
	}
	if f.Quality != string(findings.Confirmed) {
		t.Errorf("quality = %q, want confirmed when the reset's TTL agrees with its host", f.Quality)
	}
}

// TestR03NegativeDoesNotReadAClosingResetAsARefusal is the distinction the
// negative fixture exists for: a reset that ends a completed transfer is a way
// of closing, not a way of refusing.
func TestR03NegativeDoesNotReadAClosingResetAsARefusal(t *testing.T) {
	if got := findingsByRule(runLossFixture(t, "r03-syn-accepted"))["R03"]; len(got) != 0 {
		t.Errorf("R03 read a connection-closing reset as a refusal: %d findings", len(got))
	}
}

// TestR03ForgedResetIsInferredAndSaysWhy is RULES.md's false-positive trap: a
// reset whose TTL disagrees with its host's own traffic may not have come from
// that host, and the finding degrades rather than either dropping the
// observation or asserting forgery.
func TestR03ForgedResetIsInferredAndSaysWhy(t *testing.T) {
	r03 := findingsByRule(runLossFixture(t, "r03-forged-reset"))["R03"]
	if len(r03) != 1 {
		t.Fatalf("R03 findings = %d, want 1", len(r03))
	}
	f := r03[0]

	if f.Quality != string(findings.Inferred) {
		t.Errorf("quality = %q, want inferred when the reset's TTL disagrees with its host", f.Quality)
	}
	for _, want := range []string{"TTL of 62", "arrived with 52", "on the host's behalf"} {
		if !strings.Contains(f.QualityBasis, want) {
			t.Errorf("the basis does not say %q: %q", want, f.QualityBasis)
		}
	}
	// Degraded, never suppressed: the refusals were observed either way, and
	// what is in doubt is only who sent them.
	if f.TotalCount != 5 {
		t.Errorf("TotalCount = %d, want all 5 refusals still reported", f.TotalCount)
	}
	// And the observation itself must not assert forgery — that belongs in the
	// basis, hedged, because the capture cannot establish it.
	if strings.Contains(strings.ToLower(f.Observation), "forge") ||
		strings.Contains(strings.ToLower(f.Observation), "spoof") {
		t.Errorf("the observation asserts forgery the capture cannot establish:\n%s", f.Observation)
	}
}
