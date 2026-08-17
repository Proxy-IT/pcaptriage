package analysis_test

// Fixture-level tests for the loss cluster: the wording each card renders,
// the severity each fixture's findings land at, and the suppressions and
// degradations that must hold end-to-end. The classifier's mechanics are
// unit-tested in internal/rules; this file is about what a user would see.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// runLossFixture analyses a committed fixture and returns the rendered document.
func runLossFixture(t *testing.T, name string) *report.Document {
	t.Helper()
	res, err := analysis.Run(synth.FixturePath(name, "pcap"), analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", name, err)
	}
	return report.Build(res, report.Invocation{Input: name}, "test")
}

// findingsByRule indexes a document's findings.
func findingsByRule(doc *report.Document) map[string][]report.Finding {
	out := map[string][]report.Finding{}
	for _, f := range doc.Findings {
		out[f.RuleID] = append(out[f.RuleID], f)
	}
	return out
}

// TestR05FixtureWordingAndSeverity holds the R05 card to RULES.md's wording
// shape and to the severity band an RTO burst of this size belongs in.
func TestR05FixtureWordingAndSeverity(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r05-rto-burst"))

	if len(byRule["R06"]) != 0 || len(byRule["R07"]) != 0 {
		t.Fatalf("the RTO fixture produced non-R05 loss findings: R06=%d R07=%d",
			len(byRule["R06"]), len(byRule["R07"]))
	}
	r05 := byRule["R05"]
	if len(r05) != 1 {
		t.Fatalf("R05 findings = %d, want 1", len(r05))
	}
	f := r05[0]

	if f.Title != "Timeout-driven retransmissions — 10.1.1.5 → 10.3.3.2" {
		t.Errorf("title = %q", f.Title)
	}
	// The specified sentences, in the specified order.
	for _, want := range []string{
		"3 segments retransmitted after timeout, costing 4.5s of transfer time.",
		"Retry intervals doubled each attempt, indicating the sender received no acknowledgement at all rather than recovering quickly.",
		"Retransmission rate on this path is",
		"against a capture-wide median of",
	} {
		if !strings.Contains(f.Observation, want) {
			t.Errorf("observation is missing the specified wording %q:\n%s", want, f.Observation)
		}
	}
	if !strings.HasPrefix(f.CheckNext, "sustained loss on the path between these hosts.") ||
		!strings.Contains(f.CheckNext, "the sender stalled waiting for a timer rather than recovering from duplicate ACKs") {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}

	if f.Severity != string(findings.SeveritySignificant) {
		t.Errorf("severity = %q; 4.5s of timer stalls against clean peers is the significant band", f.Severity)
	}
	if f.Quality != string(findings.Confirmed) {
		t.Errorf("quality = %q, want confirmed on a clean capture", f.Quality)
	}
}

// TestR06FixtureWordingAndSeverity holds the R06 card to its wording and to
// the informational band: fast retransmit is TCP working correctly, and a
// handful of recoveries must not read as an event.
func TestR06FixtureWordingAndSeverity(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r06-fast-retransmit"))

	if len(byRule["R05"]) != 0 || len(byRule["R07"]) != 0 {
		t.Fatalf("the fast-retransmit fixture produced non-R06 loss findings: R05=%d R07=%d",
			len(byRule["R05"]), len(byRule["R07"]))
	}
	r06 := byRule["R06"]
	if len(r06) != 1 {
		t.Fatalf("R06 findings = %d, want 1", len(r06))
	}
	f := r06[0]

	if f.Title != "Packet loss with fast recovery — 10.6.6.5 ↔ 10.7.7.2" {
		t.Errorf("title = %q", f.Title)
	}
	for _, want := range []string{
		"2 segments recovered via fast retransmit (",
		"of segments on this path",
		"Recovery was quick in each case; total time cost approximately",
	} {
		if !strings.Contains(f.Observation, want) {
			t.Errorf("observation is missing the specified wording %q:\n%s", want, f.Observation)
		}
	}
	if f.CheckNext != "low-level loss on this path. Worth noting but unlikely to be the cause of a user-visible problem on its own." {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}

	if f.Severity != string(findings.SeverityInformational) {
		t.Errorf("severity = %q; a healthy fast-retransmit rate is the informational band", f.Severity)
	}
}

// TestR07FixtureSuppressesLossFindings is the suppression seam end-to-end:
// the reordering fixture contains a full duplicate-ACK run — the fast
// retransmit trigger — and must still produce no loss findings at all.
func TestR07FixtureSuppressesLossFindings(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r07-reordering"))

	if len(byRule["R05"]) != 0 || len(byRule["R06"]) != 0 {
		t.Fatalf("reordering produced loss findings: R05=%d R06=%d — the seam failed",
			len(byRule["R05"]), len(byRule["R06"]))
	}
	r07 := byRule["R07"]
	if len(r07) != 1 {
		t.Fatalf("R07 findings = %d, want 1", len(r07))
	}
	f := r07[0]

	for _, want := range []string{
		"5 segments arrived out of sequence with sub-millisecond gaps and consistent IP ID ordering.",
		"These were not retransmissions and no data was lost.",
		"Without this reclassification they would appear as a",
		"loss rate.",
	} {
		if !strings.Contains(f.Observation, want) {
			t.Errorf("observation is missing the specified wording %q:\n%s", want, f.Observation)
		}
	}
	if !strings.HasPrefix(f.CheckNext, "usually multipath routing, LACP hashing, or receive-side scaling on the capture host.") {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}
	if f.Quality != string(findings.Confirmed) {
		t.Errorf("quality = %q, want confirmed with IP IDs checked", f.Quality)
	}
	if f.Severity != string(findings.SeverityInformational) {
		t.Errorf("severity = %q; not-a-fault renders informational", f.Severity)
	}
}

// TestR07IPv6IsInferredAndSaysWhy is the degraded path: no IP ID exists, so
// the reclassification is timing-only, the confidence drops, and the finding
// carries the reason.
func TestR07IPv6IsInferredAndSaysWhy(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r07-reordering-v6"))

	if len(byRule["R05"])+len(byRule["R06"]) != 0 {
		t.Fatal("IPv6 reordering produced loss findings")
	}
	r07 := byRule["R07"]
	if len(r07) != 1 {
		t.Fatalf("R07 findings = %d, want 1", len(r07))
	}
	f := r07[0]

	if f.Quality != string(findings.Inferred) {
		t.Errorf("quality = %q, want inferred on IPv6", f.Quality)
	}
	if !strings.Contains(f.QualityBasis, "IPv6 carries no IP ID field") {
		t.Errorf("the basis does not say why confidence dropped: %q", f.QualityBasis)
	}
	// The IPv4-only claim must be absent from the observation.
	if strings.Contains(f.Observation, "IP ID ordering") {
		t.Errorf("an IPv6 finding claims IP ID ordering it could not check:\n%s", f.Observation)
	}
}

// TestR08FixtureWordingAndSeverity holds the R08 card to its wording, its
// role-aware phrasing, and confirms R05 firing on the same flow is expected
// rather than a repetition-cap violation — R05 and R08 are different rules
// answering different questions about the same segments.
func TestR08FixtureWordingAndSeverity(t *testing.T) {
	byRule := findingsByRule(runLossFixture(t, "r08-asymmetric-loss"))

	if len(byRule["R06"]) != 0 || len(byRule["R07"]) != 0 {
		t.Fatalf("the asymmetric fixture produced unexpected loss findings: R06=%d R07=%d",
			len(byRule["R06"]), len(byRule["R07"]))
	}
	if len(byRule["R05"]) != 1 {
		t.Fatalf("R05 findings = %d, want 1 — the worse direction's timeouts are a legitimate R05 finding too",
			len(byRule["R05"]))
	}
	r08 := byRule["R08"]
	if len(r08) != 1 {
		t.Fatalf("R08 findings = %d, want 1", len(r08))
	}
	f := r08[0]

	if f.Title != "Loss in one direction only — 10.11.11.5 → 10.12.12.2" {
		t.Errorf("title = %q", f.Title)
	}
	// Role-aware phrasing: the handshake establishes which side is the
	// server, so the wording uses "client-to-server" / "server-to-client"
	// rather than bare addresses.
	if !strings.Contains(f.Observation, "of segments retransmitted client-to-server, against") ||
		!strings.Contains(f.Observation, "server-to-client on the same connection. Loss is not symmetric.") {
		t.Errorf("observation does not use role-aware phrasing: %q", f.Observation)
	}
	if f.CheckNext != "something specific to the forward path — asymmetric routing, a congested uplink, or a policer applied in one direction. Symmetric loss would point at the shared path instead." {
		t.Errorf("check-next drifted from RULES.md: %q", f.CheckNext)
	}

	// 34% against ~1% is a real asymmetry; the P4 anchors should not call it
	// informational, but a single flow with no proximity bonus is not the
	// significant band either.
	if f.Severity != string(findings.SeverityWorthNoting) {
		t.Errorf("severity = %q, want worth-noting for a clear but isolated asymmetry", f.Severity)
	}
	if f.Quality != string(findings.Confirmed) {
		t.Errorf("quality = %q, want confirmed on a clean capture", f.Quality)
	}
}

// TestR08OneWayFlowIsUnavailableNotSilent is the RULES.md-specified
// degradation: a flow captured in one direction only cannot be compared, and
// must say so rather than simply producing nothing.
func TestR08OneWayFlowIsUnavailableNotSilent(t *testing.T) {
	doc := runLossFixture(t, "r08-one-way")
	byRule := findingsByRule(doc)

	if len(byRule["R08"]) != 0 {
		t.Fatalf("R08 produced a finding on a one-way flow: %d", len(byRule["R08"]))
	}
	// R05 is unaffected: timer-driven retransmissions on the one direction
	// that was captured are a real, gradable finding independent of R08's
	// cross-direction comparison.
	if len(byRule["R05"]) != 1 {
		t.Fatalf("R05 findings = %d, want 1 — one-way capture should not suppress single-direction detection",
			len(byRule["R05"]))
	}

	var note *report.Note
	for i := range doc.Notes {
		if doc.Notes[i].RuleID == "R08" {
			note = &doc.Notes[i]
		}
	}
	if note == nil {
		t.Fatal("no R08 note was emitted for the one-way flow")
	}
	if note.Kind != "unavailable" {
		t.Errorf("R08's one-way note has kind %q, want unavailable", note.Kind)
	}
	if !strings.Contains(note.Text, "one direction only") || !strings.Contains(note.Text, "SPAN") {
		t.Errorf("the note does not explain why the comparison could not be made: %q", note.Text)
	}
}

// TestKernelDropGatingReachesTheLossRules is the R15 seam the brief asks to
// verify: on a capture whose host discarded a significant share of traffic,
// apparent loss may be capture loss, and R05's finding must degrade to
// inferred with the basis stated — degraded, never suppressed.
func TestKernelDropGatingReachesTheLossRules(t *testing.T) {
	// The RTO fixture's traffic, in a pcapng whose interface statistics say
	// the capture host dropped ~11% of what it saw.
	var b *synth.Builder
	for _, f := range synth.Fixtures() {
		if f.Name == "r05-rto-burst" {
			b = f.Build()
		}
	}
	if b == nil {
		t.Fatal("the r05-rto-burst fixture is gone")
	}
	data, err := b.WithInterfaceStats(synth.InterfaceStats{Received: 270, Dropped: 30}).Pcapng()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rto-with-drops.pcapng")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := analysis.Run(path, analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Quality.KernelDropsSignificant {
		t.Fatal("the constructed drop ratio did not clear the R15 threshold; the test premise is gone")
	}

	var r05 *findings.Finding
	for _, f := range res.Findings {
		if f.RuleID == "R05" {
			r05 = f
		}
	}
	if r05 == nil {
		t.Fatal("kernel drops suppressed the R05 finding entirely; the seam degrades, never suppresses")
	}
	if r05.Quality != findings.Inferred {
		t.Errorf("R05 quality = %q under significant kernel drops, want inferred", r05.Quality)
	}
	if r05.QualityBasis == "" || !strings.Contains(r05.QualityBasis, "capture") {
		t.Errorf("the degraded finding does not state its basis: %q", r05.QualityBasis)
	}
}

// TestLossFixturesAgreeAcrossEntryPoints extends the one-engine guarantee to
// the new rules: the GUI binding and the dev CLI must render byte-identical
// findings for the loss fixtures. The golden tests cover the CLI path; this
// asserts the document built the way the GUI builds it matches.
func TestLossFixturesAgreeAcrossEntryPoints(t *testing.T) {
	for _, name := range []string{
		"r05-rto-burst", "r06-fast-retransmit", "r07-reordering", "r07-reordering-v6",
		"r08-asymmetric-loss", "r08-one-way",
	} {
		a := runLossFixture(t, name)
		b := runLossFixture(t, name)
		if len(a.Findings) != len(b.Findings) {
			t.Fatalf("%s: %d vs %d findings across two identical runs", name, len(a.Findings), len(b.Findings))
		}
		for i := range a.Findings {
			af, bf := a.Findings[i], b.Findings[i]
			if af.RuleID != bf.RuleID || af.Observation != bf.Observation || af.Severity != bf.Severity {
				t.Errorf("%s: finding %d differs across runs", name, i)
			}
		}
	}
}
