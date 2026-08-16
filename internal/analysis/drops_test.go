package analysis_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// runPcapng analyses the pcapng rendering of a fixture.
func runPcapng(t *testing.T, name string) *analysis.Result {
	t.Helper()
	res, err := analysis.Run(synth.FixturePath(name, "pcapng"), analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", name, err)
	}
	return res
}

// noteFor returns the R15 note, which every capture carries exactly one of.
func noteFor(t *testing.T, res *analysis.Result) string {
	t.Helper()
	var found []string
	for _, n := range res.Notes {
		if n.RuleID == "R15" {
			found = append(found, n.Text)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one R15 note, got %d: %v", len(found), found)
	}
	return found[0]
}

// TestKernelDropsAreDetected is the positive fixture: a pcapng whose interface
// statistics say the capture host discarded a large share of what it saw.
//
// This is a correctness fix rather than a feature. Without it the tool would
// report whatever loss it found as loss on the network, which for this capture
// would be a claim it cannot support.
func TestKernelDropsAreDetected(t *testing.T) {
	// Explicitly the pcapng rendering: the counters live in a block classic
	// pcap has no equivalent for, which the format test below covers.
	res := runPcapng(t, "r15-kernel-drops")
	c := res.Capture

	if c.DropAvailability != capture.DropsReported {
		t.Fatalf("availability = %q, want %q — the interface statistics block was not read",
			c.DropAvailability, capture.DropsReported)
	}
	if c.PacketsDropped != 2 {
		t.Errorf("PacketsDropped = %d, want 2", c.PacketsDropped)
	}
	if len(c.InterfaceDrops) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(c.InterfaceDrops))
	}
	if got := c.InterfaceDrops[0].Dropped; got != 2 {
		t.Errorf("interface 0 dropped %d, want 2", got)
	}
	if !c.DropsSignificant {
		t.Errorf("a drop ratio of %.4f was not treated as significant", c.DropRatio)
	}
	// Measured against everything the host saw, not only what it wrote, and an
	// order of magnitude clear of the threshold.
	if c.DropRatio < 0.01 || c.DropRatio > 0.05 {
		t.Errorf("DropRatio = %.4f; 2 dropped against ~96 written should be about 2%%", c.DropRatio)
	}

	note := noteFor(t, res)
	for _, want := range []string{"dropped", "capture loss", "re-capturing"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not mention %q:\n%s", want, note)
		}
	}
	assertAdvisoryText(t, note)
}

// TestNoKernelDropsIsStatedPositively is the negative fixture: statistics
// present, reporting zero. Nothing is downgraded, and the report says so rather
// than staying silent — "the host dropped nothing" is information the reader
// wants when weighing a loss finding.
func TestNoKernelDropsIsStatedPositively(t *testing.T) {
	res := runPcapng(t, "r15-no-kernel-drops")
	c := res.Capture

	if c.DropAvailability != capture.DropsReported {
		t.Fatalf("availability = %q, want %q", c.DropAvailability, capture.DropsReported)
	}
	if c.PacketsDropped != 0 {
		t.Errorf("PacketsDropped = %d, want 0", c.PacketsDropped)
	}
	if c.DropsSignificant {
		t.Error("zero drops was treated as significant")
	}

	note := noteFor(t, res)
	if !strings.Contains(note, "no packets") {
		t.Errorf("the note does not state that nothing was dropped:\n%s", note)
	}
	// The host's own counter says nothing about a tap or SPAN port upstream of
	// it, so the note must not claim the capture point as a whole was clean.
	if strings.Contains(note, "capture point") {
		t.Errorf("the note claims more than the host's counter can support:\n%s", note)
	}
	// It must not read as a warning, and must not suggest re-capturing.
	if strings.Contains(note, "re-capturing") {
		t.Errorf("a clean capture was told to re-capture:\n%s", note)
	}
	assertAdvisoryText(t, note)
}

// TestTrivialDropsAreMentionedButDoNotGate covers the middle branch: the host
// dropped something, but far too little to account for anything a loss rule
// would flag.
//
// Built in memory rather than committed, because it is a variation on the
// positive fixture's shape rather than a distinct case worth carrying in the
// repository.
func TestTrivialDropsAreMentionedButDoNotGate(t *testing.T) {
	// The ratio is measured against packets actually read, so expressing a
	// sub-0.1% drop needs a capture of more than a thousand frames. Two hundred
	// trivial connections is the cheapest way to get there.
	b := synth.New()
	for i := 0; i < 200; i++ {
		c := b.NewConn(synth.ConnOpts{
			Client:    fmt.Sprintf("10.1.1.%d:%d", 1+i%200, 40000+i),
			Server:    "10.2.2.7:443",
			ClientISN: uint32(1000 + i*10),
			ServerISN: uint32(5000 + i*10),
		})
		at := time.Duration(i) * 10 * time.Millisecond
		c.Handshake(at, 10*time.Millisecond)
		c.FinClose(at+50*time.Millisecond, 5*time.Millisecond)
	}
	// One packet in twelve hundred: real, and nowhere near enough to account
	// for anything a loss rule would flag.
	b.WithInterfaceStats(synth.InterfaceStats{Received: 1201, Dropped: 1})

	data, err := b.Pcapng()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trivial.pcapng")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := analysis.Run(path, analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := res.Capture

	if c.PacketsDropped != 1 {
		t.Errorf("PacketsDropped = %d, want 1", c.PacketsDropped)
	}
	if c.DropsSignificant {
		t.Errorf("a drop ratio of %.6f was treated as significant", c.DropRatio)
	}
	if res.Quality.KernelDropsSignificant {
		t.Error("trivial drops set the gating flag")
	}

	note := noteFor(t, res)
	if !strings.Contains(note, "dropped 1 of") {
		t.Errorf("the drop is not reported at all:\n%s", note)
	}
	if strings.Contains(note, "re-capturing") {
		t.Errorf("a trivial drop count prompted a re-capture:\n%s", note)
	}
	for _, n := range res.Notes {
		if n.RuleID == "R15" && n.Kind != "info" {
			t.Errorf("note kind = %q, want info for a below-threshold drop count", n.Kind)
		}
	}
}

// TestClassicPcapCannotReportDrops is the format fixture. Classic pcap has no
// field for this, and the difference between "reported none" and "cannot say"
// is exactly the false all-clear the reporting exists to prevent.
func TestClassicPcapCannotReportDrops(t *testing.T) {
	// The same fixture in the other container: identical traffic, no ISB.
	res, err := analysis.Run(synth.FixturePath("r15-kernel-drops", "pcap"), analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := res.Capture

	if c.DropAvailability != capture.DropsUnsupported {
		t.Fatalf("availability = %q, want %q", c.DropAvailability, capture.DropsUnsupported)
	}
	if c.DropsSignificant {
		t.Error("a format that cannot report drops was treated as reporting significant ones")
	}
	if c.PacketsDropped != 0 {
		t.Errorf("PacketsDropped = %d; unknown must not be counted as a number", c.PacketsDropped)
	}

	note := noteFor(t, res)
	if !strings.Contains(note, "Not assessed") {
		t.Errorf("the note does not mark this as unassessed:\n%s", note)
	}
	for _, want := range []string{"classic pcap", "cannot say", "pcapng"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not mention %q:\n%s", want, note)
		}
	}
	// And it must be an unavailable note, not an informational one — the
	// difference is what stops it being read as reassurance.
	for _, n := range res.Notes {
		if n.RuleID == "R15" && n.Kind != "unavailable" {
			t.Errorf("the note kind is %q, want unavailable", n.Kind)
		}
	}
	assertAdvisoryText(t, note)
}

// TestPcapngWithoutStatisticsIsDistinguished checks the third state: the format
// could carry drop counters, this file has none. Every existing fixture is one.
func TestPcapngWithoutStatisticsIsDistinguished(t *testing.T) {
	res, err := analysis.Run(synth.FixturePath("mixed-findings", "pcapng"), analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Capture.DropAvailability; got != capture.DropsAbsent {
		t.Fatalf("availability = %q, want %q", got, capture.DropsAbsent)
	}

	note := noteFor(t, res)
	if !strings.Contains(note, "no interface statistics") {
		t.Errorf("the note does not explain what is missing:\n%s", note)
	}
	if strings.Contains(note, "classic pcap") {
		t.Errorf("a pcapng was described as classic pcap:\n%s", note)
	}
}

// TestDropGatingSeamIsPopulated checks the flags R05, R06 and R08 will consult
// once they exist. Nothing reads them yet, which is precisely why they need a
// test — an unread field is one that quietly stops being filled.
func TestDropGatingSeamIsPopulated(t *testing.T) {
	dirty := runPcapng(t, "r15-kernel-drops")
	if !dirty.Capture.DropsSignificant {
		t.Fatal("fixture did not produce significant drops")
	}
	basis := dirty.Quality
	if !basis.KernelDropsSignificant {
		t.Error("the gating flag was not set for a capture with significant drops")
	}
	if basis.KernelDropBasis == "" {
		t.Error("no basis sentence was supplied for a degraded finding to state")
	}
	for _, want := range []string{"capture host", "capture loss"} {
		if !strings.Contains(basis.KernelDropBasis, want) {
			t.Errorf("the basis does not mention %q: %q", want, basis.KernelDropBasis)
		}
	}

	clean := runPcapng(t, "r15-no-kernel-drops")
	cleanBasis := clean.Quality
	if cleanBasis.KernelDropsSignificant {
		t.Error("the gating flag was set for a capture that dropped nothing")
	}
	if cleanBasis.KernelDropBasis != "" {
		t.Errorf("a basis was supplied with nothing to justify: %q", cleanBasis.KernelDropBasis)
	}
}

// assertAdvisoryText holds the drop wording to the same posture as the rules:
// it states what was seen and what to do, never what it means.
func assertAdvisoryText(t *testing.T, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, banned := range []string{
		"your network", "is broken", "is faulty", "the cause", "caused by",
		"healthy", "all clear", "no problems",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("wording contains verdict language %q:\n%s", banned, text)
		}
	}
}
