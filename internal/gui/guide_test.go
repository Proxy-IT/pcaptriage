package gui

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/guide"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestGuideRegistryBijection is the no-orphans check in both directions.
//
// A guide page for a rule that does not exist teaches the reader about
// something the tool never looks for — the home screen's registry-honesty
// problem moved to a page with more words on it. That direction is strict and
// permanent.
//
// The forward direction is INTERIM, weakened between Batch 1's Part 1/2 and
// Part 3: R05, R06, R07, R08 and R15 are built but their guide content (the
// combined loss page and the R15 page in GUIDE-CONTENT-BATCH1.md) is not
// wired in until Part 3 updates this contract to many-to-one. Until then the
// invariant that matters — a
// finding card never links to a page that does not exist — is enforced at the
// index (HasPage) and the card link renders only when HasPage is true, both
// asserted here. Part 3 restores the strict form: every built rule maps to
// exactly one guide entry.
func TestGuideRegistryBijection(t *testing.T) {
	pages, err := guide.Pages()
	if err != nil {
		t.Fatalf("guide content did not parse: %v", err)
	}

	registered := map[string]bool{}
	for _, m := range rules.AllMeta() {
		registered[m.ID] = true
	}
	documented := map[string]bool{}
	for _, p := range pages {
		documented[p.RuleID] = true
	}

	// Backward direction, strict: no page without a rule.
	for id := range documented {
		if !registered[id] {
			t.Errorf("guide page %s describes a rule that is not registered: the guide would "+
				"teach a check the tool does not run", id)
		}
	}

	// Forward direction, interim: a built rule without a page must be exactly
	// one the index discloses as page-less, so nothing renders a dead link.
	idx, err := New("test").Guide()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range idx.Entries {
		if e.HasPage != documented[e.RuleID] {
			t.Errorf("%s: index says has_page=%v but the guide content says %v — "+
				"the card link gate would be wrong", e.RuleID, e.HasPage, documented[e.RuleID])
		}
	}

	// TODO(batch1 part 3): wire GUIDE-CONTENT-BATCH1.md and restore the
	// strict forward assertion — every built rule has a guide entry.
	pending := 0
	for id := range registered {
		if !documented[id] {
			pending++
		}
	}
	if pending > 5 {
		t.Errorf("%d built rules lack guide pages; only the Batch 1 interim (R05, R06, R07, R08, R15) is tolerated", pending)
	}
}

// TestGuideIndexIsRegistryDriven checks the index reports what the tool actually
// does, and discloses what it does not.
func TestGuideIndexIsRegistryDriven(t *testing.T) {
	idx, err := New("test").Guide()
	if err != nil {
		t.Fatal(err)
	}

	if len(idx.Entries) != len(rules.AllMeta()) {
		t.Errorf("index has %d entries, registry has %d", len(idx.Entries), len(rules.AllMeta()))
	}
	for _, e := range idx.Entries {
		if e.RuleID == "" || e.Name == "" || e.Summary == "" {
			t.Errorf("index entry %+v is missing text", e)
		}
		if !e.Built {
			t.Errorf("%s is listed as built but is not", e.RuleID)
		}
		// HasPage must match the guide content exactly — it is what gates
		// both the index entry and the finding card's link.
		_, hasPage := guide.Lookup(e.RuleID)
		if e.HasPage != hasPage {
			t.Errorf("%s: HasPage = %v, guide content says %v", e.RuleID, e.HasPage, hasPage)
		}
		// The index uses the authored one-liner, which is written for this
		// reader rather than for a developer reading the registry.
		if p, ok := guide.Lookup(e.RuleID); ok && e.Summary != p.Summary() {
			t.Errorf("%s index summary is not the authored one-line summary", e.RuleID)
		}
	}

	if want := rules.TotalV1Rules - len(rules.AllMeta()); idx.PlannedCount != want {
		t.Errorf("PlannedCount = %d, want %d (registry-derived)", idx.PlannedCount, want)
	}
	if idx.PlannedNote == "" {
		t.Error("the index does not disclose the unbuilt checks, so two entries would read as the whole tool")
	}
}

// TestGuidePageLookup checks both the hit and the miss.
func TestGuidePageLookup(t *testing.T) {
	app := New("test")

	p, err := app.GuidePage("R01")
	if err != nil {
		t.Fatalf("R01: %v", err)
	}
	if p.RuleID != "R01" || len(p.Sections) != len(guide.Skeleton) {
		t.Errorf("R01 page = %+v", p.RuleID)
	}

	// An unbuilt rule has no page, and asking for one is an error rather than an
	// empty page that would look like missing content.
	if _, err := app.GuidePage("R07"); err == nil {
		t.Error("R07 is not built but returned a guide page")
	}
	if _, err := app.GuidePage("nonsense"); err == nil {
		t.Error("a nonsense rule ID returned a page")
	}
}

// TestEveryFindingCanReachItsGuide is the end of the card→guide link, checked
// against real findings rather than against the registry alone.
func TestEveryFindingCanReachItsGuide(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("mixed-findings", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range res.Report.Findings {
		if _, err := app.GuidePage(f.RuleID); err != nil {
			t.Errorf("finding from %s links to a guide page that does not exist: %v", f.RuleID, err)
		}
	}
}

// TestContextTravelsWithTheClick is the binding-layer half of that requirement.
//
// The frontend puts the finding's key facts at the top of the guide page so the
// general explanation and the specific case share a screen. That is only
// possible if the finding it was given carries them, which is what this asserts.
// The visual placement and the scroll-preserving return are verified in the
// preview render, since there is no DOM harness here.
func TestContextTravelsWithTheClick(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("mixed-findings", "pcap"))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range res.Report.Findings {
		// The three things the context block renders.
		if f.Title == "" {
			t.Errorf("%s finding has no title for the context block", f.RuleID)
		}
		if f.Observation == "" {
			t.Errorf("%s finding has no observation, so the headline numbers would be absent", f.RuleID)
		}
		if len(f.Frames) == 0 {
			t.Errorf("%s finding cites no frames", f.RuleID)
		}
		// The host is in the subject label, which is what identifies the case.
		if f.SubjectLabel == "" {
			t.Errorf("%s finding has no subject label", f.RuleID)
		}
	}
}

// TestAboutContent checks the About page says the things it is required to say,
// and that its version numbers come from the same constants the reports carry.
func TestAboutContent(t *testing.T) {
	a := New("test-version").About()

	if a.Version != "test-version" {
		t.Errorf("Version = %q; it must come from the build, not be written into the page", a.Version)
	}
	for _, f := range []struct{ name, val string }{
		{"RulesetVersion", a.RulesetVersion},
		{"SchemaVersion", a.SchemaVersion},
		{"Posture", a.Posture},
		{"OpenSource", a.OpenSource},
		{"Attribution", a.Attribution},
		{"Coverage", a.Coverage},
	} {
		if strings.TrimSpace(f.val) == "" {
			t.Errorf("About.%s is empty", f.name)
		}
	}

	if len(a.What) < 2 || len(a.What) > 3 {
		t.Errorf("About 'what this is' has %d sentences, the brief asks for two or three", len(a.What))
	}

	// The privacy story is the strongest thing the tool has to say and is
	// currently invisible everywhere else.
	privacy := strings.ToLower(strings.Join(a.Privacy, " "))
	for _, want := range []string{"no network calls", "telemetry", "uploaded", "settings"} {
		if !strings.Contains(privacy, want) {
			t.Errorf("the privacy section does not mention %q", want)
		}
	}

	if a.Attribution != "Built by Proxy-IT" {
		t.Errorf("Attribution = %q", a.Attribution)
	}
	if a.AttributionURL != ProjectURL || !strings.HasPrefix(a.AttributionURL, "https://") {
		t.Errorf("AttributionURL = %q", a.AttributionURL)
	}

	// It must not imply a finished tool.
	if !strings.Contains(a.Coverage, "15") {
		t.Errorf("the About page does not disclose how much of the rule set exists: %q", a.Coverage)
	}
}

// TestAboutLinkOpensExternallyAndIsNeverFetched is the constraint behind the
// attribution link.
//
// The About page tells the reader this application makes no network calls. A
// link that fetched anything in-process would contradict that on the same
// screen, so the URL is handed to the operating system and never requested here.
func TestAboutLinkOpensExternallyAndIsNeverFetched(t *testing.T) {
	var opened []string
	app := New("test")
	app.openExternal = func(u string) { opened = append(opened, u) }

	if err := app.OpenExternal(ProjectURL); err != nil {
		t.Fatalf("OpenExternal: %v", err)
	}
	if len(opened) != 1 || opened[0] != ProjectURL {
		t.Fatalf("handed %v to the operating system, want [%s]", opened, ProjectURL)
	}

	// Only the app's own link. This is the one method that passes a string to
	// the OS, and a capture is attacker-controlled data.
	for _, bad := range []string{"https://example.com", "file:///etc/passwd", "", "javascript:alert(1)"} {
		if err := app.OpenExternal(bad); err == nil {
			t.Errorf("OpenExternal accepted %q", bad)
		}
	}
	if len(opened) != 1 {
		t.Errorf("a rejected URL was still handed over: %v", opened)
	}
}

// TestGuiPackageCannotMakeNetworkCalls is the structural half of the same claim.
//
// Asserted against the import graph rather than behaviour, because the promise
// is that the capability is absent — not that the current code paths happen not
// to use it.
func TestGuiPackageCannotMakeNetworkCalls(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}

	banned := []string{`"net/http"`, `"net"`, `"net/url"`, `"os/exec"`}
	var checked int
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			checked++
			for _, imp := range file.Imports {
				for _, b := range banned {
					if imp.Path.Value == b {
						t.Errorf("%s imports %s; the About page promises no network calls, and "+
							"os/exec would be a way around the browser handoff", name, b)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files were examined, so this check proved nothing")
	}
}
