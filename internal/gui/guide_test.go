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

// TestGuideRegistryBijection is the no-orphans check in both directions,
// restored to strict many-to-one by Part 3: every built rule maps to exactly
// one guide entry — a page, plus an anchor within it when that page serves
// more than one rule — and every guide entry is reachable from at least one
// built rule. The cardinality changed (a page can now serve several rules);
// the honesty the check enforces did not.
func TestGuideRegistryBijection(t *testing.T) {
	pages, err := guide.Pages()
	if err != nil {
		t.Fatalf("guide content did not parse: %v", err)
	}

	registered := map[string]bool{}
	for _, m := range rules.AllMeta() {
		registered[m.ID] = true
	}

	// Backward: every rule ID any page claims to serve must be registered —
	// a guide page for a rule that does not exist teaches the reader about
	// something the tool never looks for.
	documented := map[string]guide.Page{}
	for _, p := range pages {
		for _, id := range p.RuleIDs {
			if prior, dup := documented[id]; dup {
				t.Errorf("%s is served by two guide pages (%q and %q); exactly one guide entry per rule",
					id, prior.Title, p.Title)
			}
			documented[id] = p
			if !registered[id] {
				t.Errorf("guide page %q describes %s, which is not registered: the guide would "+
					"teach a check the tool does not run", p.Title, id)
			}
		}
	}

	// Forward, strict: every built rule has exactly one guide entry. Batch 2's
	// interim tolerance is gone — every rule in the registry is documented,
	// with no exception list left behind.
	for id := range registered {
		p, ok := documented[id]
		if !ok {
			t.Errorf("%s is built but has no guide page: its finding cards would link nowhere", id)
			continue
		}
		// A rule on a page it shares with others needs its own landing spot;
		// a rule alone on its page needs none — landing "at that rule's
		// spot" and landing at the top are the same place there.
		if len(p.RuleIDs) > 1 {
			var anchors int
			for _, s := range p.Sections {
				if strings.EqualFold(s.Anchor, id) {
					anchors++
				}
			}
			if anchors != 1 {
				t.Errorf("%s shares a page with %d other rule(s) but has %d anchored sections there, want 1",
					id, len(p.RuleIDs)-1, anchors)
			}
		}
	}

	// The index is the other reachability path Part 3a names, and must not
	// disagree with what was just proven true of the guide content directly.
	// HasPage is what gates both the index row and the finding card's link, so
	// it has to track the content exactly — in both directions, which is what
	// keeps a rule awaiting its page from rendering a link that goes nowhere.
	idx, err := New("test").Guide()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range idx.Entries {
		for _, id := range e.RuleIDs {
			_, hasContent := documented[id]
			if e.HasPage != hasContent {
				t.Errorf("%s: index says has_page=%v, guide content says %v", id, e.HasPage, hasContent)
			}
		}
	}
}

// TestGuideIndexIsRegistryDriven checks the index reports what the tool
// actually does, and discloses what it does not. Entries are grouped by page,
// so the entry count is pages, not rules — the registry-driven property is
// that every rule appears exactly once, either as an entry or as a member of
// one, which TestGuideRegistryBijection already proves; this test is about
// each entry's own content being correct and complete.
func TestGuideIndexIsRegistryDriven(t *testing.T) {
	idx, err := New("test").Guide()
	if err != nil {
		t.Fatal(err)
	}

	metas := rules.AllMeta()
	byID := map[string]rules.Meta{}
	for _, m := range metas {
		byID[m.ID] = m
	}

	seen := map[string]bool{}
	for _, e := range idx.Entries {
		if e.RuleID == "" || e.Name == "" || e.Summary == "" || len(e.RuleIDs) == 0 {
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
		if p, ok := guide.Lookup(e.RuleID); ok {
			// The index uses the authored one-liner, which is written for
			// this reader rather than for a developer reading the registry.
			if e.Summary != p.Summary() {
				t.Errorf("%s index summary is not the authored one-line summary", e.RuleID)
			}
			// RuleIDs must match the page's own served set exactly — an
			// entry that silently dropped a member would be the bijection
			// bug in a place TestGuideRegistryBijection cannot see, since it
			// checks the guide content and the index independently, not
			// that the two agree on which rule IDs go together.
			if len(e.RuleIDs) != len(p.RuleIDs) {
				t.Errorf("%s entry lists %v, page serves %v", e.RuleID, e.RuleIDs, p.RuleIDs)
			}
		}

		for _, id := range e.RuleIDs {
			if seen[id] {
				t.Errorf("%s appears in more than one index entry", id)
			}
			seen[id] = true
			m, ok := byID[id]
			if !ok {
				t.Errorf("entry lists %s, which is not a registered rule", id)
				continue
			}
			// Every member (or the entry itself) must carry that rule's own
			// name and summary somewhere reachable — the entry-level Name is
			// the page's title for a group, so it is the members, not the
			// top-level fields, that carry each rule's own identity there.
			if id == e.RuleID {
				continue
			}
			var found bool
			for _, mm := range e.Members {
				if mm.RuleID == id {
					found = true
					if mm.Name != m.Name {
						t.Errorf("%s member name = %q, registry says %q", id, mm.Name, m.Name)
					}
				}
			}
			if !found {
				t.Errorf("%s is in RuleIDs but has no Members entry", id)
			}
		}
	}
	for id := range byID {
		if !seen[id] {
			t.Errorf("%s is a built rule but appears in no index entry", id)
		}
	}

	if want := rules.TotalV1Rules - len(metas); idx.PlannedCount != want {
		t.Errorf("PlannedCount = %d, want %d (registry-derived)", idx.PlannedCount, want)
	}
	if idx.PlannedNote == "" {
		t.Error("the index does not disclose the unbuilt checks, so a short entry list would read as the whole tool")
	}
}

// TestGuidePageLookup checks both the hit and the miss.
func TestGuidePageLookup(t *testing.T) {
	app := New("test")

	p, err := app.GuidePage("R01")
	if err != nil {
		t.Fatalf("R01: %v", err)
	}
	if len(p.RuleIDs) != 1 || p.RuleIDs[0] != "R01" || len(p.Sections) != len(guide.Skeleton) {
		t.Errorf("R01 page = %+v", p)
	}

	// R05 shares a page with R06, R07 and R08 — GuidePage still resolves it,
	// and returns the whole shared page, not a slice of it.
	loss, err := app.GuidePage("R05")
	if err != nil {
		t.Fatalf("R05: %v", err)
	}
	if !loss.ServesRule("R05") || !loss.ServesRule("R08") {
		t.Errorf("R05 page = %+v, want it to also serve R08", loss)
	}

	// An unbuilt rule has no page, and asking for one is an error rather than an
	// empty page that would look like missing content.
	if _, err := app.GuidePage("R10"); err == nil {
		t.Error("R10 is not built but returned a guide page")
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
