package gui

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/config"
	"github.com/Proxy-IT/pcaptriage/internal/guide"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// previewPath, when set, writes a browsable copy of the real frontend loaded
// with real engine output:
//
//	go test ./internal/gui/ -preview <path>.html
//
// It exists so the UI can be looked at without launching the desktop app. The
// markup and stylesheet are the shipped ones, byte for byte; only the Wails
// bindings are replaced, by a stub returning what the engine actually produced.
var previewPath = flag.String("preview", "", "write a browsable preview of the frontend to this path")

// previewFixture selects which committed capture the preview is built from, so
// the empty-result and notes states can be looked at as well as the populated
// one.
var previewFixture = flag.String("preview-fixture", "mixed-findings", "fixture to build the preview from")

// previewVariant constructs a state no committed fixture can currently reach.
//
//	force-strong  clean capture with coverage forced strong, to see what green
//	              looks like — unreachable today because 13 checks are unbuilt
//	no-tcp        packets present, no TCP conversations
//
// Both are marked in the rendered page as constructed rather than observed, so a
// screenshot of one cannot be mistaken for the tool's real output.
var previewVariant = flag.String("preview-variant", "", "construct an otherwise unreachable state: force-strong | no-tcp")

// previewLand opens the preview directly on a secondary view, so a render can
// be looked at without clicking through to it.
//
//	guide-from-finding  a guide page reached from a card (context block present)
//	guide-from-index    the same page reached from the index (no context block)
//	guide-index         the index
//	about               the About page
var previewLand = flag.String("preview-land", "", "open the preview on a view: guide-from-finding | guide-from-index | guide-index | r15-from-banner | about")

// landingScript drives the preview into a secondary view after load.
//
// It clicks the real controls rather than manipulating the views directly, so
// what is rendered is what a user's clicks produce — including the back-button
// label, which depends on where they came from.
func landingScript(land string) string {
	var steps string
	switch land {
	case "":
		return ""
	case "guide-from-finding":
		// Index 0: correct for a single-finding fixture (r06-fast-retransmit,
		// for Checkpoint 3's R06-anchor-landing render). Pass a fixture whose
		// first card is the finding you want if reusing this for another rule.
		steps = `document.querySelectorAll(".guide-link-row .linkish")[0].click();`
	case "guide-from-index":
		steps = `window.__emit("nav:guide");
      await pause(500);
      document.querySelectorAll("#guide-index-list .index-link")[0].click();`
	case "guide-index-entry-2":
		// The second index row, which is the R02/R03 page — index arrival, so
		// it must land at the top with no context block whichever rule the
		// row's own lookup key happens to be.
		steps = `window.__emit("nav:guide");
      await pause(500);
      document.querySelectorAll("#guide-index-list .index-link")[1].click();`
	case "guide-index-entry-5":
		// The fifth index row: the R09/R14 page, same expectation.
		steps = `window.__emit("nav:guide");
      await pause(500);
      document.querySelectorAll("#guide-index-list .index-link")[4].click();`
	case "guide-index":
		steps = `window.__emit("nav:guide");`
	case "r15-from-banner":
		// Use with -preview-fixture clean-capture: the clean-state screen's
		// gaps column carries R15's one banner link (3c).
		steps = `document.getElementById("btn-clean-gaps-guide").click();`
	case "about":
		steps = `window.__emit("nav:about");`
	default:
		panic("unknown -preview-land " + land)
	}

	return `
<script>
// Preview landing: drives the real controls so the rendered state is one a
// user's clicks can actually produce.
(async function () {
  var pause = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  await pause(400);
  document.getElementById("dropzone").click();
  await pause(2200);
  ` + steps + `
})();
</script>`
}

// TestAnalyzeEndToEnd drives the exact method the frontend calls and requires
// real findings from the real engine.
//
// This is the "one engine, both interfaces" constraint under test: if the GUI
// ever grew its own detection or ranking path, the wording and ordering here
// would stop matching what the CLI produces.
func TestAnalyzeEndToEnd(t *testing.T) {
	app := New("test")

	res, err := app.Analyze(synth.FixturePath("mixed-findings", "pcap"))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if res.FileName != "mixed-findings.pcap" {
		t.Errorf("FileName = %q", res.FileName)
	}
	if res.FileSize <= 0 {
		t.Error("FileSize was not reported")
	}
	if res.Report == nil {
		t.Fatal("no report returned")
	}

	got := res.Report.Findings
	if len(got) == 0 {
		t.Fatal("no findings; the GUI would show an empty result for a capture that has them")
	}

	// The same five findings the CLI reports, in the same order.
	cliRes, err := analysis.Run(synth.FixturePath("mixed-findings", "pcap"), analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := report.Build(cliRes, report.Invocation{}, "test").Findings

	if len(got) != len(want) {
		t.Fatalf("GUI produced %d findings, CLI produced %d", len(got), len(want))
	}
	for i := range want {
		if got[i].RuleID != want[i].RuleID || got[i].Subject != want[i].Subject {
			t.Errorf("finding %d differs between interfaces: GUI %s/%s, CLI %s/%s",
				i, got[i].RuleID, got[i].Subject, want[i].RuleID, want[i].Subject)
		}
		if got[i].Observation != want[i].Observation {
			t.Errorf("finding %d wording differs between interfaces", i)
		}
	}

	// Both rules must actually be represented, or the fixture is not
	// exercising the pipeline the brief asks to see working.
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.RuleID] = true
	}
	for _, id := range []string{"R01", "R04"} {
		if !seen[id] {
			t.Errorf("no %s finding reached the GUI", id)
		}
	}
}

// TestAnalysesAreHeldAsAList pins the P1 state model: the app holds a list of
// open analyses with an active index, even though the UI renders exactly one.
//
// No behaviour visible to the user depends on this yet. It is asserted because
// the whole point of the refactor is that the shape is right before anything is
// built on it, and a list that silently collapsed back to "the current one"
// would look identical from the UI.
func TestAnalysesAreHeldAsAList(t *testing.T) {
	app := New("test")

	if app.OpenAnalysisCount() != 0 {
		t.Errorf("a fresh app holds %d analyses, want 0", app.OpenAnalysisCount())
	}
	if app.ActiveAnalysis() != nil {
		t.Error("a fresh app has an active analysis")
	}

	first, err := app.Analyze(synth.FixturePath("r01-zero-window-stall", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.Analyze(synth.FixturePath("r04-server-response-outlier", "pcap"))
	if err != nil {
		t.Fatal(err)
	}

	if got := app.OpenAnalysisCount(); got != 2 {
		t.Errorf("holding %d analyses, want 2 — the first was not kept", got)
	}
	// The most recently opened capture is the one the user is looking at.
	if app.ActiveAnalysis() != second {
		t.Error("the active analysis is not the one just opened")
	}

	if !app.SetActiveAnalysis(0) {
		t.Fatal("could not select the first analysis")
	}
	if app.ActiveAnalysis() != first {
		t.Error("selecting index 0 did not bring back the first analysis")
	}
	if app.SetActiveAnalysis(2) || app.SetActiveAnalysis(-1) {
		t.Error("an out-of-range index was accepted")
	}
	if app.ActiveAnalysis() != first {
		t.Error("a rejected selection changed the active analysis anyway")
	}
}

// TestOpenAnalysesAreBounded checks the cap. Nothing closes an analysis yet, so
// without it the list would grow for as long as the app is open.
func TestOpenAnalysesAreBounded(t *testing.T) {
	app := New("test")
	path := synth.FixturePath("r01-brief-zero-windows", "pcap")

	for i := 0; i < MaxOpenAnalyses+3; i++ {
		if _, err := app.Analyze(path); err != nil {
			t.Fatalf("analyse %d: %v", i, err)
		}
	}

	if got := app.OpenAnalysisCount(); got != MaxOpenAnalyses {
		t.Errorf("holding %d analyses, want the cap of %d", got, MaxOpenAnalyses)
	}
	// The newest must survive: it is the one the user just asked for.
	if a := app.ActiveAnalysis(); a == nil || a.FilePath != path {
		t.Error("the most recent analysis is not the active one after eviction")
	}
}

// TestActiveAnalysisIsNeverEvicted is the invariant that "evict the oldest"
// must not be allowed to mean "close the window the user is reading".
//
// Today the active analysis is always the newest, so the two rules coincide and
// nothing would notice the difference. This exercises the case that breaks that
// coincidence: an older entry is selected, then analyses keep arriving without
// stealing the view. The selected one must survive every eviction.
func TestActiveAnalysisIsNeverEvicted(t *testing.T) {
	app := New("test")

	pinned := &AnalysisResult{FileName: "pinned.pcap", FilePath: "pinned.pcap"}
	app.open(pinned, true)
	for i := 0; i < 3; i++ {
		app.open(&AnalysisResult{FileName: "filler.pcap"}, true)
	}

	if !app.SetActiveAnalysis(0) {
		t.Fatal("could not select the oldest analysis")
	}
	if app.ActiveAnalysis() != pinned {
		t.Fatal("selecting index 0 did not select the pinned analysis")
	}

	// Well past the cap, none of them stealing the view.
	for i := 0; i < MaxOpenAnalyses*2; i++ {
		app.open(&AnalysisResult{FileName: "flood.pcap"}, false)

		if app.ActiveAnalysis() != pinned {
			t.Fatalf("after %d additions the viewed analysis was evicted", i+1)
		}
	}

	if got := app.OpenAnalysisCount(); got > MaxOpenAnalyses+1 {
		t.Errorf("holding %d analyses; protecting the active entry should overshoot the cap of %d by at most one",
			got, MaxOpenAnalyses)
	}

	// And it is still reachable by index, not merely present in the slice.
	found := false
	for i := 0; i < app.OpenAnalysisCount(); i++ {
		if app.SetActiveAnalysis(i) && app.ActiveAnalysis() == pinned {
			found = true
			break
		}
	}
	if !found {
		t.Error("the pinned analysis is no longer selectable")
	}
}

// TestAnalyzeReportsProgress checks that the loading state has something to
// show. A window that looks frozen reads as broken rather than as working.
func TestAnalyzeReportsProgress(t *testing.T) {
	var updates []analysis.Progress
	_, err := analysis.Run(synth.FixturePath("mixed-findings", "pcap"), analysis.Options{
		ProgressInterval: 32,
		Progress:         func(p analysis.Progress) { updates = append(updates, p) },
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(updates) < 2 {
		t.Fatalf("got %d progress callbacks, want several", len(updates))
	}
	last := updates[len(updates)-1]
	if !last.Done {
		t.Error("the final progress callback did not mark completion")
	}
	if last.TotalBytes <= 0 {
		t.Error("total size was not reported, so the bar can only be indeterminate")
	}
	if f, ok := last.Fraction(); !ok || f != 1 {
		t.Errorf("final fraction = %v (known %v), want 1", f, ok)
	}

	// Progress must be monotonic, or the bar goes backwards.
	for i := 1; i < len(updates); i++ {
		if updates[i].BytesRead < updates[i-1].BytesRead {
			t.Fatalf("bytes read went backwards at update %d", i)
		}
		if updates[i].PacketsRead < updates[i-1].PacketsRead {
			t.Fatalf("packet count went backwards at update %d", i)
		}
	}
}

// TestProgressDoesNotAffectFindings guards the determinism constraint against
// the one thing this session added to the engine.
func TestProgressDoesNotAffectFindings(t *testing.T) {
	path := synth.FixturePath("mixed-findings", "pcap")

	plain, err := analysis.Run(path, analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	watched, err := analysis.Run(path, analysis.Options{
		ProgressInterval: 1,
		Progress:         func(analysis.Progress) {},
	})
	if err != nil {
		t.Fatal(err)
	}

	a, _ := json.Marshal(report.Build(plain, report.Invocation{}, "t"))
	b, _ := json.Marshal(report.Build(watched, report.Invocation{}, "t"))
	if string(a) != string(b) {
		t.Error("observing progress changed the result; it must be inert")
	}
}

// TestInfoComesFromTheRuleRegistry checks that the home screen cannot advertise
// a check the engine does not run, and that it states the shortfall.
func TestInfoComesFromTheRuleRegistry(t *testing.T) {
	i := New("test").Info()

	if len(i.ImplementedChecks) == 0 {
		t.Fatal("no checks reported")
	}
	if i.TotalV1Rules <= len(i.ImplementedChecks) {
		t.Error("the home screen would not disclose that the rule set is incomplete")
	}
	for _, c := range i.ImplementedChecks {
		if c.ID == "" || c.Name == "" || c.Summary == "" {
			t.Errorf("check %+v is missing text the home screen renders", c)
		}
	}
	for _, s := range []string{i.Tagline, i.Posture, i.Instruction} {
		if strings.TrimSpace(s) == "" {
			t.Error("home screen copy is empty")
		}
	}
	// The posture line is doing real work: it sets expectations before the
	// user reads a finding, so it has to say what the tool will not do.
	if !strings.Contains(i.Posture, "doesn't diagnose") {
		t.Errorf("posture line does not disclaim diagnosis: %q", i.Posture)
	}
}

// TestPreferencesRoundTripThroughTheApp checks the binding surface the config
// mechanism exists behind.
func TestPreferencesRoundTripThroughTheApp(t *testing.T) {
	dir := t.TempDir()
	if os.PathSeparator == '\\' {
		t.Setenv("APPDATA", dir)
	} else {
		t.Setenv("XDG_CONFIG_HOME", dir)
		t.Setenv("HOME", dir)
	}

	app := New("test")
	got := app.Preferences()
	if got.Timezone != config.TimezoneLocal {
		t.Errorf("default timezone = %q, want %q", got.Timezone, config.TimezoneLocal)
	}
	if got.Path == "" {
		t.Error("preferences do not say where they live")
	}
	if got.Notice != "" {
		t.Errorf("first run produced a notice: %q", got.Notice)
	}

	if err := app.SavePreferences(config.Preferences{Timezone: "Europe/London"}); err != nil {
		t.Fatalf("SavePreferences: %v", err)
	}
	if got := app.Preferences().Timezone; got != "Europe/London" {
		t.Errorf("after save, timezone = %q", got)
	}
	// A fresh app must read back what was written.
	if got := New("test").Preferences().Timezone; got != "Europe/London" {
		t.Errorf("a new app read timezone = %q", got)
	}

	// A zone this machine does not have is refused rather than written and then
	// quietly ignored.
	if err := app.SavePreferences(config.Preferences{Timezone: "Nowhere/Nothing"}); err == nil {
		t.Error("an unknown timezone was accepted")
	}
	if got := app.Preferences().Timezone; got != "Europe/London" {
		t.Errorf("a rejected save changed the preferences anyway: %q", got)
	}
}

// TestCorruptPreferencesSurfaceOnTheHomeScreen checks that a setting silently
// not applying is something the user is told about.
func TestCorruptPreferencesSurfaceOnTheHomeScreen(t *testing.T) {
	dir := t.TempDir()
	if os.PathSeparator == '\\' {
		t.Setenv("APPDATA", dir)
	} else {
		t.Setenv("XDG_CONFIG_HOME", dir)
		t.Setenv("HOME", dir)
	}

	path, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := New("test")
	if app.Info().PreferencesNotice == "" {
		t.Error("the home screen carries no notice about the unusable preferences file")
	}
	if app.Preferences().Timezone != config.TimezoneLocal {
		t.Error("defaults did not apply")
	}

	// The app still works — a bad preferences file must not stop an analysis.
	if _, err := app.Analyze(synth.FixturePath("mixed-findings", "pcap")); err != nil {
		t.Errorf("a corrupt preferences file broke analysis: %v", err)
	}
}

// TestFriendlyErrors checks that a failure explains itself in terms a
// non-expert can act on, without inventing a cause.
func TestFriendlyErrors(t *testing.T) {
	dir := t.TempDir()

	notCapture := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notCapture, []byte("not a capture"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := New("test")

	if _, err := app.Analyze(filepath.Join(dir, "missing.pcap")); err == nil {
		t.Error("expected an error for a missing file")
	} else if !strings.Contains(err.Error(), "could not be found") {
		t.Errorf("unhelpful message: %v", err)
	}

	if _, err := app.Analyze(notCapture); err == nil {
		t.Error("expected an error for a non-capture file")
	} else if !strings.Contains(err.Error(), "pcap") {
		t.Errorf("message does not say what the tool expects: %v", err)
	}

	if _, err := app.Analyze(dir); err == nil {
		t.Error("expected an error for a directory")
	}

	if _, err := app.Analyze(""); err == nil {
		t.Error("expected an error for an empty path")
	}
}

// TestWritePreview renders the shipped frontend against real engine output.
//
// It is skipped unless -preview is given. It asserts nothing about appearance —
// it exists so the UI can be opened and looked at, which is the only way to
// catch a layout problem.
func TestWritePreview(t *testing.T) {
	if *previewPath == "" {
		t.Skip("pass -preview <path>.html to write a browsable preview")
	}

	app := New("preview")
	res, err := app.Analyze(synth.FixturePath(*previewFixture, "pcap"))
	if err != nil {
		t.Fatal(err)
	}

	switch *previewVariant {
	case "":
	case "force-strong":
		// Green is withheld today because the rule set is incomplete. Forcing it
		// shows the treatment; it is not something a real run can produce.
		res.Report.Coverage.CoverageStrong = true
		res.Report.Coverage.CoverageWeakReason = ""
		res.Report.Coverage.NotChecked = nil
		res.Report.Coverage.UnbuiltChecks = 0
		res.Report.Coverage.Qualifier = "CONSTRUCTED FOR REVIEW — no real run reaches this state yet: " +
			"green requires every planned check built and no gaps on the capture. " + res.Report.Coverage.Qualifier
	case "no-tcp":
		res.Report.Capture.TCPFlows = 0
		res.Report.Capture.PacketsNonTCP = res.Report.Capture.PacketsRead
		res.Report.Capture.PacketsTCP = 0
		res.Report.Findings = nil
		// Rebuilt through report.Build so the constructed state carries the
		// same coverage a real no-TCP run would, rather than a hand-mixed one.
		noTCP := report.Build(&analysis.Result{Capture: analysis.CaptureInfo{
			PacketsRead:   res.Report.Capture.PacketsRead,
			PacketsNonTCP: res.Report.Capture.PacketsRead,
		}}, report.Invocation{}, "preview")
		res.Report.Coverage = noTCP.Coverage
		res.Report.Coverage.Qualifier = "CONSTRUCTED FOR REVIEW — " + res.Report.Coverage.Qualifier
	default:
		t.Fatalf("unknown -preview-variant %q", *previewVariant)
	}

	resultJSON, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	infoJSON, err := json.Marshal(app.Info())
	if err != nil {
		t.Fatal(err)
	}

	idx, err := app.Guide()
	if err != nil {
		t.Fatal(err)
	}
	indexJSON, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	// Keyed by every rule ID each page serves, not just each index entry's
	// primary — GuidePage("R06") must resolve here exactly as it does through
	// the real binding, which looks the page up by any of its served rules.
	pages := map[string]guide.Page{}
	for _, e := range idx.Entries {
		p, ok := guide.Lookup(e.RuleID)
		if !ok {
			continue
		}
		for _, id := range p.RuleIDs {
			pages[id] = p
		}
	}
	pagesJSON, err := json.Marshal(pages)
	if err != nil {
		t.Fatal(err)
	}
	aboutJSON, err := json.Marshal(app.About())
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Dir(filepath.Dir(synth.FixtureDir()))
	dist := filepath.Join(root, "frontend", "dist")

	html, err := os.ReadFile(filepath.Join(dist, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := os.ReadFile(filepath.Join(dist, "tokens.css"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := os.ReadFile(filepath.Join(dist, "app.css"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile(filepath.Join(dist, "app.js"))
	if err != nil {
		t.Fatal(err)
	}

	page := string(html)

	// The shipped page has a strict CSP and loads its assets by URL. A
	// file:// preview cannot satisfy either, so both are inlined here. The
	// markup itself is untouched.
	page = stripTag(page, `<meta http-equiv="Content-Security-Policy"`, ">")
	page = strings.Replace(page, `<link rel="stylesheet" href="tokens.css">`,
		"<style>"+string(tokens)+"</style>", 1)
	page = strings.Replace(page, `<link rel="stylesheet" href="app.css">`,
		"<style>"+string(css)+"</style>", 1)

	stub := `<script>
// Stand-in for the Wails bindings. The data below is verbatim engine output
// for testdata/fixtures/mixed-findings.pcap, captured at preview build time.
window.__preview = { info: ` + string(infoJSON) + `, result: ` + string(resultJSON) + `,
                     guideIndex: ` + string(indexJSON) + `, guidePages: ` + string(pagesJSON) + `,
                     about: ` + string(aboutJSON) + ` };
window.__opened = [];
window.go = { gui: { App: {
  Info:       function () { return Promise.resolve(window.__preview.info); },
  Guide:      function () { return Promise.resolve(window.__preview.guideIndex); },
  GuidePage:  function (id) {
    var p = window.__preview.guidePages[id];
    return p ? Promise.resolve(p) : Promise.reject(new Error("no guide page for " + id));
  },
  About:      function () { return Promise.resolve(window.__preview.about); },
  // Records the handoff instead of performing it, so a preview cannot open a
  // browser and the assertion is still observable.
  OpenExternal: function (u) { window.__opened.push(u); return Promise.resolve(); },
  ChooseFile: function () { return Promise.resolve(window.__preview.result.file_path); },
  Analyze:    function () {
    return new Promise(function (resolve) {
      var pkts = window.__preview.result.report.capture.packets_read;
      var total = window.__preview.result.file_size, step = 0;
      var tick = setInterval(function () {
        step++;
        window.__emit("analysis:progress", {
          PacketsRead: Math.round(pkts * step / 6),
          BytesRead: Math.round(total * step / 6),
          TotalBytes: total, Done: step >= 6
        });
        if (step >= 6) { clearInterval(tick); resolve(window.__preview.result); }
      }, 220);
    });
  }
}}};
window.__handlers = {};
window.__emit = function (n, d) { (window.__handlers[n] || []).forEach(function (f) { f(d); }); };
window.runtime = { EventsOn: function (n, f) { (window.__handlers[n] = window.__handlers[n] || []).push(f); } };
</script>`

	page = strings.Replace(page, `<script src="app.js"></script>`,
		stub+"\n<script>"+string(js)+"</script>"+landingScript(*previewLand), 1)

	if err := os.WriteFile(*previewPath, []byte(page), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote preview to %s", *previewPath)
}

// stripTag removes the tag starting at open and ending at the next close.
func stripTag(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return s
	}
	j := strings.Index(s[i:], close)
	if j < 0 {
		return s
	}
	return s[:i] + s[i+j+len(close):]
}
