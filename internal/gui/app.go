// Package gui is the desktop application shell.
//
// It is a shell and nothing more: every method here delegates to the same
// engine packages the CLI calls. No parsing, detection, or ranking logic lives
// in this package, and none should ever be added — if the GUI appears to need
// behaviour the engine does not have, the behaviour belongs in the engine.
package gui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/config"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Event names emitted to the frontend.
const (
	// EventProgress carries an analysis.Progress while a capture is being read.
	EventProgress = "analysis:progress"
	// EventFileDropped carries a path the user dropped onto the window.
	EventFileDropped = "file:dropped"
	// EventShowAbout asks the frontend to show the about screen.
	EventShowAbout = "nav:about"
	// EventOpenRequested asks the frontend to start the file-picker flow.
	EventOpenRequested = "nav:open"
)

// MaxOpenAnalyses bounds how many analyses are held at once.
//
// [chosen] Nothing in the UI closes an analysis yet, so without a bound the
// list would grow for as long as the app stays open. Each entry is a report
// document — kilobytes, not megabytes — so this is a guard against unbounded
// growth rather than a memory constraint, and the number is arbitrary. When a
// close action exists this should become the user's business, not a constant.
const MaxOpenAnalyses = 16

// App is the object bound into the frontend. Its exported methods are callable
// from JavaScript as window.go.gui.App.<Method>.
type App struct {
	ctx context.Context

	// Version is the tool version, shown in the about screen.
	Version string

	// mu guards the analysis list and the running flag. running stops a second
	// capture being started while the first is still being read.
	mu      sync.Mutex
	running bool

	// analyses is every analysis currently open, oldest first, with active
	// indexing the one the UI is showing.
	//
	// This is a list rather than a single current analysis on purpose, and the
	// UI renders exactly one of them — there are no tabs and no session list.
	// The shape is the point: several planned features (multiple captures open
	// at once, comparing two captures, a recent-files list that reopens into a
	// new slot) are additive against a list and a rewrite against a single
	// value. Making it a list now costs a struct field; making it one later
	// costs every caller.
	analyses []*AnalysisResult
	active   int

	// prefs is the loaded preferences, and prefsNotice is the plain-language
	// explanation when they are not the ones on disk.
	prefs       config.Preferences
	prefsNotice string
	prefsPath   string
}

// New returns an App.
//
// Preferences are read here rather than lazily, so a problem with the file is
// known before the first screen renders and can be shown alongside it.
func New(version string) *App {
	loaded := config.Load()
	return &App{
		Version:     version,
		active:      -1,
		prefs:       loaded.Preferences,
		prefsNotice: loaded.Notice,
		prefsPath:   loaded.Path,
	}
}

// Context returns the Wails runtime context, for callers such as menu handlers
// that need it to emit events. It is nil until Startup has run.
func (a *App) Context() context.Context { return a.ctx }

// Startup is called by Wails once the runtime is available.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx

	// Dropping a capture onto the window is the same action as picking one, so
	// it goes through the same path: the frontend is told a file arrived and
	// calls Analyze itself.
	wruntime.OnFileDrop(ctx, func(_, _ int, paths []string) {
		if len(paths) == 0 {
			return
		}
		wruntime.EventsEmit(ctx, EventFileDropped, paths[0])
	})
}

// AppInfo is the identity the home and about screens render.
//
// It comes from the backend rather than being written into the HTML so that the
// version and the rule counts cannot drift from what the engine actually does.
type AppInfo struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	RulesetVersion string `json:"ruleset_version"`
	SchemaVersion  string `json:"schema_version"`
	// Tagline is the one-line description of what the app does.
	Tagline string `json:"tagline"`
	// Posture is the advisory-posture line, shown before the user sees a
	// finding rather than after.
	Posture string `json:"posture"`
	// Instruction tells the user what to do and what they will get.
	Instruction string `json:"instruction"`
	// Accepts lists the file extensions the picker allows.
	Accepts []string `json:"accepts"`
	// ImplementedChecks is what this build actually looks for. Rendered on the
	// home screen so the user's expectations are set before the run, not after.
	ImplementedChecks []CheckInfo `json:"implemented_checks"`
	// TotalV1Rules is how many rules the finished v1 rule set will contain.
	TotalV1Rules int `json:"total_v1_rules"`
	// PreferencesNotice is set when the preferences file could not be used and
	// defaults are in force. Shown on the home screen: a setting silently not
	// applying is the kind of thing a user discovers much later and mistrusts.
	PreferencesNotice string `json:"preferences_notice,omitempty"`
}

// CheckInfo describes one implemented rule for the home screen.
type CheckInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

// Info returns the app identity and the checks this build implements.
func (a *App) Info() AppInfo {
	// Taken from the rule registry rather than written into the UI, so the home
	// screen cannot claim a check the engine does not actually run.
	metas := rules.AllMeta()
	out := make([]CheckInfo, 0, len(metas))
	for _, m := range metas {
		out = append(out, CheckInfo{ID: m.ID, Name: m.Name, Summary: m.Summary})
	}
	return AppInfo{
		Name:           "pcaptriage",
		Version:        a.Version,
		RulesetVersion: report.RulesetVersion,
		SchemaVersion:  report.SchemaVersion,
		Tagline:        "Reads a network capture and points out what looks unusual in it.",
		Posture:        "This tool highlights unusual activity — it doesn't diagnose the cause.",
		Instruction:    "Drop a .pcap or .pcapng file here, or click to browse — we'll look for common problems and explain what we find.",
		Accepts:        []string{".pcap", ".pcapng", ".cap"},
		// The finished rule set is fifteen. Saying so on the home screen is
		// what stops a quiet result being read as a clean bill of health.
		ImplementedChecks: out,
		TotalV1Rules:      15,
		PreferencesNotice: a.prefsNotice,
	}
}

// PreferencesInfo is the preferences plus where they live, for a settings
// screen that does not exist yet.
type PreferencesInfo struct {
	config.Preferences
	// Path is the file the preferences were read from and will be written to.
	Path string `json:"path"`
	// Notice explains why the preferences in force are not the ones on disk.
	Notice string `json:"notice,omitempty"`
}

// Preferences returns the preferences currently in force.
func (a *App) Preferences() PreferencesInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return PreferencesInfo{Preferences: a.prefs, Path: a.prefsPath, Notice: a.prefsNotice}
}

// SavePreferences validates and writes the preferences.
//
// A timezone this machine does not know is rejected here rather than written
// and quietly ignored later, so the caller finds out while it can still be
// corrected.
func (a *App) SavePreferences(p config.Preferences) error {
	if _, err := p.Location(); err != nil {
		return err
	}
	if err := config.Save(p); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	p.Schema = config.SchemaVersion
	a.prefs = p
	// The file on disk is now the one in force, so any earlier complaint about
	// it no longer applies.
	a.prefsNotice = ""
	return nil
}

// ChooseFile opens the native file picker and returns the chosen path, or an
// empty string if the user cancelled.
func (a *App) ChooseFile() (string, error) {
	if a.ctx == nil {
		return "", errors.New("the application is still starting up")
	}
	return wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Open a capture file",
		Filters: []wruntime.FileFilter{
			{DisplayName: "Capture files (*.pcap, *.pcapng, *.cap)", Pattern: "*.pcap;*.pcapng;*.cap"},
			{DisplayName: "All files (*.*)", Pattern: "*.*"},
		},
	})
}

// AnalysisResult is what the findings view renders.
//
// It is the same report document the CLI writes as JSON, with the file's
// display name alongside it. The two interfaces render the same document; there
// is no second shape of result for the GUI.
type AnalysisResult struct {
	FileName string           `json:"file_name"`
	FilePath string           `json:"file_path"`
	FileSize int64            `json:"file_size"`
	Report   *report.Document `json:"report"`

	// Coverage is what the run examined and what it could not. Always present;
	// the clean-capture screen is built from it, and the findings screen uses
	// its gap list too.
	Coverage Coverage `json:"coverage"`

	// Evidence carries the packets behind each finding, matched to it by rule
	// and subject.
	//
	// It rides alongside the report rather than inside it because the exported
	// HTML and the JSON do not show packets yet. The rules collect it either
	// way, so switching it on there later is a rendering change and not a
	// second analysis path.
	Evidence []FindingEvidence `json:"evidence"`
}

// FindingEvidence is the packet list for one finding.
type FindingEvidence struct {
	RuleID  string               `json:"rule_id"`
	Subject string               `json:"subject"`
	Packets []findings.PacketRef `json:"packets"`
}

// Analyze runs the engine over a capture and returns the report.
//
// Progress is emitted to the frontend as it reads. The capture is opened
// read-only; nothing is written to or near it.
func (a *App) Analyze(path string) (*AnalysisResult, error) {
	if path == "" {
		return nil, errors.New("no file was chosen")
	}

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil, errors.New("a capture is already being read")
	}
	a.running = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()

	info, err := os.Stat(path)
	if err != nil {
		return nil, friendlyError(err, path)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%q is a folder, not a capture file", filepath.Base(path))
	}

	opts := analysis.Options{}
	if a.ctx != nil {
		opts.Progress = func(p analysis.Progress) {
			wruntime.EventsEmit(a.ctx, EventProgress, p)
		}
	}

	res, err := analysis.Run(path, opts)
	if err != nil {
		return nil, friendlyError(err, path)
	}

	// A file that parses but holds nothing is not a clean capture, and must not
	// reach the screen that says nothing significant was found — that screen
	// would be reporting an absence of problems in an absence of data. It is an
	// error the user can act on: the capture did not record what they expected.
	if res.Capture.PacketsRead == 0 {
		return nil, fmt.Errorf(
			"%s contains no packets. The file is a valid capture, but nothing was recorded in it — "+
				"the capture may have been stopped before any traffic arrived, or filtered to nothing while running",
			filepath.Base(path))
	}

	doc := report.Build(res, report.Invocation{
		Args:  []string{path},
		Input: path,
	}, a.Version)

	evidence := make([]FindingEvidence, 0, len(res.Findings))
	for _, f := range res.Findings {
		if len(f.Packets) == 0 {
			continue
		}
		evidence = append(evidence, FindingEvidence{
			RuleID:  f.RuleID,
			Subject: f.ScopeKey,
			Packets: f.Packets,
		})
	}

	out := &AnalysisResult{
		FileName: filepath.Base(path),
		FilePath: path,
		FileSize: info.Size(),
		Report:   doc,
		Coverage: buildCoverage(res),
		Evidence: evidence,
	}

	a.open(out, true)
	return out, nil
}

// open adds an analysis to the list, optionally making it the active one.
//
// makeActive is false for a caller that adds an analysis without moving the
// user's view to it. Nothing does that today — opening a capture is always
// something the user just asked for — but the eviction rule below has to hold
// for a caller that does, which is why the distinction exists at all rather
// than being folded into the one current behaviour.
func (a *App) open(res *AnalysisResult, makeActive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// The entry the user is looking at, tracked by identity rather than index,
	// because eviction shifts every index after the one it removes.
	protected := a.currentLocked()
	if makeActive {
		protected = res
	}

	a.analyses = append(a.analyses, res)

	// Evict oldest-first, but never the analysis being viewed. "Drop the
	// oldest" and "drop the one on screen" coincide only while the active entry
	// is always the newest; the moment anything selects an older one, the
	// unqualified rule would close the window the user is reading.
	for len(a.analyses) > MaxOpenAnalyses {
		victim := -1
		for i, cand := range a.analyses {
			if cand == protected || cand == res {
				continue
			}
			victim = i
			break
		}
		if victim < 0 {
			// Everything left is protected. The cap yields: keeping what is on
			// screen matters more than the bound, and this can only overshoot
			// by the two protected entries.
			break
		}
		a.analyses = append(a.analyses[:victim], a.analyses[victim+1:]...)
	}

	// Re-resolve the index by identity, since eviction moved things.
	a.active = indexOfAnalysis(a.analyses, protected)
}

// currentLocked returns the active analysis. The caller holds a.mu.
func (a *App) currentLocked() *AnalysisResult {
	if a.active < 0 || a.active >= len(a.analyses) {
		return nil
	}
	return a.analyses[a.active]
}

func indexOfAnalysis(list []*AnalysisResult, want *AnalysisResult) int {
	for i, got := range list {
		if got == want {
			return i
		}
	}
	return -1
}

// OpenAnalysisCount reports how many analyses are currently held.
func (a *App) OpenAnalysisCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.analyses)
}

// ActiveAnalysis returns the analysis the UI is showing, or nil if none has
// been opened yet.
//
// The frontend does not need this today — Analyze hands back the result it just
// produced — but it is what a re-render or a future tab switch reads, and it is
// the accessor that makes the active index mean something.
func (a *App) ActiveAnalysis() *AnalysisResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.currentLocked()
}

// SetActiveAnalysis selects which open analysis the UI shows. It reports
// whether the index was in range.
func (a *App) SetActiveAnalysis(i int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if i < 0 || i >= len(a.analyses) {
		return false
	}
	a.active = i
	return true
}

// friendlyError turns an engine error into something a non-expert can act on,
// without inventing a cause the tool has not established.
func friendlyError(err error, path string) error {
	name := filepath.Base(path)

	var unsupported *capture.UnsupportedLinkTypeError
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s could not be found", name)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%s could not be opened — this account does not have permission to read it", name)
	case errors.Is(err, capture.ErrUnknownFormat):
		return fmt.Errorf("%s does not look like a capture file. This tool reads pcap and pcapng files, the format tcpdump and Wireshark save", name)
	case errors.As(err, &unsupported):
		return fmt.Errorf("%s was captured from a link type this build does not read (%s). Captures taken on a normal Ethernet interface work; a Linux \"any\" interface capture does not yet", name, unsupported.Name)
	}

	msg := err.Error()
	if strings.TrimSpace(msg) == "" {
		msg = "the file could not be read"
	}
	return fmt.Errorf("%s could not be analysed: %s", name, msg)
}
