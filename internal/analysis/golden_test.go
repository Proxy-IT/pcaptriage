package analysis_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

var update = flag.Bool("update", false, "rewrite committed golden files")

// determinismRuns is how many times each fixture is analysed when checking for
// byte-identical output.
//
// Go randomises map iteration order per range statement, so a collection built
// from a map and emitted unsorted will usually, but not always, come out in a
// different order on any given run. Repeating raises the chance of catching it
// to near certainty. TestEmittedCollectionsAreSorted below covers the same
// ground without depending on chance.
const determinismRuns = 16

// renderFixture analyses a committed fixture and renders the JSON report,
// normalising the fields that legitimately vary with where the file sits and
// how the tool was invoked.
func renderFixture(t *testing.T, name, format string) []byte {
	t.Helper()

	path := synth.FixturePath(name, format)
	res, err := analysis.Run(path, analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", path, err)
	}

	// The absolute path and the container format are properties of the file on
	// disk, not of the analysis, and would make the golden depend on the
	// checkout location.
	res.Capture.Path = "testdata/fixtures/" + name
	res.Capture.Format = "normalised"

	doc := report.Build(res, report.Invocation{
		Args:     []string{"testdata/fixtures/" + name},
		Input:    "testdata/fixtures/" + name,
		MaxFlows: 0,
	}, "test")

	var buf bytes.Buffer
	if err := report.Write(&buf, doc); err != nil {
		t.Fatalf("render %s: %v", path, err)
	}
	return buf.Bytes()
}

// TestGolden pins the full JSON report for every fixture.
//
// This is the regression net for the whole pipeline. A change to wording, a
// threshold, the ranking, or the schema shows up here as a reviewable diff
// rather than as a silent behavioural shift.
func TestGolden(t *testing.T) {
	if *update {
		if err := os.MkdirAll(synth.GoldenDir(), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range allFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			got := renderFixture(t, f.Name, "pcap")

			path := synth.GoldenPath(f.Name)
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v\nrun `go test ./... -update` to generate golden files", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("report for %s differs from the golden file\n%s",
					f.Name, firstDifference(want, got))
			}
		})
	}
}

// TestDeterminism analyses each fixture repeatedly and requires byte-identical
// output every time.
//
// Constraint 4 in the brief is that identical input produces identical output.
// The most likely way it breaks is a findings list, flow table, or per-host
// aggregate assembled from a Go map and emitted without sorting.
func TestDeterminism(t *testing.T) {
	for _, f := range allFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			first := renderFixture(t, f.Name, "pcap")
			for i := 1; i < determinismRuns; i++ {
				again := renderFixture(t, f.Name, "pcap")
				if !bytes.Equal(first, again) {
					t.Fatalf("run %d of %d differs from run 0 — output is not deterministic\n%s",
						i+1, determinismRuns, firstDifference(first, again))
				}
			}
		})
	}
}

// TestEmittedCollectionsAreSorted asserts the documented order of every array
// in the report directly.
//
// TestDeterminism catches an unsorted emit only when Go happens to iterate the
// map differently between runs. This test does not depend on that: it checks
// the ordering property itself, so a collection that is emitted in map order
// fails here even if two runs happened to agree.
func TestEmittedCollectionsAreSorted(t *testing.T) {
	for _, f := range allFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			var doc struct {
				Checks []struct {
					ID string `json:"id"`
				} `json:"checks"`
				Findings []struct {
					Rank   int      `json:"rank"`
					RuleID string   `json:"rule_id"`
					Frames []uint64 `json:"frames"`
					Title  string   `json:"title"`
				} `json:"findings"`
				Notes []struct {
					Kind   string `json:"kind"`
					RuleID string `json:"rule_id"`
					Text   string `json:"text"`
				} `json:"notes"`
			}
			if err := json.Unmarshal(renderFixture(t, f.Name, "pcap"), &doc); err != nil {
				t.Fatal(err)
			}

			if !sort.SliceIsSorted(doc.Checks, func(i, j int) bool {
				return doc.Checks[i].ID < doc.Checks[j].ID
			}) {
				t.Error("checks are not sorted by rule id")
			}

			for i, fd := range doc.Findings {
				if fd.Rank != i+1 {
					t.Errorf("finding %d has rank %d; ranks must be dense and ascending", i, fd.Rank)
				}
				if !sort.SliceIsSorted(fd.Frames, func(a, b int) bool { return fd.Frames[a] < fd.Frames[b] }) {
					t.Errorf("finding %q: frame references are not ascending: %v", fd.Title, fd.Frames)
				}
				for a := 1; a < len(fd.Frames); a++ {
					if fd.Frames[a] == fd.Frames[a-1] {
						t.Errorf("finding %q: duplicate frame reference %d", fd.Title, fd.Frames[a])
					}
				}
				if len(fd.Frames) > 8 {
					t.Errorf("finding %q: %d frame references exceeds the cap of 8", fd.Title, len(fd.Frames))
				}
			}

			if !sort.SliceIsSorted(doc.Notes, func(i, j int) bool {
				a, b := doc.Notes[i], doc.Notes[j]
				if a.RuleID != b.RuleID {
					return a.RuleID < b.RuleID
				}
				if a.Kind != b.Kind {
					return a.Kind < b.Kind
				}
				return a.Text < b.Text
			}) {
				t.Error("notes are not in their documented order")
			}
		})
	}
}

// renderIgnoringContainerFacts renders a fixture with the facts that are
// properties of the container rather than of the packets blanked out.
//
// Whether a file can report the capture host's own drop counters is one such
// fact: pcapng has a block for it and classic pcap does not, so the two
// renderings of identical traffic legitimately say different things about it.
// That difference is the feature working, not a divergence in the analysis,
// and folding it into the equivalence check would either weaken the check or
// require the reporting to lie about one of the two formats.
//
// What remains compared is everything that should be identical: the same
// frames, the same flows, the same findings, in the same order.
func renderIgnoringContainerFacts(t *testing.T, name, format string) []byte {
	t.Helper()

	res, err := analysis.Run(synth.FixturePath(name, format), analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", name, err)
	}

	res.Capture.Path = "testdata/fixtures/" + name
	res.Capture.Format = "normalised"
	res.Capture.DropAvailability = "normalised"
	res.Capture.InterfaceDrops = nil
	res.Capture.PacketsDropped = 0
	res.Capture.DropRatio = 0
	res.Capture.DropsSignificant = false

	kept := res.Notes[:0]
	for _, n := range res.Notes {
		if n.RuleID == "R15" {
			continue
		}
		kept = append(kept, n)
	}
	res.Notes = kept

	doc := report.Build(res, report.Invocation{
		Args:  []string{"testdata/fixtures/" + name},
		Input: "testdata/fixtures/" + name,
	}, "test")

	var buf bytes.Buffer
	if err := report.Write(&buf, doc); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return buf.Bytes()
}

// TestFindingOrderingKeyIsTotal closes the gap TestDeterminism cannot cover on
// its own.
//
// The findings list is sorted by significance, then rule id, then scope key,
// then first frame. As long as no two findings tie on all four, insertion
// order can never influence the output — which is why an unsorted emit
// upstream does not currently show up in the golden files. That protection
// only holds while the sort key stays total, so it is asserted rather than
// assumed: two findings sharing a scope key would silently reintroduce
// dependence on Go's map iteration order.
func TestFindingOrderingKeyIsTotal(t *testing.T) {
	for _, f := range allFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			res := runFixture(t, f.Name)
			seen := make(map[string]string, len(res.Findings))
			for _, fd := range res.Findings {
				k := fd.RuleID + "\x00" + fd.ScopeKey
				if prev, dup := seen[k]; dup {
					t.Errorf("two findings share the sort key %s/%s (%q and %q); "+
						"their relative order would depend on map iteration order",
						fd.RuleID, fd.ScopeKey, prev, fd.Title)
				}
				seen[k] = fd.Title
			}
		})
	}
}

// TestPcapAndPcapngAgree checks that the container format does not change the
// analysis. Both readers have to yield the same frames, in the same order,
// with the same timestamps.
func TestPcapAndPcapngAgree(t *testing.T) {
	for _, f := range allFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			if f.FormatsDiffer {
				// Capture-host drop counters live in a pcapng block that
				// classic pcap has no equivalent for, so these two renderings
				// are supposed to disagree — see the drop fixtures.
				t.Skip("fixture exercises a format-specific feature")
			}
			a := renderIgnoringContainerFacts(t, f.Name, "pcap")
			b := renderIgnoringContainerFacts(t, f.Name, "pcapng")
			if !bytes.Equal(a, b) {
				t.Errorf("pcap and pcapng renderings of the same fixture differ\n%s", firstDifference(a, b))
			}
		})
	}
}

// TestNoWallClockInOutput guards the reason the reports are reproducible at
// all: nothing in the document is derived from the current time.
func TestNoWallClockInOutput(t *testing.T) {
	got := renderFixture(t, "mixed-findings", "pcap")
	for _, banned := range []string{"generated_at", "generatedAt", "run_at", "timestamp\":"} {
		if bytes.Contains(got, []byte(banned)) {
			t.Errorf("report contains %q; a wall-clock field breaks byte-identical output", banned)
		}
	}
}

// TestInputFileIsNotModified checks the read-only guarantee. Captures are
// frequently incident evidence and occasionally under legal hold.
func TestInputFileIsNotModified(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(synth.FixturePath("mixed-findings", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := analysis.Run(path, analysis.Options{}); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Error("input capture was modified by the run")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("run created files alongside the input capture: %v", names)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, got) {
		t.Error("input capture contents changed")
	}
}

// firstDifference renders the first differing line of two documents, which is
// far more useful in a failure than either whole document.
func firstDifference(want, got []byte) string {
	wl := bytes.Split(want, []byte("\n"))
	gl := bytes.Split(got, []byte("\n"))
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g []byte
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if !bytes.Equal(w, g) {
			return "first difference at line " + itoa(i+1) + ":\n  want: " + string(w) + "\n  got:  " + string(g)
		}
	}
	return "documents differ but no differing line was found"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
