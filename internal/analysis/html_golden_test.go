package analysis_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/report"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// renderFixtureHTML analyses a committed fixture and renders the HTML report,
// normalising the same location-dependent fields the JSON golden does.
func renderFixtureHTML(t *testing.T, name, format string) []byte {
	t.Helper()

	res, err := analysis.Run(synth.FixturePath(name, format), analysis.Options{})
	if err != nil {
		t.Fatalf("analyse %s: %v", name, err)
	}
	res.Capture.Path = "testdata/fixtures/" + name
	res.Capture.Format = "normalised"

	doc := report.Build(res, report.Invocation{
		Args:  []string{"testdata/fixtures/" + name},
		Input: "testdata/fixtures/" + name,
	}, "test")

	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, doc); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return buf.Bytes()
}

// TestHTMLGolden pins the rendered report for every fixture, so a change to
// layout, wording or a chart shows up as a reviewable diff.
func TestHTMLGolden(t *testing.T) {
	if *update {
		if err := os.MkdirAll(synth.GoldenDir(), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			got := renderFixtureHTML(t, f.Name, "pcap")
			path := strings.TrimSuffix(synth.GoldenPath(f.Name), ".json") + ".html"

			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v\nrun `go test ./internal/analysis/ -update` to generate golden reports", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("HTML report for %s differs from the golden file\n%s",
					f.Name, firstDifference(want, got))
			}
		})
	}
}

// TestHTMLDeterminismEndToEnd is the requirement carried through the whole
// pipeline rather than checked on a hand-built document: parse, analyse, rank
// and render, repeatedly, and require byte-identical HTML every time.
func TestHTMLDeterminismEndToEnd(t *testing.T) {
	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			first := renderFixtureHTML(t, f.Name, "pcap")
			for i := 1; i < determinismRuns; i++ {
				again := renderFixtureHTML(t, f.Name, "pcap")
				if !bytes.Equal(first, again) {
					t.Fatalf("run %d of %d differs from run 0 — HTML output is not deterministic\n%s",
						i+1, determinismRuns, firstDifference(first, again))
				}
			}
		})
	}
}

// TestHTMLMatchesJSONWording checks that the two renderings cannot drift.
// The HTML is a view over the same document, so every finding's wording must
// appear in both, character for character.
func TestHTMLMatchesJSONWording(t *testing.T) {
	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			res := runFixture(t, f.Name)
			html := string(renderFixtureHTML(t, f.Name, "pcap"))

			for _, fd := range res.Findings {
				// The renderer escapes for HTML; the fixture wording contains
				// no characters that escape, so a direct comparison holds and
				// would fail loudly if that ever stopped being true.
				if !strings.Contains(html, fd.Title) {
					t.Errorf("HTML is missing the finding title verbatim: %q", fd.Title)
				}
				if !strings.Contains(html, fd.Observation) {
					t.Errorf("HTML is missing the observation verbatim for %q", fd.Title)
				}
				if !strings.Contains(html, fd.CheckNext) {
					t.Errorf("HTML is missing the check-next line verbatim for %q", fd.Title)
				}
			}

			for _, n := range res.Notes {
				if !strings.Contains(html, n.Text) {
					t.Errorf("HTML is missing a note that the JSON carries: %q", n.Text)
				}
			}
		})
	}
}

// TestHTMLFixturesAreSelfContained repeats the air-gap check against reports
// rendered from real captures, where the prose and labels carry addresses
// rather than the hand-built strings the unit test uses.
func TestHTMLFixturesAreSelfContained(t *testing.T) {
	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			html := strings.ToLower(string(renderFixtureHTML(t, f.Name, "pcap")))
			for _, banned := range []string{"http://", "https://", "<script", "@import", "url(", "<link ", "<img "} {
				if strings.Contains(html, banned) {
					t.Errorf("report contains %q", banned)
				}
			}
		})
	}
}
