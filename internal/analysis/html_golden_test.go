package analysis_test

import (
	"bytes"
	stdhtml "html"
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
//
// Light-only, deliberately, and this is the documented reason the visual-
// identity brief's "every render test runs in both themes, or a documented
// reason a specific one is light-only" asks for: the export is not themed at
// all. template.html stamps data-theme="light" on its root element (see
// TestExportedHTMLLocksToLightTheme in internal/report), which is what keeps
// a report looking the same to everyone who opens it regardless of their
// browser's OS theme — the exact property a report needs and an app screen
// does not. Rendering these goldens under "dark" would not exercise a real
// state the tool can produce; it would exercise a state the tool goes out of
// its way to prevent.
func TestHTMLGolden(t *testing.T) {
	if *update {
		if err := os.MkdirAll(synth.GoldenDir(), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range allFixtures(t) {
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
	for _, f := range allFixtures(t) {
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
	for _, f := range allFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			res := runFixture(t, f.Name)
			html := string(renderFixtureHTML(t, f.Name, "pcap"))

			// The renderer escapes for HTML, so the comparison escapes the
			// expected text the same way rather than looking for the raw
			// bytes. This used to compare raw, on the grounds that no rule's
			// wording contained a character that escapes — R09's "the peer's
			// other traffic" is the first that does, and the test failed
			// loudly exactly as its previous comment promised. Escaping here
			// keeps the property being tested ("the renderer emitted this
			// wording") while leaving the escaping itself intact, which is
			// what stops capture-derived text from becoming markup.
			contains := func(hay, needle string) bool {
				return strings.Contains(hay, stdhtml.EscapeString(needle))
			}

			for _, fd := range res.Findings {
				if !contains(html, fd.Title) {
					t.Errorf("HTML is missing the finding title verbatim: %q", fd.Title)
				}
				if !contains(html, fd.Observation) {
					t.Errorf("HTML is missing the observation verbatim for %q", fd.Title)
				}
				if !contains(html, fd.CheckNext) {
					t.Errorf("HTML is missing the check-next line verbatim for %q", fd.Title)
				}
			}

			for _, n := range res.Notes {
				if !contains(html, n.Text) {
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
	for _, f := range allFixtures(t) {
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
