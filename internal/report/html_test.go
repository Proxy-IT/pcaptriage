package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// sampleDoc builds a document with enough shape to exercise every branch of the
// renderer without depending on the analysis packages.
func sampleDoc(findings ...Finding) *Document {
	snaplen := uint32(262144)
	return &Document{
		SchemaVersion: "1",
		Tool:          ToolInfo{Name: "pcaptriage", Version: "test", RulesetVersion: "1.0.0-partial", Build: "partial build"},
		Invocation:    Invocation{Args: []string{"cap.pcap"}, Input: "cap.pcap"},
		Capture: Capture{
			Path: "cap.pcap", Format: "pcap", LinkType: "Ethernet", Snaplen: &snaplen,
			PacketsRead: 1234567, PacketsTCP: 1234000, PacketsNonTCP: 500, PacketsUndecoded: 67,
			FirstPacketTime: "2024-03-14T09:00:00Z", LastPacketTime: "2024-03-14T09:00:20Z",
			Timezone: "UTC", TCPFlows: 42, TCPHosts: 14,
			FlowsComplete: 24, FlowsPartial: 3, FlowsMidstream: 15,
		},
		Checks: []Check{
			{ID: "R01", Name: "zero-window-stall", BaseWeight: 9, Status: "ran", Summary: "zero window summary"},
			{ID: "R04", Name: "server-response-outlier", BaseWeight: 8, Status: "ran", Summary: "response summary"},
		},
		Findings: findings,
		Notes: []Note{
			{Kind: "unavailable", RuleID: "R04", Text: "Not assessed: something."},
			{Kind: "info", RuleID: "R01", Text: "Suppressed below the floor."},
		},
		// Mirrors what Build produces: the unavailable note above appears in the
		// gap list too, since that is where the template renders gaps from.
		Coverage: Coverage{
			Clean:     len(findings) == 0,
			Statement: "No significant problems found in what was checked",
			Qualifier: "That is not the same as the capture being problem-free. " +
				"2 of 15 planned checks are built, and what they do not cover has not been examined.",
			NotChecked: []CoverageGap{
				{RuleID: "R04", Text: "Not assessed: something."},
			},
			UnbuiltChecks:      13,
			CoverageWeakReason: "not all planned checks are built",
		},
	}
}

func zeroWindowFinding(rank int, subject string, cumulative, longest int64) Finding {
	return Finding{
		Rank: rank, RuleID: "R01", Rule: "zero-window-stall",
		Subject: subject, ScopeKind: "flow",
		Title:       "Receiver stopped accepting data — " + subject,
		Observation: "Advertised a zero receive window 6 times.",
		CheckNext:   "the receiving application.",
		Frames:      []uint64{7, 9, 11}, FirstFrame: 7, WorstFrame: 9, TotalCount: 6,
		Quality: "confirmed",
		Metrics: map[string]any{
			metricCumulativeStall: cumulative,
			metricMaxStall:        longest,
		},
	}
}

func responseFinding(rank int, subject string, p95, max, median int64) Finding {
	return Finding{
		Rank: rank, RuleID: "R04", Rule: "server-response-outlier",
		Subject: subject, ScopeKind: "endpoint",
		Title:       "One server much slower to respond than its peers — " + subject,
		Observation: "Responded in 1.8s at p95.",
		CheckNext:   "application or backend dependency latency.",
		Frames:      []uint64{5, 44, 47}, FirstFrame: 5, WorstFrame: 47, TotalCount: 20,
		Quality: "inferred", QualityBasis: "RTT taken from minimum observed ACK round trip.",
		Metrics: map[string]any{
			metricP95: p95, metricMax: max, metricPopMedianP95: median,
		},
	}
}

func render(t *testing.T, doc *Document) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, doc); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	return buf.String()
}

// TestHTMLIsDeterministic is the requirement that the HTML behave like the
// JSON: identical input, byte-identical output.
//
// It should follow from the findings already being sorted, but the renderer
// groups findings through a map on its way to the page, so it is confirmed
// here rather than assumed.
func TestHTMLIsDeterministic(t *testing.T) {
	doc := sampleDoc(
		zeroWindowFinding(1, "10.1.1.5:44210 <-> 10.2.2.7:5432", 4200, 2900),
		responseFinding(2, "10.4.4.1:443", 2600, 3000, 30),
		zeroWindowFinding(3, "10.1.1.5:44211 <-> 10.2.2.8:5432", 1500, 800),
		responseFinding(4, "10.4.4.2:443", 1500, 1600, 30),
		zeroWindowFinding(5, "10.1.1.5:44212 <-> 10.2.2.9:5432", 600, 600),
	)

	first := render(t, doc)
	for i := 1; i < 24; i++ {
		again := render(t, doc)
		if first != again {
			t.Fatalf("render %d differs from render 0 — HTML output is not deterministic", i)
		}
	}
}

// TestHTMLIsSelfContained is the air-gap requirement. A report that reaches for
// a CDN is useless in the environments this tool exists for, and would also
// leak the fact that it was opened.
func TestHTMLIsSelfContained(t *testing.T) {
	html := render(t, sampleDoc(
		zeroWindowFinding(1, "10.1.1.5:44210 <-> 10.2.2.7:5432", 4200, 2900),
		responseFinding(2, "10.4.4.1:443", 2600, 3000, 30),
	))

	for _, banned := range []string{
		"http://", "https://", "//cdn", "<script", "@import", "url(",
		"integrity=", "crossorigin", "<iframe", "<link ", "<img ",
	} {
		if strings.Contains(strings.ToLower(html), banned) {
			t.Errorf("report contains %q; it must open with no network access and run no script", banned)
		}
	}

	// The stylesheet and the charts have to be present, or "self-contained"
	// would be trivially satisfied by rendering nothing.
	if !strings.Contains(html, "<style>") {
		t.Error("stylesheet was not inlined")
	}
	if !strings.Contains(html, "<svg") {
		t.Error("no SVG chart was rendered")
	}
}

// TestExportedHTMLLocksToLightTheme is the interim half of Part 3's "the
// export is always light" rule, landed now rather than left as a known gap
// until Part 3.
//
// tokens.css gained dark values this session, activated either by an explicit
// choice or by @media (prefers-color-scheme: dark) — the second of which is
// driven by whatever browser opens the file, not by anything the report
// controls. Without this, a report exported from a light-theme session would
// render dark the moment someone opened it in a dark-mode browser: the same
// document rendering two different ways depending on who reads it, which is
// wrong for an artifact that gets attached to a ticket and is meant to look
// the same for everyone who opens it. data-theme="light" on the root element
// excludes the report from that media query the same way an explicit light
// choice does in the app (tokens.css: the dark block is scoped to
// :root:not([data-theme="light"])), regardless of the reader's OS.
//
// This is not the whole of Part 3 — legibility on paper and the print
// stylesheet are unrelated and still to do — but leaving this specific gap
// open for another session, once the dark values existed to fall into it,
// was not.
func TestExportedHTMLLocksToLightTheme(t *testing.T) {
	html := render(t, sampleDoc(zeroWindowFinding(1, "a <-> b", 4200, 2900)))
	if !regexp.MustCompile(`<html[^>]*\bdata-theme="light"`).MatchString(html) {
		t.Error(`the report's <html> element does not carry data-theme="light"; ` +
			"opened in a dark-mode browser it would now pick up the app's dark palette")
	}
}

// TestHTMLNoWallClock guards the same reproducibility property the JSON has.
func TestHTMLNoWallClock(t *testing.T) {
	html := render(t, sampleDoc(zeroWindowFinding(1, "a <-> b", 4200, 2900)))
	for _, banned := range []string{"generated_at", "Generated at", "Report generated on"} {
		if strings.Contains(html, banned) {
			t.Errorf("report contains %q; a wall-clock field breaks byte-identical output", banned)
		}
	}
}

// TestFindingWordingIsVerbatim checks that the renderer presents the rule
// wording as written rather than reflowing or truncating it. The wording is the
// specification; the presentation layer is not allowed to edit it.
func TestFindingWordingIsVerbatim(t *testing.T) {
	f := zeroWindowFinding(1, "10.2.2.7:5432", 4200, 2900)
	f.Observation = "Advertised a zero receive window 6 times, stalling the sender for 4.2s total " +
		"(longest single stall 2.9s). The other 12 hosts in this capture show no zero window events."
	f.CheckNext = "the receiving application on 10.2.2.7 — a zero window means the application is " +
		"not reading from its socket buffer fast enough."

	html := render(t, sampleDoc(f))

	for _, want := range []string{f.Title, f.Observation, f.CheckNext} {
		if !strings.Contains(html, want) {
			t.Errorf("report does not contain the finding wording verbatim:\n  want: %q", want)
		}
	}
	if !strings.Contains(html, "Frames 7, 9, 11") {
		t.Error("frame references are not rendered in the form the rule wordings use")
	}
	if !strings.Contains(html, "3 shown of 6 occurrences") {
		t.Error("the repetition cap is not disclosed; a reader cannot tell the cited frames are a sample")
	}
}

// TestHTMLEscapesCaptureDerivedText is the hostile-input requirement applied to
// the report. Addresses and ports come out of a capture, which is
// attacker-controlled data, and they reach both the prose and the SVG labels.
func TestHTMLEscapesCaptureDerivedText(t *testing.T) {
	evil := `<script>alert(1)</script>`
	a := zeroWindowFinding(1, evil, 4200, 2900)
	a.Title = "Receiver stopped accepting data — " + evil
	a.Observation = "Observed " + evil
	b := zeroWindowFinding(2, evil+"-2", 1000, 500)

	html := render(t, sampleDoc(a, b))

	if strings.Contains(html, "<script>") {
		t.Fatal("capture-derived text was not escaped; the report would execute it")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the hostile string to appear escaped somewhere in the report")
	}
	// The bar chart puts the same string into an SVG text node and an
	// aria-label, which escape by different paths than the HTML body.
	svgText := regexp.MustCompile(`<svg[\s\S]*?</svg>`).FindAllString(html, -1)
	if len(svgText) == 0 {
		t.Fatal("no SVG rendered, so the SVG escaping path was not exercised")
	}
	for _, s := range svgText {
		if strings.Contains(s, "<script>") {
			t.Error("capture-derived text was not escaped inside an SVG")
		}
	}
}

// TestSingleFindingRendersTileNotChart checks the form heuristic: one subject
// is a number, not a bar chart. A one-bar chart asks the reader to compare
// against nothing.
func TestSingleFindingRendersTileNotChart(t *testing.T) {
	one := render(t, sampleDoc(responseFinding(1, "10.2.2.7:443", 1800, 4100, 30)))
	if !strings.Contains(one, "Response time at p95 · 10.2.2.7:443") {
		t.Error("a single finding should render a stat tile naming its subject")
	}
	if strings.Contains(one, `class="chart"`) {
		t.Error("a single finding rendered a bar chart; one bar compares against nothing")
	}
	// The capture completeness bar is a different form and must still be there.
	if !strings.Contains(one, "chart-stack") {
		t.Error("the completeness bar should render regardless of finding count")
	}

	two := render(t, sampleDoc(
		responseFinding(1, "10.4.4.1:443", 2600, 3000, 30),
		responseFinding(2, "10.4.4.2:443", 1500, 1600, 30),
	))
	if !strings.Contains(two, `class="chart"`) {
		t.Error("two or more findings should render a bar chart")
	}
}

// TestChartsReadTheMetricsRulesActuallyEmit catches a metric rename in a rule
// silently emptying a chart. Without this the figure would just disappear and
// every other test would still pass.
func TestChartsReadTheMetricsRulesActuallyEmit(t *testing.T) {
	html := render(t, sampleDoc(
		zeroWindowFinding(1, "flow-a", 4200, 2900),
		zeroWindowFinding(2, "flow-b", 1500, 800),
		responseFinding(3, "10.4.4.1:443", 2600, 3000, 30),
		responseFinding(4, "10.4.4.2:443", 1500, 1600, 30),
	))

	// Values that can only appear if the metric lookups resolved.
	for _, want := range []string{"4.2s", "1.5s", "2.6s", "30ms"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in the report; a chart metric lookup did not resolve", want)
		}
	}
	if !strings.Contains(html, "threshold") {
		t.Error("the population median reference line is missing from the response chart")
	}
}

// TestEmptyReportStillStatesWhatWasNotChecked is the control that stops a clean
// report reading as an all-clear.
func TestEmptyReportStillStatesWhatWasNotChecked(t *testing.T) {
	html := render(t, sampleDoc())

	// The findings section leads with the calibrated statement and its
	// qualifier — the same wording the in-app clean screen shows — rendered
	// neutral, since this document's coverage is not strong.
	if !strings.Contains(html, "No significant problems found in what was checked") {
		t.Error("an empty report should lead with the calibrated clean statement")
	}
	if !strings.Contains(html, "not the same as the capture being problem-free") {
		t.Error("the clean statement renders without its qualifier, so it reads as a verdict")
	}
	// Scoped past the inlined stylesheet, which necessarily defines the class.
	if _, body, ok := strings.Cut(html, "</style>"); !ok || strings.Contains(body, "coverage-strong") {
		t.Error("a weakly-covered clean report picked up the green treatment")
	}

	if !strings.Contains(html, "Not assessed: something.") {
		t.Error("coverage gaps must be rendered, not dropped")
	}
	if !strings.Contains(html, "not implemented in this build") {
		t.Error("the report must state that most of the rule set was never run")
	}
}

// TestDocWithoutCoverageFallsBackToTheOldEmptyText guards the degenerate case:
// a hand-built document with no coverage must not render an empty banner with
// nothing in it.
func TestDocWithoutCoverageFallsBackToTheOldEmptyText(t *testing.T) {
	doc := sampleDoc()
	doc.Coverage = Coverage{}

	if !strings.Contains(render(t, doc), "Nothing was surfaced by the checks that ran") {
		t.Error("a document without coverage should fall back to the plain empty-list text")
	}
}

// TestLegendSwatchesArePainted guards a failure that looks like nothing at all:
// the ramp classes are shared between SVG marks and HTML legend swatches, and
// an SVG-only `fill` leaves the swatch blank, so the legend silently stops
// carrying identity.
func TestLegendSwatchesArePainted(t *testing.T) {
	for _, class := range []string{"fill-strong", "fill-mid", "fill-soft"} {
		i := strings.Index(styleSource, "."+class+" ")
		if i < 0 {
			t.Errorf("ramp class %q is not defined in the stylesheet", class)
			continue
		}
		rule := styleSource[i:]
		if end := strings.Index(rule, "}"); end >= 0 {
			rule = rule[:end]
		}
		if !strings.Contains(rule, "background:") {
			t.Errorf("ramp class %q sets no background; the HTML legend swatch would render blank", class)
		}
		if !strings.Contains(rule, "fill:") {
			t.Errorf("ramp class %q sets no fill; the SVG mark would render unpainted", class)
		}
	}
}

// TestBarPathGeometry checks the mark spec: a rounded data-end, a square
// baseline end, and no inverted arc on a bar shorter than the corner radius.
func TestBarPathGeometry(t *testing.T) {
	if got := barPath(0, 0, 0, 18, 4); got != "" {
		t.Errorf("zero-width bar should render nothing, got %q", got)
	}
	short := barPath(10, 0, 2, 18, 4)
	if strings.Contains(short, "A") {
		t.Errorf("bar shorter than the radius must not draw an arc: %q", short)
	}
	long := barPath(10, 0, 100, 18, 4)
	if !strings.Contains(long, "A4,4") {
		t.Errorf("expected a 4px rounded data-end: %q", long)
	}
}

// TestStackedBarFillsItsWidth checks that rounding across segments cannot leave
// a gap at the end of a part-to-whole bar, which would misstate the total.
func TestStackedBarFillsItsWidth(t *testing.T) {
	cases := [][]StackSegment{
		{{Label: "a", Count: 1, Class: "fill-strong"}, {Label: "b", Count: 1, Class: "fill-mid"}, {Label: "c", Count: 1, Class: "fill-soft"}},
		{{Label: "a", Count: 13, Class: "fill-strong"}},
		{{Label: "a", Count: 24, Class: "fill-strong"}, {Label: "b", Count: 3, Class: "fill-mid"}, {Label: "c", Count: 15, Class: "fill-soft"}},
		{{Label: "a", Count: 0, Class: "fill-strong"}, {Label: "b", Count: 7, Class: "fill-mid"}, {Label: "c", Count: 0, Class: "fill-soft"}},
	}
	for i, segs := range cases {
		got := string(StackedBar(segs, "t"))
		if got == "" {
			t.Errorf("case %d rendered nothing", i)
			continue
		}
		if !strings.Contains(got, "680") {
			t.Errorf("case %d: bar does not reach the full width: %s", i, got)
		}
	}
	if got := StackedBar(nil, "t"); got != "" {
		t.Error("an empty segment list should render nothing rather than an empty bar")
	}
}

// TestFormatMillis pins the figures used in chart labels to the same shape the
// rule wordings use, so a chart and the prose beside it never disagree.
func TestFormatMillis(t *testing.T) {
	cases := []struct {
		ms   int64
		want string
	}{
		{0, "0ms"}, {30, "30ms"}, {999, "999ms"},
		{1000, "1.0s"}, {1500, "1.5s"}, {4200, "4.2s"}, {-5, "0ms"},
	}
	for _, c := range cases {
		if got := formatMillis(c.ms); got != c.want {
			t.Errorf("formatMillis(%d) = %q, want %q", c.ms, got, c.want)
		}
	}
}
