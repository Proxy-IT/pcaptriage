package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// The template and stylesheet are embedded, so the binary stays a single file
// and the rendered report references nothing external. A report that needed a
// CDN would be useless in exactly the air-gapped environments this tool exists
// for.
//
//go:embed template.html
var templateSource string

// tokensSource is the shared design tokens — the one source of the palette
// both this report and the desktop app consume. frontend/dist/tokens.css is a
// byte-identical copy of it, enforced by test; see tokens.css for why the copy
// exists at all.
//
//go:embed tokens.css
var tokensSource string

//go:embed style.css
var baseStyleSource string

// styleSource is what gets inlined into every report: the shared tokens first,
// then the report's own styles, which reference them.
var styleSource = tokensSource + "\n" + baseStyleSource

var pageTemplate = template.Must(template.New("report").Parse(templateSource))

// StyleSheet returns the embedded report stylesheet, tokens included.
//
// Exported so tests can assert properties of it — that evidence quality carries
// no severity colour, in particular — without a second copy of the rules to
// drift from.
func StyleSheet() string { return styleSource }

// Tokens returns the shared design tokens on their own, for tests that assert
// the token file is the single source of the palette.
func Tokens() string { return tokensSource }

// TopFindingLimit is how many findings lead the report.
//
// BRIEF.md section 3 asks for the five to ten most significant. Ten is the top
// of that range: the list is already ranked, and a reader who stops after five
// has lost nothing.
const TopFindingLimit = 10

// findingView is one finding prepared for rendering.
type findingView struct {
	Rank        int
	RuleID      string
	Title       string
	Observation string
	CheckNext   string
	// Frames is the comma-separated frame list, rendered the way the rule
	// wordings in RULES.md present it.
	Frames string
	// More qualifies the frame list when the finding stands for more
	// occurrences than it cites.
	More         string
	Quality      string
	QualityBasis string
	// Severity is the slug used for the CSS class; SeverityLabel is the word.
	// Colour never carries this signal alone.
	Severity      string
	SeverityLabel string
	IsTop         bool
}

type tileView struct {
	Show    bool
	Label   string
	Value   string
	Context string
}

type legendKey struct {
	Class string
	Label string
	Count string
	Share string
}

type groupView struct {
	RuleID      string
	RuleName    string
	Summary     string
	Findings    []findingView
	FigureTitle string
	Chart       template.HTML
	Legend      []legendKey
	Caption     string
	Tile        tileView
}

type bannerView struct {
	// QualityDisclosure is what the capture-quality assessment covers and what
	// it does not. Composed in the rules package beside R15 rather than written
	// here, so that adding a condition to the rule updates the sentence.
	QualityDisclosure string

	Packets          string
	PacketsContext   string
	Flows            string
	FlowsContext     string
	MidstreamPct     string
	MidstreamContext string
	Snaplen          string
	SnaplenContext   string
}

type subjectRow struct {
	Subject string
	Kind    string
	Rules   string
	Count   string
	Frames  string
}

type pageView struct {
	PageTitle string
	CSS       template.CSS
	Doc       *Document

	Banner             bannerView
	CompletenessChart  template.HTML
	CompletenessLegend []legendKey

	Top        []findingView
	TopCaption string
	Groups     []groupView
	Subjects   []subjectRow

	// Info is the non-gap notes. The gaps themselves render from
	// Doc.Coverage.NotChecked, which is a superset of the unavailable notes:
	// it also carries the completeness-derived gaps (midstream, one-way,
	// evicted flows) that no rule announced.
	Info []Note
}

// WriteHTML renders a self-contained HTML report.
//
// Output is byte-identical for identical input, for the same two reasons the
// JSON is: every collection is already sorted by the time it arrives here, and
// nothing is derived from the wall clock.
func WriteHTML(w io.Writer, doc *Document) error {
	return pageTemplate.Execute(w, buildPage(doc))
}

func buildPage(doc *Document) *pageView {
	p := &pageView{
		PageTitle: "pcap triage — " + baseName(doc.Capture.Path),
		CSS:       template.CSS(styleSource),
		Doc:       doc,
		Banner:    buildBanner(doc),
	}

	p.CompletenessChart, p.CompletenessLegend = buildCompleteness(doc)

	all := make([]findingView, 0, len(doc.Findings))
	for _, f := range doc.Findings {
		all = append(all, toView(f, false))
	}

	limit := TopFindingLimit
	if len(all) < limit {
		limit = len(all)
	}
	p.Top = make([]findingView, limit)
	for i := 0; i < limit; i++ {
		p.Top[i] = all[i]
		p.Top[i].IsTop = true
	}
	switch {
	case len(all) == 0:
		p.TopCaption = "none"
	case len(all) <= TopFindingLimit:
		p.TopCaption = fmt.Sprintf("all %d, most significant first", len(all))
	default:
		p.TopCaption = fmt.Sprintf("%d of %d, most significant first", limit, len(all))
	}

	p.Groups = buildGroups(doc)
	p.Subjects = buildSubjects(doc)

	for _, n := range doc.Notes {
		// Unavailable notes are already inside Doc.Coverage.NotChecked, which
		// is what the template renders; repeating them here would list every
		// gap twice.
		if n.Kind != "unavailable" {
			p.Info = append(p.Info, n)
		}
	}

	return p
}

func toView(f Finding, isTop bool) findingView {
	v := findingView{
		Rank:          f.Rank,
		RuleID:        f.RuleID,
		Title:         f.Title,
		Observation:   f.Observation,
		CheckNext:     f.CheckNext,
		Quality:       f.Quality,
		QualityBasis:  f.QualityBasis,
		Severity:      f.Severity,
		SeverityLabel: f.SeverityLabel,
		IsTop:         isTop,
	}

	parts := make([]string, 0, len(f.Frames))
	for _, fr := range f.Frames {
		parts = append(parts, strconv.FormatUint(fr, 10))
	}
	v.Frames = strings.Join(parts, ", ")
	if v.Frames == "" {
		v.Frames = "—"
	}

	// The repetition cap means one finding stands for every occurrence on its
	// subject. Say so where the cited frames are a sample rather than the lot.
	if f.TotalCount > uint64(len(f.Frames)) {
		v.More = fmt.Sprintf("(%d shown of %d occurrences)", len(f.Frames), f.TotalCount)
	}
	return v
}

func buildBanner(doc *Document) bannerView {
	c := doc.Capture

	b := bannerView{
		QualityDisclosure: rules.CaptureQualityDisclosure(),
		Packets:           formatCount(c.PacketsRead),
		Flows:             formatCount(uint64(c.TCPFlows)),
	}

	b.PacketsContext = fmt.Sprintf("%s TCP · %s other · %s undecodable",
		formatCount(c.PacketsTCP), formatCount(c.PacketsNonTCP), formatCount(c.PacketsUndecoded))
	b.FlowsContext = fmt.Sprintf("across %s host%s", formatCount(uint64(c.TCPHosts)), plural(c.TCPHosts))

	if c.TCPFlows > 0 {
		pct := float64(c.FlowsMidstream) * 100 / float64(c.TCPFlows)
		b.MidstreamPct = fmt.Sprintf("%.0f%%", pct)
		b.MidstreamContext = fmt.Sprintf("%d of %d flow%s midstream", c.FlowsMidstream, c.TCPFlows, plural(c.TCPFlows))
	} else {
		b.MidstreamPct = "—"
		b.MidstreamContext = "no TCP flows observed"
	}

	if c.Snaplen != nil {
		b.Snaplen = formatCount(uint64(*c.Snaplen))
		b.SnaplenContext = "bytes per frame, as declared by the file"
	} else {
		b.Snaplen = "none"
		b.SnaplenContext = "the file declares no capture limit"
	}

	return b
}

// buildCompleteness draws the part-to-whole bar of flows by completeness.
//
// The ramp is ordinal rather than categorical: complete, partial and midstream
// are an ordered scale of how much protocol state was observed, so more state
// reads as more ink. Every segment's count and share appear in the legend, so
// nothing is carried by colour alone.
func buildCompleteness(doc *Document) (template.HTML, []legendKey) {
	c := doc.Capture
	if c.TCPFlows <= 0 {
		return "", nil
	}

	segs := []StackSegment{
		{Label: "Complete", Count: c.FlowsComplete, Class: "fill-strong"},
		{Label: "Partial", Count: c.FlowsPartial, Class: "fill-mid"},
		{Label: "Midstream", Count: c.FlowsMidstream, Class: "fill-soft"},
	}

	legend := make([]legendKey, 0, len(segs))
	for _, s := range segs {
		legend = append(legend, legendKey{
			Class: s.Class,
			Label: s.Label,
			Count: strconv.Itoa(s.Count),
			Share: fmt.Sprintf("%.0f%%", float64(s.Count)*100/float64(c.TCPFlows)),
		})
	}

	return StackedBar(segs, "Flows by capture completeness"), legend
}

// Metric keys the figures read. Named here so a rename in a rule shows up as a
// compile-time reference rather than a silently empty chart; the figure tests
// assert these still resolve.
const (
	metricCumulativeStall = "cumulative_stall_ms"
	metricMaxStall        = "max_stall_ms"
	metricP95             = "p95_ms"
	metricMax             = "max_ms"
	metricPopMedianP95    = "population_median_p95_ms"
)

func buildGroups(doc *Document) []groupView {
	byRule := map[string][]Finding{}
	for _, f := range doc.Findings {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
	}

	ids := make([]string, 0, len(byRule))
	for id := range byRule {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	summaries := map[string]string{}
	for _, c := range doc.Checks {
		summaries[c.ID] = c.Summary
	}

	groups := make([]groupView, 0, len(ids))
	for _, id := range ids {
		fs := byRule[id]
		g := groupView{RuleID: id, Summary: summaries[id]}
		if len(fs) > 0 {
			g.RuleName = fs[0].Rule
		}
		for _, f := range fs {
			g.Findings = append(g.Findings, toView(f, false))
		}

		switch id {
		case "R01":
			buildR01Figure(&g, fs)
		case "R04":
			buildR04Figure(&g, fs)
		}
		groups = append(groups, g)
	}
	return groups
}

// buildR01Figure charts cumulative stall per receiver, with the longest single
// stall as a leading segment of each bar.
//
// The split is the useful part: it says whether the total came from one long
// stall or from many short ones, which is the difference between an outage and
// background flow control.
func buildR01Figure(g *groupView, fs []Finding) {
	g.FigureTitle = "Time the sender was blocked, by receiver"

	// A single subject is a number, not a chart. A one-bar bar chart asks the
	// reader to compare against nothing.
	if len(fs) == 1 {
		cum, ok := metricInt(fs[0].Metrics, metricCumulativeStall)
		if !ok {
			return
		}
		longest, _ := metricInt(fs[0].Metrics, metricMaxStall)
		g.Tile = tileView{
			Show:    true,
			Label:   "Cumulative stall · " + label(fs[0]),
			Value:   formatMillis(cum),
			Context: fmt.Sprintf("longest single stall %s", formatMillis(longest)),
		}
		g.Caption = "One receiver stalled a sender in this capture, so there is nothing to compare it against here."
		return
	}

	bars := make([]Bar, 0, len(fs))
	for _, f := range fs {
		cum, ok := metricInt(f.Metrics, metricCumulativeStall)
		if !ok {
			continue
		}
		longest, _ := metricInt(f.Metrics, metricMaxStall)
		bars = append(bars, Bar{
			Label:     label(f),
			Value:     float64(cum),
			Part:      float64(longest),
			ValueText: formatMillis(cum),
		})
	}
	if len(bars) < 2 {
		return
	}

	g.Chart = BarChart(bars, 0, "Time the sender was blocked, by receiver")
	g.Legend = []legendKey{
		{Class: "fill-strong", Label: "Longest single stall"},
		{Class: "fill-soft", Label: "Remaining stall time"},
	}
	g.Caption = "Bars are ordered as the findings are, most significant first, which is not the same as longest: a shorter stall close to a reset outranks a longer one during steady state."
}

// buildR04Figure charts p95 response time per flagged server against the
// capture-wide population median.
//
// The threshold line is the point of the chart. A server's p95 in isolation
// says nothing; the same figure against what the rest of the capture manages is
// the whole finding.
func buildR04Figure(g *groupView, fs []Finding) {
	g.FigureTitle = "Server response time at p95, against the capture"

	median, hasMedian := metricInt(fs[0].Metrics, metricPopMedianP95)

	if len(fs) == 1 {
		p95, ok := metricInt(fs[0].Metrics, metricP95)
		if !ok {
			return
		}
		max, _ := metricInt(fs[0].Metrics, metricMax)
		ctx := fmt.Sprintf("max %s", formatMillis(max))
		if hasMedian && median > 0 {
			ctx += fmt.Sprintf(" · capture median p95 %s", formatMillis(median))
		}
		g.Tile = tileView{
			Show:    true,
			Label:   "Response time at p95 · " + label(fs[0]),
			Value:   formatMillis(p95),
			Context: ctx,
		}
		g.Caption = "One server stood out in this capture, so there is nothing to compare it against here. Measured from last request byte to first response byte, with network round-trip time subtracted."
		return
	}

	bars := make([]Bar, 0, len(fs))
	for _, f := range fs {
		p95, ok := metricInt(f.Metrics, metricP95)
		if !ok {
			continue
		}
		bars = append(bars, Bar{
			Label:     label(f),
			Value:     float64(p95),
			ValueText: formatMillis(p95),
		})
	}
	if len(bars) < 2 {
		return
	}

	var reference float64
	if hasMedian && median > 0 {
		reference = float64(median)
	}
	g.Chart = BarChart(bars, reference, "Server response time at p95, against the capture")
	if reference > 0 {
		g.Caption = fmt.Sprintf(
			"Dashed line: the capture-wide median p95 of %s, taken across every server endpoint with enough exchanges to assess. Measured from last request byte to first response byte, with network round-trip time subtracted.",
			formatMillis(median))
	} else {
		g.Caption = "Measured from last request byte to first response byte, with network round-trip time subtracted."
	}
}

// buildSubjects tabulates what raised findings.
//
// This is the bounded stand-in for a per-flow table: it is sized by the
// findings rather than by the flow count, so it costs nothing to retain.
func buildSubjects(doc *Document) []subjectRow {
	type acc struct {
		kind   string
		rules  []string
		count  uint64
		frames []uint64
	}
	agg := map[string]*acc{}

	for _, f := range doc.Findings {
		a := agg[f.Subject]
		if a == nil {
			a = &acc{kind: f.ScopeKind}
			agg[f.Subject] = a
		}
		a.rules = append(a.rules, f.RuleID)
		a.count += f.TotalCount
		a.frames = append(a.frames, f.Frames...)
	}

	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := make([]subjectRow, 0, len(keys))
	for _, k := range keys {
		a := agg[k]
		sort.Strings(a.rules)
		sort.Slice(a.frames, func(i, j int) bool { return a.frames[i] < a.frames[j] })

		shown := a.frames
		suffix := ""
		if len(shown) > 6 {
			shown = shown[:6]
			suffix = " …"
		}
		parts := make([]string, 0, len(shown))
		for _, fr := range shown {
			parts = append(parts, strconv.FormatUint(fr, 10))
		}

		kind := a.kind
		if kind == "" {
			kind = "unspecified"
		}
		rows = append(rows, subjectRow{
			Subject: k,
			Kind:    kind,
			Rules:   strings.Join(a.rules, ", "),
			Count:   formatCount(a.count),
			Frames:  strings.Join(parts, ", ") + suffix,
		})
	}
	return rows
}

// label returns the short name for a finding's subject, falling back to the
// scope key where a rule has not supplied one.
func label(f Finding) string {
	if f.SubjectLabel != "" {
		return f.SubjectLabel
	}
	return f.Subject
}

// metricInt reads a numeric metric. The metrics map carries whatever numeric
// type the rule wrote, so every integer kind has to be accepted.
func metricInt(m map[string]any, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// formatCount renders a count with thousands separators.
func formatCount(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
