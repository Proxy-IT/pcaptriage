// Package report renders analysis results as JSON and as a self-contained HTML
// report.
//
// Both renderings are views over the same Document, so they cannot disagree
// about what was found. The HTML is a presentation of that document, never a
// second analysis path.
//
// Output is byte-identical for identical input. Two things make that hold:
// every collection is sorted before it is emitted, and nothing derived from
// the wall clock appears anywhere in the document. A "generated at" timestamp
// would break reproducibility for no benefit the capture timestamps do not
// already give.
package report

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// SchemaVersion is the version of this JSON document's structure.
//
// This format is internal and is not an API. With no shipped CLI there are no
// external consumers: it is a format shared between the engine, the app, the
// export action, and the golden-file tests, versioned in git like any other
// internal interface and changeable freely.
//
// The version is still stamped, for two reasons that survive the format being
// internal. A user comparing an exported report from last month against one
// from today needs to tell "the network changed" from "the tool changed", and
// the golden files need a visible marker when the shape shifts underneath them.
// Neither is a stability promise.
//
// History:
//
//	4 — added coverage: what the run examined and what it could not, the same
//	    data the in-app clean screen shows. The export is read by people with
//	    zero context, so it carries the same §9 false-all-clear guard. Additive.
//	3 — added schema_note, stating in the document itself that this format is
//	    not a stability contract. Additive.
//	2 — findings gained subject, scope_kind and subject_label, naming what each
//	    finding is about and at what granularity. Additive: every field present
//	    in 1 is still present and unchanged.
//	1 — initial.
const SchemaVersion = "4"

// RulesetVersion versions the rules, thresholds and wording separately from
// the tool itself. A user comparing a report from last month against one from
// today needs to tell "the network changed" from "the tool changed".
const RulesetVersion = "1.0.0-partial"

// SchemaNote rides in every emitted document.
//
// It costs one line and stops someone building against this format on the
// assumption that it will hold still — which, with no shipped CLI and no
// external consumers, it is under no obligation to do.
const SchemaNote = "This format is internal to pcaptriage and may change in any release. It is not a stability contract; do not build tooling that depends on its shape."

// Document is the top-level JSON report.
type Document struct {
	SchemaVersion string `json:"schema_version"`
	// SchemaNote says plainly that the shape above is not promised.
	SchemaNote string     `json:"schema_note"`
	Tool       ToolInfo   `json:"tool"`
	Invocation Invocation `json:"invocation"`
	Capture    Capture    `json:"capture"`
	// Coverage is what the run examined and what it could not — the same data
	// the in-app clean screen shows, carried in every export so a reader with
	// no context sees the gaps beside the result.
	Coverage Coverage  `json:"coverage"`
	Checks   []Check   `json:"checks"`
	Findings []Finding `json:"findings"`
	Notes    []Note    `json:"notes"`
}

// ToolInfo stamps the versions.
type ToolInfo struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	RulesetVersion string `json:"ruleset_version"`
	// Build states plainly that this is a partial rule set. Without it a clean
	// report could be read as an all-clear from checks that were never built.
	Build string `json:"build"`
}

// Invocation records how the tool was called, so a report can be reproduced.
type Invocation struct {
	Args     []string `json:"args"`
	Input    string   `json:"input"`
	MaxFlows int      `json:"max_flows"`
}

// Capture is the completeness banner in structured form.
type Capture struct {
	Path     string `json:"path"`
	Format   string `json:"format"`
	LinkType string `json:"link_type"`

	Snaplen *uint32 `json:"snaplen"`

	PacketsRead      uint64            `json:"packets_read"`
	PacketsTCP       uint64            `json:"packets_tcp"`
	PacketsNonTCP    uint64            `json:"packets_non_tcp"`
	PacketsUndecoded uint64            `json:"packets_undecoded"`
	UndecodedReasons map[string]uint64 `json:"undecoded_reasons,omitempty"`

	FirstPacketTime string  `json:"first_packet_time"`
	LastPacketTime  string  `json:"last_packet_time"`
	DurationSeconds float64 `json:"duration_seconds"`
	Timezone        string  `json:"timezone"`

	TCPFlows int `json:"tcp_flows"`
	TCPHosts int `json:"tcp_hosts"`

	FlowsComplete  int `json:"flows_complete"`
	FlowsPartial   int `json:"flows_partial"`
	FlowsMidstream int `json:"flows_midstream"`
	FlowsOneWay    int `json:"flows_one_way"`

	FlowCap       int    `json:"flow_cap"`
	FlowsEvicted  uint64 `json:"flows_evicted"`
	PeakLiveFlows int    `json:"peak_live_flows"`
}

// Check reports a rule and whether it ran.
type Check struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	BaseWeight float64 `json:"base_weight"`
	Status     string  `json:"status"`
	Summary    string  `json:"summary"`
}

// Finding is one anomaly, rendered.
//
// The significance score is deliberately absent. It exists only to order this
// list and is never shown to the user as a number; the rank is what the reader
// needs.
type Finding struct {
	Rank   int    `json:"rank"`
	RuleID string `json:"rule_id"`
	Rule   string `json:"rule"`
	// Subject names what the finding is about, and ScopeKind says whether that
	// is a flow or an address:port.
	Subject   string `json:"subject"`
	ScopeKind string `json:"scope_kind"`
	// SubjectLabel is the short name for the subject, used where the full
	// scope key will not fit.
	SubjectLabel string `json:"subject_label"`
	Title        string `json:"title"`
	Observation  string `json:"observation"`
	CheckNext    string `json:"check_next"`

	Frames     []uint64 `json:"frames"`
	FirstFrame uint64   `json:"first_frame"`
	WorstFrame uint64   `json:"worst_frame"`
	TotalCount uint64   `json:"total_count"`

	Quality      string `json:"quality"`
	QualityBasis string `json:"quality_basis,omitempty"`

	// Severity is how much this matters; Quality above is how sure the tool is.
	// Two different questions, deliberately two fields.
	//
	// SeverityLabel is the word rendered beside the colour. It travels with the
	// slug because colour is never the only carrier of this signal, and the word
	// is authored in one place rather than restated by each renderer.
	Severity      string `json:"severity"`
	SeverityLabel string `json:"severity_label"`

	Metrics map[string]any `json:"metrics,omitempty"`
}

// Note is a check that could not be performed, or a qualification on the run.
type Note struct {
	Kind   string `json:"kind"`
	RuleID string `json:"rule_id,omitempty"`
	Text   string `json:"text"`
}

// Build converts an analysis result into a report document.
func Build(res *analysis.Result, inv Invocation, version string) *Document {
	c := res.Capture

	var snaplen *uint32
	if c.SnaplenKnown {
		s := c.Snaplen
		snaplen = &s
	}

	var duration float64
	if !c.FirstPacketTime.IsZero() && c.LastPacketTime.After(c.FirstPacketTime) {
		duration = c.LastPacketTime.Sub(c.FirstPacketTime).Seconds()
	}

	doc := &Document{
		SchemaVersion: SchemaVersion,
		SchemaNote:    SchemaNote,
		Tool: ToolInfo{
			Name:           "pcaptriage",
			Version:        version,
			RulesetVersion: RulesetVersion,
			// Worded to stand on its own. It is rendered in the JSON, in the
			// exported HTML report, and in the app, and referring to anything
			// "below" would be wrong in at least one of them. Derived from the
			// rule registry so it cannot go stale as rules land.
			Build: rules.BuildDisclosure(),
		},
		Invocation: inv,
		Capture: Capture{
			Path:             c.Path,
			Format:           c.Format,
			LinkType:         c.LinkType,
			Snaplen:          snaplen,
			PacketsRead:      c.PacketsRead,
			PacketsTCP:       c.PacketsTCP,
			PacketsNonTCP:    c.PacketsNonTCP,
			PacketsUndecoded: c.PacketsUndecoded,
			UndecodedReasons: c.UndecodedReasons,
			FirstPacketTime:  formatTime(c.FirstPacketTime),
			LastPacketTime:   formatTime(c.LastPacketTime),
			DurationSeconds:  duration,
			Timezone:         "UTC",
			TCPFlows:         c.TCPFlows,
			TCPHosts:         c.TCPHosts,
			FlowsComplete:    c.CompleteFlows,
			FlowsPartial:     c.PartialFlows,
			FlowsMidstream:   c.MidstreamFlows,
			FlowsOneWay:      c.OneWayFlows,
			FlowCap:          c.FlowCap,
			FlowsEvicted:     c.FlowsEvicted,
			PeakLiveFlows:    c.PeakLiveFlows,
		},
	}

	doc.Checks = make([]Check, 0, len(res.Checks))
	for _, m := range res.Checks {
		doc.Checks = append(doc.Checks, Check{
			ID:         m.ID,
			Name:       m.Name,
			BaseWeight: m.BaseWeight,
			Status:     "ran",
			Summary:    m.Summary,
		})
	}
	sort.Slice(doc.Checks, func(i, j int) bool { return doc.Checks[i].ID < doc.Checks[j].ID })

	doc.Findings = make([]Finding, 0, len(res.Findings))
	for i, f := range res.Findings {
		// Derived here rather than in the engine: it is a reading of the score,
		// not a property of the detection, and the order below is untouched.
		severity := rules.SeverityFor(f.Significance)
		doc.Findings = append(doc.Findings, Finding{
			Rank:          i + 1,
			RuleID:        f.RuleID,
			Rule:          f.RuleName,
			Subject:       f.ScopeKey,
			ScopeKind:     string(f.ScopeKind),
			SubjectLabel:  f.SubjectLabel,
			Title:         f.Title,
			Observation:   f.Observation,
			CheckNext:     f.CheckNext,
			Frames:        nonNilFrames(f.Frames),
			FirstFrame:    f.FirstFrame,
			WorstFrame:    f.WorstFrame,
			TotalCount:    f.TotalCount,
			Quality:       string(f.Quality),
			QualityBasis:  f.QualityBasis,
			Severity:      string(severity),
			SeverityLabel: severity.Label(),
			Metrics:       f.Metrics,
		})
	}

	doc.Notes = make([]Note, 0, len(res.Notes))
	for _, n := range res.Notes {
		doc.Notes = append(doc.Notes, Note{Kind: n.Kind, RuleID: n.RuleID, Text: n.Text})
	}

	doc.Coverage = buildCoverage(res)

	return doc
}

// Write renders the document as indented JSON with a trailing newline.
func Write(w io.Writer, doc *Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Report prose is plain text and must not be mangled into < escapes.
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func nonNilFrames(f []uint64) []uint64 {
	if f == nil {
		return []uint64{}
	}
	return f
}
