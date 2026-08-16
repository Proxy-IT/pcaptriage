// Package findings holds the retained tier of the two-tier memory model:
// detected anomalies, their frame references, and the notes describing checks
// that could not be performed.
//
// Findings are held to the end of the run rather than streamed out as they are
// detected, because both impact ranking and presentation-layer filtering need
// the full picture: you cannot rank against a population you have not finished
// counting, and you cannot filter a report you have already written.
package findings

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Quality is the evidence quality tag carried by every finding, per BRIEF.md
// section 10.
type Quality string

const (
	// Confirmed means the finding is derived from directly observed protocol
	// state.
	Confirmed Quality = "confirmed"
	// Inferred means it is derived from a defensible deduction. The basis must
	// be stated alongside it.
	Inferred Quality = "inferred"
	// Unavailable means the check could not be performed. These are rendered
	// in the report rather than silently dropped: a report that looks clean
	// because half the checks never ran will close a ticket on a live fault.
	Unavailable Quality = "unavailable"
)

// ScopeKind names what kind of subject a finding is about.
//
// Rules do not all work at the same granularity: R01 is per flow, R04 is per
// server endpoint. A report that tabulates findings has to say which, rather
// than implying every finding names a flow.
type ScopeKind string

const (
	// ScopeFlow means the finding is about one flow.
	ScopeFlow ScopeKind = "flow"
	// ScopeEndpoint means the finding is about one address:port, aggregated
	// across every flow that reached it.
	ScopeEndpoint ScopeKind = "endpoint"
)

// MaxFrames caps the representative frame references retained per finding.
const MaxFrames = 8

// PacketRole says why a packet appears in a finding's evidence.
type PacketRole string

const (
	// RoleFlagged marks a packet the rule fired on.
	RoleFlagged PacketRole = "flagged"
	// RoleContext marks a packet that makes the flagged ones legible — the
	// non-zero window immediately before a stall, the request preceding a slow
	// response. Without it a reader sees what was flagged but not why it stood
	// out.
	RoleContext PacketRole = "context"
)

// PacketRef is a header snapshot of one frame, for showing the reader what the
// finding is actually pointing at.
//
// Headers and derived fields only. There is deliberately no field capable of
// holding payload: the "no payload bytes in output" guarantee is structural,
// and adding one here would quietly break it for every rule at once.
type PacketRef struct {
	Frame uint64    `json:"frame"`
	Time  time.Time `json:"time"`
	// RelSeconds is seconds since the first packet in the capture, which is
	// what Wireshark's default time column shows.
	RelSeconds float64 `json:"rel_seconds"`

	Src string `json:"src"`
	Dst string `json:"dst"`
	// Protocol is the transport, as Wireshark labels it.
	Protocol string `json:"protocol"`
	// Length is the frame's original length on the wire.
	Length int `json:"length"`

	Seq        uint32 `json:"seq"`
	Ack        uint32 `json:"ack"`
	Window     uint16 `json:"window"`
	Flags      string `json:"flags"`
	PayloadLen int    `json:"payload_len"`

	// Info is the one-line summary, in the shape Wireshark's info column uses.
	Info string `json:"info"`

	// Markers are Wireshark-style expert annotations, e.g. "TCP ZeroWindow".
	// They are supplied by the rule that detected the condition rather than
	// derived here, so the report never claims an annotation the tool did not
	// actually establish.
	Markers []string `json:"markers,omitempty"`

	Role PacketRole `json:"role"`
	// Note is a short observation about this row's part in the finding. Like
	// every other line the tool emits it states what was seen, never why.
	Note string `json:"note,omitempty"`
}

// Summary renders the packet the way Wireshark's info column does, so a reader
// who opens the capture recognises the same line.
func (p PacketRef) Summary() string {
	var b strings.Builder
	for _, m := range p.Markers {
		b.WriteString("[")
		b.WriteString(m)
		b.WriteString("] ")
	}
	if p.Flags != "" {
		b.WriteString("[")
		b.WriteString(p.Flags)
		b.WriteString("] ")
	}
	fmt.Fprintf(&b, "Seq=%d Ack=%d Win=%d Len=%d", p.Seq, p.Ack, p.Window, p.PayloadLen)
	return b.String()
}

// Finding is one detected anomaly.
//
// The prose fields follow the structure every rule in RULES.md uses: what was
// observed, why it stood out, which frames evidence it, and what to check
// next. None of them assert a cause.
type Finding struct {
	RuleID   string
	RuleName string

	// ScopeKey uniquely identifies what this finding is about — a flow for
	// per-flow rules, a server endpoint for per-endpoint rules. The store uses
	// it to enforce one finding per rule per scope.
	ScopeKey string
	// ScopeKind says which of those it is, so a reader can be shown a table of
	// subjects without having to parse ScopeKey.
	ScopeKind ScopeKind
	// SubjectLabel is the short name for the thing the finding is about, for
	// places too narrow for the full scope key — a chart axis, a stat tile.
	//
	// It is not always a prefix of ScopeKey: R01 is keyed by flow but is about
	// the receiver within it, and an axis labelled with the flow key would
	// truncate away the part that matters.
	SubjectLabel string

	// Title, Observation and CheckNext carry the wording specified in
	// RULES.md, parameterised.
	Title       string
	Observation string
	CheckNext   string

	// Frames are the representative frame references, ascending.
	Frames []uint64
	// FirstFrame and WorstFrame are the first and worst occurrences.
	FirstFrame uint64
	WorstFrame uint64
	// TotalCount is how many occurrences the finding stands for. A flow with
	// fifty thousand events is one finding with a count of fifty thousand.
	TotalCount uint64

	Quality      Quality
	QualityBasis string

	// Packets are the frames a reader should look at, in frame order: the ones
	// the rule fired on, plus the context that makes them legible.
	//
	// Not carried into the report Document yet — the app renders it, the JSON
	// and exported HTML do not. Collecting it here rather than in the app is
	// what keeps the two interfaces from diverging when it is.
	Packets []PacketRef

	// Metrics carries the derived numbers behind the wording, so the JSON
	// consumer does not have to parse prose. Values are limited to numbers,
	// strings and bools; encoding/json sorts the keys.
	Metrics map[string]any

	// Significance orders findings and is never rendered to the user as a
	// number. It is not emitted in the report.
	Significance float64
}

// Note records a check that could not be performed, or a qualification on the
// run as a whole.
type Note struct {
	// Kind is "unavailable" for a check that did not run, or "info" for a
	// qualification on findings that did.
	Kind   string
	RuleID string
	Text   string
}

// Store accumulates findings and notes for the run.
//
// It enforces the repetition cap: at most one finding per rule per scope.
//
// # Observability: completion-only, deliberately
//
// This store is a write-only sink until the run completes, and then a read-only
// snapshot. There is no subscription, no callback, and no incremental reader,
// and that is a decision rather than an omission.
//
// The reason is that a finding is not fully itself until the run ends. Its
// significance is computed against capture-wide medians, and its wording quotes
// the population directly — "the other 12 hosts in this capture show no zero
// window events" is a claim about hosts that may not have been read yet. A
// mid-run reader would therefore be handed values the store is going to
// contradict: an ordering that reshuffles, and sentences that turn out false.
// Publishing a value we intend to retract is worse than publishing nothing.
//
// Determinism (constraint 5) is the second reason. A mid-run view would be a
// second output surface, and every output surface has to be byte-identical
// across runs. Ranking happens once, over the full population, at completion,
// and there is exactly one place that ordering is decided.
//
// This does not foreclose progressive results. If findings should ever appear
// while a capture is still being read, the right shape is a separate provisional
// channel carrying detections *without* significance or comparative clauses,
// re-ranked into this store at completion — not an observable version of this
// type. Making that a different type is what keeps the two contracts from being
// confused for one another.
//
// Seal marks completion. Reading before it is a programming error and panics,
// so a rule that reaches for the population mid-Emit fails in its own tests
// rather than shipping a subtly wrong comparison.
type Store struct {
	seen   map[string]bool
	list   []*Finding
	notes  []Note
	sealed bool
}

// NewStore returns an empty findings store.
func NewStore() *Store {
	return &Store{seen: make(map[string]bool)}
}

// Seal marks the run complete, after which the store is readable and no further
// findings may be added.
func (s *Store) Seal() { s.sealed = true }

// Sealed reports whether the run has completed.
func (s *Store) Sealed() bool { return s.sealed }

// mustBeSealed guards the readers. See the observability note on Store.
func (s *Store) mustBeSealed(method string) {
	if !s.sealed {
		panic("findings: Store." + method + " called before Seal; " +
			"findings are only meaningful once the whole capture has been read " +
			"— see the observability note on Store")
	}
}

// Add records a finding. It returns false if a finding for the same rule and
// scope was already recorded, which is the repetition cap doing its job.
func (s *Store) Add(f *Finding) bool {
	if s.sealed {
		panic("findings: Store.Add called after Seal; the run is over")
	}
	k := f.RuleID + "\x00" + f.ScopeKey
	if s.seen[k] {
		return false
	}
	s.seen[k] = true
	s.list = append(s.list, f)
	return true
}

// AddNote records a note.
func (s *Store) AddNote(n Note) { s.notes = append(s.notes, n) }

// Findings returns the findings ordered for presentation: most significant
// first, with ties broken deterministically so identical input produces
// identical output.
func (s *Store) Findings() []*Finding {
	s.mustBeSealed("Findings")
	out := make([]*Finding, len(s.list))
	copy(out, s.list)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Significance != b.Significance {
			return a.Significance > b.Significance
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ScopeKey != b.ScopeKey {
			return a.ScopeKey < b.ScopeKey
		}
		return a.FirstFrame < b.FirstFrame
	})
	return out
}

// Notes returns the notes in a stable order: by rule, then kind, then text.
func (s *Store) Notes() []Note {
	s.mustBeSealed("Notes")
	out := make([]Note, len(s.notes))
	copy(out, s.notes)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Text < b.Text
	})
	return out
}

// EvidenceMode selects which occurrences an Evidence keeps as representative.
type EvidenceMode uint8

const (
	// ModeFirst keeps the earliest occurrences. Use where the reader wants to
	// see where the condition started.
	ModeFirst EvidenceMode = iota
	// ModeWorst keeps the highest-valued occurrences. Use where the reader
	// wants to see the condition at its most pronounced.
	ModeWorst
)

type occurrence struct {
	frame uint64
	when  time.Time
	value float64
	// packet is the header snapshot, present only where the rule asked for one.
	packet *PacketRef
}

// Evidence accumulates occurrences of a condition under the repetition cap:
// the first occurrence, the worst occurrence, up to MaxFrames representative
// frames, and the total count.
//
// This is what stops a flow that retransmits fifty thousand times from
// producing fifty thousand findings.
type Evidence struct {
	Mode EvidenceMode

	Total uint64

	first    occurrence
	hasFirst bool
	worst    occurrence
	hasWorst bool

	samples []occurrence
}

// Record folds in one occurrence. value ranks occurrences against each other:
// use the metric the rule scores on, or zero where only ordering matters.
func (e *Evidence) Record(frame uint64, when time.Time, value float64) {
	e.record(occurrence{frame: frame, when: when, value: value}, nil)
}

// PacketSource supplies a header snapshot on demand.
//
// Evidence calls it only when the occurrence is going to be retained, so a flow
// with fifty thousand events snapshots at most a handful of them rather than
// building and discarding fifty thousand.
type PacketSource func() PacketRef

// RecordPacket folds in one occurrence and, if it is retained, captures the
// packet behind it.
func (e *Evidence) RecordPacket(frame uint64, when time.Time, value float64, src PacketSource) {
	e.record(occurrence{frame: frame, when: when, value: value}, src)
}

func (e *Evidence) record(o occurrence, src PacketSource) {
	e.Total++

	// A snapshot is built at most once per Record even when the occurrence is
	// retained in several places.
	var snap *PacketRef
	take := func() *PacketRef {
		if src == nil {
			return nil
		}
		if snap == nil {
			ref := src()
			snap = &ref
		}
		return snap
	}

	if !e.hasFirst {
		e.first = o
		e.first.packet = take()
		e.hasFirst = true
	}
	if !e.hasWorst || o.value > e.worst.value || (o.value == e.worst.value && o.frame < e.worst.frame) {
		e.worst = o
		e.worst.packet = take()
		e.hasWorst = true
	}

	switch e.Mode {
	case ModeFirst:
		if len(e.samples) < MaxFrames {
			s := o
			s.packet = take()
			e.samples = append(e.samples, s)
		}
	case ModeWorst:
		if e.wouldKeep(o) {
			s := o
			s.packet = take()
			e.insertWorst(s)
		}
	}
}

// wouldKeep reports whether an occurrence would survive insertion into the
// worst-N set, so a snapshot is only taken for one that will.
func (e *Evidence) wouldKeep(o occurrence) bool {
	if len(e.samples) < MaxFrames {
		return true
	}
	last := e.samples[len(e.samples)-1]
	if o.value != last.value {
		return o.value > last.value
	}
	return o.frame < last.frame
}

// Packets returns the header snapshots for the occurrences this evidence
// retained, in frame order. Occurrences recorded without a source contribute
// nothing.
func (e *Evidence) Packets() []PacketRef {
	seen := make(map[uint64]bool, MaxFrames+2)
	out := make([]PacketRef, 0, MaxFrames+2)

	add := func(o occurrence) {
		if o.packet == nil || seen[o.frame] {
			return
		}
		seen[o.frame] = true
		out = append(out, *o.packet)
	}

	if e.hasFirst {
		add(e.first)
	}
	if e.hasWorst {
		add(e.worst)
	}
	for _, s := range e.samples {
		add(s)
	}

	SortPacketRefs(out)
	return out
}

// Note updates the worst occurrence without counting a new one.
//
// Rules use this where the value that ranks an occurrence is only known later
// than the occurrence itself — a stall's duration is not known until it ends,
// but the frame worth citing is the one that opened it.
func (e *Evidence) Note(frame uint64, when time.Time, value float64) {
	if !e.hasWorst || value > e.worst.value || (value == e.worst.value && frame < e.worst.frame) {
		// The frame is one already recorded, so its snapshot is carried across
		// rather than lost — re-ranking an occurrence must not drop the packet
		// behind it.
		e.worst = occurrence{
			frame: frame, when: when, value: value,
			packet: e.lookupPacket(frame),
		}
		e.hasWorst = true
	}
}

// lookupPacket finds an already-captured snapshot for a frame.
func (e *Evidence) lookupPacket(frame uint64) *PacketRef {
	if e.hasFirst && e.first.frame == frame && e.first.packet != nil {
		return e.first.packet
	}
	for i := range e.samples {
		if e.samples[i].frame == frame && e.samples[i].packet != nil {
			return e.samples[i].packet
		}
	}
	if e.hasWorst && e.worst.frame == frame {
		return e.worst.packet
	}
	return nil
}

// insertWorst maintains samples sorted by value descending, then frame
// ascending, truncated to MaxFrames.
func (e *Evidence) insertWorst(o occurrence) {
	i := sort.Search(len(e.samples), func(i int) bool {
		s := e.samples[i]
		if s.value != o.value {
			return s.value < o.value
		}
		return s.frame > o.frame
	})
	if i >= MaxFrames {
		return
	}
	if len(e.samples) < MaxFrames {
		e.samples = append(e.samples, occurrence{})
	}
	copy(e.samples[i+1:], e.samples[i:])
	e.samples[i] = o
}

// FirstFrame reports the frame of the first occurrence.
func (e *Evidence) FirstFrame() uint64 { return e.first.frame }

// FirstTime reports the time of the first occurrence.
func (e *Evidence) FirstTime() time.Time { return e.first.when }

// WorstFrame reports the frame of the worst occurrence.
func (e *Evidence) WorstFrame() uint64 { return e.worst.frame }

// WorstTime reports the time of the worst occurrence.
func (e *Evidence) WorstTime() time.Time { return e.worst.when }

// WorstValue reports the value of the worst occurrence.
func (e *Evidence) WorstValue() float64 { return e.worst.value }

// Frames returns up to MaxFrames representative frame numbers in ascending
// order, always including the first and worst occurrences.
func (e *Evidence) Frames() []uint64 {
	if !e.hasFirst {
		return nil
	}

	picked := make([]uint64, 0, MaxFrames+2)
	seen := make(map[uint64]bool, MaxFrames+2)
	add := func(f uint64) bool {
		if seen[f] {
			return true
		}
		if len(picked) >= MaxFrames {
			return false
		}
		seen[f] = true
		picked = append(picked, f)
		return true
	}

	// The first and worst occurrences are guaranteed slots; the samples fill
	// whatever is left.
	add(e.first.frame)
	if e.hasWorst {
		add(e.worst.frame)
	}
	for _, s := range e.samples {
		if !add(s.frame) {
			break
		}
	}

	sort.Slice(picked, func(i, j int) bool { return picked[i] < picked[j] })
	return picked
}
