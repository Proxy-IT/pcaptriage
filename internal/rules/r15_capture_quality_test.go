package rules

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
)

// TestR15MetaDoesNotOverclaimCoverage holds the Summary to the same honesty
// standard as the home screen's registry-driven check list: it must not
// describe a condition (snaplen truncation, TSO, timestamp/multi-interface)
// this build does not actually detect.
func TestR15MetaDoesNotOverclaimCoverage(t *testing.T) {
	m := NewCaptureQualityRule().Meta()
	if m.ID != "R15" || m.Name != "capture-quality" {
		t.Fatalf("Meta = %+v", m)
	}
	for _, unbuilt := range []string{"snaplen", "TSO", "MTU", "timestamp resolution", "multi-interface"} {
		if strings.Contains(strings.ToLower(m.Summary), strings.ToLower(unbuilt)) {
			t.Errorf("Summary claims coverage of %q, which this build does not detect: %q", unbuilt, m.Summary)
		}
	}
	// It must still say what it does cover, or the summary is content-free.
	for _, built := range []string{"capture began", "one direction", "dropped", "headers"} {
		if !strings.Contains(m.Summary, built) {
			t.Errorf("Summary omits the covered condition %q: %q", built, m.Summary)
		}
	}
}

// TestR15NeverProducesAFinding is the "n/a base weight, always the banner,
// never the ranked list" requirement: whatever Emit writes goes to notes,
// never to the findings store.
func TestR15NeverProducesAFinding(t *testing.T) {
	pop := &Population{
		TCPFlows: 10, MidstreamFlows: 3, OneWayFlows: 2, FlowsEvicted: 5,
		PacketsRead: 1000, PacketsDropped: 50, DropRatio: 0.05,
		DropAvailability: capture.DropsReported,
		Quality:          CaptureQuality{KernelDropsSignificant: true, KernelDropBasis: "test basis"},
	}
	store := findings.NewStore()
	NewCaptureQualityRule().Emit(pop, store)
	store.Seal()

	if len(store.Findings()) != 0 {
		t.Errorf("R15 produced %d findings; RULES.md marks it a meta-rule with base weight n/a", len(store.Findings()))
	}
	if len(store.Notes()) == 0 {
		t.Error("R15 produced no notes at all, with drops, midstream and one-way flows all present")
	}
}

// TestR15WritesOneNotePerCondition checks that each condition present on the
// population produces exactly the note it should, tagged R15, and that a
// condition absent from the population produces no note at all — R15 must
// not manufacture a gap for something the capture didn't actually do.
func TestR15WritesOneNotePerCondition(t *testing.T) {
	pop := &Population{
		TCPFlows: 20, MidstreamFlows: 4, OneWayFlows: 1, FlowsEvicted: 7,
		PacketsRead: 500, DropAvailability: capture.DropsAbsent,
	}
	store := findings.NewStore()
	NewCaptureQualityRule().Emit(pop, store)
	store.Seal()

	notes := store.Notes()
	var sawDrop, sawMidstream, sawOneWay, sawEvicted bool
	for _, n := range notes {
		if n.RuleID != "R15" {
			t.Errorf("note %q is tagged %q, not R15", n.Text, n.RuleID)
		}
		switch {
		case strings.Contains(n.Text, "no interface statistics"):
			sawDrop = true
		case strings.Contains(n.Text, "receive window sizing"):
			sawMidstream = true
		case strings.Contains(n.Text, "comparing the two directions"):
			sawOneWay = true
		case strings.Contains(n.Text, "set aside before the capture ended"):
			sawEvicted = true
		}
	}
	for name, got := range map[string]bool{
		"drop (pcapng without statistics)": sawDrop,
		"midstream":                        sawMidstream,
		"one-way":                          sawOneWay,
		"evicted":                          sawEvicted,
	} {
		if !got {
			t.Errorf("expected a %s note, none was produced", name)
		}
	}

	// A population with none of the conditions should produce only the drop
	// note — always present — and nothing else.
	clean := &Population{TCPFlows: 5, DropAvailability: capture.DropsReported}
	store2 := findings.NewStore()
	NewCaptureQualityRule().Emit(clean, store2)
	store2.Seal()
	if len(store2.Notes()) != 1 {
		t.Errorf("a capture with no midstream, one-way or evicted flows produced %d notes, want 1 (drop only)",
			len(store2.Notes()))
	}
}

// TestR15DropNoteMatchesGatingFlag checks the note's own account of
// significance stays in step with the CaptureQuality flag R05/R06/R08 read —
// the two must never disagree about whether drops are significant.
func TestR15DropNoteMatchesGatingFlag(t *testing.T) {
	sig := &Population{
		TCPFlows: 5, PacketsRead: 100, PacketsDropped: 20, DropRatio: 0.2,
		DropAvailability: capture.DropsReported,
		Quality:          CaptureQuality{KernelDropsSignificant: true},
	}
	note := dropNote(sig)
	if note.Kind != "unavailable" {
		t.Errorf("significant drops produced kind %q, want unavailable", note.Kind)
	}
	if !strings.Contains(note.Text, "may be capture loss") {
		t.Errorf("the note does not say drops may explain apparent loss: %q", note.Text)
	}

	trivial := &Population{
		TCPFlows: 5, PacketsRead: 10000, PacketsDropped: 1, DropRatio: 0.0001,
		DropAvailability: capture.DropsReported,
		Quality:          CaptureQuality{KernelDropsSignificant: false},
	}
	note2 := dropNote(trivial)
	if note2.Kind != "info" {
		t.Errorf("trivial drops produced kind %q, want info", note2.Kind)
	}
	if strings.Contains(note2.Text, "may be capture loss") {
		t.Errorf("a trivial drop count was still described as potentially explaining loss: %q", note2.Text)
	}
}

// TestR15MalformedHeaderNoteSaysFindingsAreUnverified is the point of the
// whole check: when the header bytes cannot be believed, the reader has to be
// told before they act on findings derived from them.
//
// The wording is asserted rather than merely the note's presence. A note that
// mentions corruption but leaves the findings looking authoritative would pass
// a presence check while failing at the only thing it exists to do.
func TestR15MalformedHeaderNoteSaysFindingsAreUnverified(t *testing.T) {
	pop := &Population{
		TCPFlows: 10, PacketsRead: 1871, PacketsTCP: 1231, PacketsMalformed: 640,
		DropAvailability: capture.DropsUnsupported,
		Quality: CaptureQuality{
			HeadersUnreliable: true,
			HeaderBasis:       "640 of 1,871 frames carrying TCP (34%) declare a header length no sender could have written.",
		},
	}
	store := findings.NewStore()
	NewCaptureQualityRule().Emit(pop, store)
	store.Seal()

	var note string
	for _, n := range store.Notes() {
		if strings.Contains(n.Text, "header length no sender") {
			if n.Kind != "unavailable" {
				t.Errorf("note kind = %q, want %q: an info note does not count as a coverage gap, "+
					"so a corrupt capture would still qualify for a strong-coverage all-clear", n.Kind, n.Kind)
			}
			note = n.Text
		}
	}
	if note == "" {
		t.Fatal("no malformed-header note was written")
	}
	for _, required := range []string{"unverified", "Wireshark"} {
		if !strings.Contains(note, required) {
			t.Errorf("note omits %q, so it does not tell the reader what to do about it: %q", required, note)
		}
	}
}

// TestR15MalformedHeaderNoteAbsentWhenHeadersAreSound guards the other
// direction. A note that is always present says nothing.
func TestR15MalformedHeaderNoteAbsentWhenHeadersAreSound(t *testing.T) {
	pop := &Population{
		TCPFlows: 10, PacketsRead: 1000, PacketsTCP: 1000,
		DropAvailability: capture.DropsUnsupported,
	}
	store := findings.NewStore()
	NewCaptureQualityRule().Emit(pop, store)
	store.Seal()

	notes := store.Notes()
	if len(notes) == 0 {
		t.Fatal("R15 wrote no notes at all, so finding no malformed-header note proves nothing")
	}
	for _, n := range notes {
		if strings.Contains(n.Text, "header length no sender") {
			t.Errorf("malformed-header note written for a capture with no malformed frames: %q", n.Text)
		}
	}
}
