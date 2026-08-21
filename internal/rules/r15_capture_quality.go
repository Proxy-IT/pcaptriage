package rules

import (
	"fmt"
	"strings"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
)

// CaptureQualityRule implements the built subset of R15 · capture-quality.
//
// RULES.md's R15 condition list is broader than what this build detects:
// TSO/LRO segment-size artifacts and timestamp resolution / multi-interface
// merges are specified but not implemented —
// there is no tracking for any of them yet, so there is nothing to report.
// Meta.Summary below states only what this build actually covers, for the
// same reason the home screen's check list is registry-driven rather than
// hand-described: a summary claiming more than the code does is a stale
// promise the moment someone reads it. The remaining R15 conditions are
// tracked as follow-up detection work.
//
// What is covered: flows already open when the capture began (midstream),
// connections captured in one direction only, packets the capture host itself
// dropped before writing them, frames clipped by a capture size limit, and
// frames whose header length fields cannot be correct. This is ownership and structure, moved
// out of the engine and the report package where it lived ad hoc — every
// note below existed before this rule did; nothing here changes what a
// report says, only who is responsible for saying it.
//
// R15 never produces a ranked finding — RULES.md marks its base weight "n/a"
// and says its results belong in the completeness banner, not the findings
// list. Its Emit writes only Notes.
type CaptureQualityRule struct{}

// captureQualityAssessed and captureQualityUnassessed are what the report says
// this build's capture-quality assessment does and does not cover.
//
// They live here, beside the implementation, because the sentence they compose
// previously lived as a literal in the report template and was false for two
// releases: it named R15 as unimplemented while R15 shipped, and listed as
// unassessed several conditions the rule had begun detecting. A claim about
// what a rule covers has to sit next to the rule, so that adding a condition
// puts the claim in the same diff.
//
// RULES.md section R15 is the source of truth for the full condition list;
// these two slices are this build's split of it.
var (
	captureQualityAssessed = []string{
		"snaplen truncation",
		"the proportion of flows that began before the capture started",
		"segments larger than the MTU (an on-host capture with offload enabled)",
		"flows seen in one direction only",
	}
	captureQualityUnassessed = []string{
		"Timestamp resolution",
		"multi-interface merges",
	}
)

// CaptureQualityDisclosure is the completeness banner's opening sentence.
//
// It states coverage in both directions — what was assessed and what was not —
// because naming only the first would let silence read as an all-clear, which
// is the failure this rule exists to prevent.
func CaptureQualityDisclosure() string {
	return fmt.Sprintf(
		"The capture-quality assessment covers %s. %s are not yet assessed. "+
			"These figures describe what was read, not a verdict on whether the capture was adequate.",
		joinOxford(captureQualityAssessed), joinAnd(captureQualityUnassessed))
}

// joinOxford renders a list with a serial comma: "a, b, and c".
func joinOxford(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
}

// joinAnd renders a short list without a serial comma: "a and b".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// NewCaptureQualityRule returns the R15 detector.
func NewCaptureQualityRule() *CaptureQualityRule { return &CaptureQualityRule{} }

// Meta describes the built subset of R15.
func (r *CaptureQualityRule) Meta() Meta {
	return Meta{
		ID:   "R15",
		Name: "capture-quality",
		// n/a per RULES.md: R15 always runs and never competes for rank.
		BaseWeight: 0,
		Summary: "Reports what the capture itself may limit: flows already open when the capture began, " +
			"connections seen in one direction only, packets the capture host dropped before writing them, " +
			"frames clipped by a snaplen, and headers too damaged to be believed.",
	}
}

// NewFlow, OnPacket and OnFlowEnd are no-ops: everything R15 reports on is
// already computed by the engine's own bookkeeping (flow completeness,
// one-way detection, interface drop counters) before any detector's Emit
// runs, and carried in on Population.
func (r *CaptureQualityRule) NewFlow() any                                               { return nil }
func (r *CaptureQualityRule) OnPacket(any, *flow.State, *capture.Packet, flow.Direction) {}
func (r *CaptureQualityRule) OnFlowEnd(any, *flow.State)                                 {}

// Emit writes the capture-quality notes. There is always a drop note — "the
// host recorded nothing dropped" and "the file cannot say" are both
// statements worth making — and a midstream, one-way or eviction note
// wherever that condition affects any flow.
func (r *CaptureQualityRule) Emit(pop *Population, out *findings.Store) {
	out.AddNote(dropNote(pop))
	out.AddNote(snaplenNote(pop))

	// Flows already established when the capture began. Their window scale
	// factor was never negotiated in view, so anything sized in bytes is
	// unavailable for them — while zero-window detection, which does not
	// depend on the scale factor, is not affected.
	if pop.MidstreamFlows > 0 && pop.TCPFlows > 0 {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: fmt.Sprintf(
				"Not assessed: receive window sizing. %d of %d flows (%s) began before the capture started, "+
					"so the window scale factor for them is unknown. Zero-window detection does not depend on it "+
					"and was performed on every flow.",
				pop.MidstreamFlows, pop.TCPFlows, formatShare(pop.MidstreamFlows, pop.TCPFlows)),
		})
	}

	// Only one direction captured. Anything that compares the two directions
	// has nothing to compare, which is a common consequence of a one-way SPAN
	// configuration rather than anything wrong with the network.
	if pop.OneWayFlows > 0 {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: fmt.Sprintf(
				"Not assessed: anything comparing the two directions of a conversation. "+
					"%d of %d flows were captured in one direction only, which usually means the capture point "+
					"saw traffic going one way. Loss direction analysis is unavailable for those.",
				pop.OneWayFlows, pop.TCPFlows),
		})
	}

	// Segments larger than the connection negotiated. Conditional, unlike the
	// drop note: "no oversized segments were seen" carries none of the
	// ambiguity "the file cannot record drops" does, so there is nothing to
	// say when the condition is absent.
	if pop.Quality.OffloadArtifacts {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: "Partly assessed: anything that depends on segment size. " +
				pop.Quality.OffloadBasis +
				" Loss and retransmission analysis still ran; size-based conclusions on these flows are the ones to treat carefully.",
		})
	}

	// Header bytes that are not what the sender wrote. Placed after the gaps
	// above and before the eviction note because it is the one condition here
	// that bears on whether the findings themselves mean anything, rather than
	// on which checks could run.
	if pop.Quality.HeadersUnreliable {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: "Not assessed: anything read from a TCP header in this capture. " +
				pop.Quality.HeaderBasis +
				" Findings below were derived from those headers and should be treated as unverified — " +
				"the frame numbers are real and can be opened in Wireshark, but the conditions reported " +
				"may be artifacts of the corruption rather than events on the network. A capture taken " +
				"at a different point, or exported by different means, would settle it.",
		})
	}

	// Flows discarded mid-run because the concurrency cap was reached: those
	// were analysed only up to the point they were dropped. Not one of
	// RULES.md's R15 conditions — it is a tool limit, not a capture-file
	// fact — but tagged R15 since before this rule existed, and moved here
	// rather than left as the one gap synthesised outside the store.
	if pop.FlowsEvicted > 0 {
		out.AddNote(findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: fmt.Sprintf(
				"Partly assessed: %s of %s flows were set aside before the capture ended, because more "+
					"conversations were open at once than this run tracks. Those flows were examined only up to "+
					"that point.",
				formatCount(pop.FlowsEvicted), formatCount(uint64(pop.TCPFlows))),
		})
	}
}

// snaplenNote is what the completeness reporting says about frames arriving
// shorter than they were on the wire.
//
// Always present, for the same reason the drop note is: "nothing was clipped"
// and "the file declares no limit" are different statements about different
// files, and neither is silence. Which one applies is decided by what was
// observed in the frames, not by the declared figure — a file can declare a
// snap length and clip nothing, and RULES.md's own banner example reports
// exactly that case ("Snaplen 262144 (untruncated)").
//
// The zero case is the one to be careful with. A classic pcap has to spell "no
// truncation limit" as zero, so a file declaring zero is the *least* truncated
// kind there is. Reading it as a zero-byte cap would invert the meaning
// completely, which is why the declared figure never decides this on its own.
func snaplenNote(pop *Population) findings.Note {
	if pop.PacketsClipped == 0 {
		if !pop.SnaplenKnown {
			return findings.Note{
				Kind:   "info",
				RuleID: "R15",
				Text: "This file declares no capture size limit, and no frame in it arrived shorter than " +
					"it was on the wire. Every packet was recorded in full.",
			}
		}
		return findings.Note{
			Kind:   "info",
			RuleID: "R15",
			Text: fmt.Sprintf(
				"This file declares a capture size limit of %s bytes per frame, and no frame reached it — "+
					"nothing was clipped. Every packet was recorded in full.",
				formatCount(uint64(pop.Snaplen))),
		}
	}

	limit := "The file declares no capture size limit, so the clipping was applied by whatever wrote it."
	if pop.SnaplenKnown {
		limit = fmt.Sprintf("The file declares a capture size limit of %s bytes per frame.",
			formatCount(uint64(pop.Snaplen)))
	}

	return findings.Note{
		Kind:   "unavailable",
		RuleID: "R15",
		Text: fmt.Sprintf(
			"Partly assessed: anything that reads inside a packet rather than its headers. "+
				"%s of %s frames (%s) arrived shorter than they were on the wire. %s "+
				"What survived the clipping was analysed normally; name lookups and encrypted "+
				"handshakes are the checks most likely to have been cut short, and say so "+
				"themselves where they were.",
			formatCount(pop.PacketsClipped),
			formatCount(pop.PacketsRead),
			formatShare(int(pop.PacketsClipped), int(pop.PacketsRead)),
			limit),
	}
}

// dropNote is what the completeness reporting says about capture-host drops.
//
// There is always something to say. "The file records no drops" and "the file
// cannot record drops" are different statements, and only one of them is
// reassuring — reporting silence as the former is the false all-clear.
func dropNote(pop *Population) findings.Note {
	switch pop.DropAvailability {
	case capture.DropsUnsupported:
		return findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: "Not assessed: whether the capture host dropped packets before writing them. " +
				"The classic pcap format has no field to record it, so this file cannot say either way. " +
				"Packets dropped by the capturing machine look the same as packets lost on the network. " +
				"If that distinction matters here, re-capturing in pcapng format would record the count.",
		}

	case capture.DropsAbsent:
		return findings.Note{
			Kind:   "unavailable",
			RuleID: "R15",
			Text: "Not assessed: whether the capture host dropped packets before writing them. " +
				"This pcapng file carries no interface statistics, which is where that count is kept. " +
				"Captures written by tcpdump or dumpcap normally include it.",
		}
	}

	if pop.PacketsDropped == 0 {
		// Scoped to the capture host deliberately. Its own counter says nothing
		// about a SPAN port or tap upstream of it, so "no loss at the capture
		// point" would claim more than this number can support.
		return findings.Note{
			Kind:   "info",
			RuleID: "R15",
			Text: "The capture host reported dropping no packets, so this file contains everything that reached it. " +
				"Any packet loss reported here was not introduced by the capture host itself.",
		}
	}

	text := fmt.Sprintf(
		"The capture host dropped %s of %s packets (%s) before writing them, on %s. ",
		formatCount(pop.PacketsDropped),
		formatCount(pop.PacketsRead+pop.PacketsDropped),
		formatDropRatio(pop.DropRatio),
		describeDropInterfaces(pop.InterfaceDrops))

	if pop.Quality.KernelDropsSignificant {
		text += "Packets dropped by the capturing machine are indistinguishable from packets lost on the network, " +
			"so some apparent loss in this capture may be capture loss rather than loss on the wire. " +
			"If the fault is reproducible, re-capturing with a larger capture buffer, or on a less busy host, " +
			"would remove the ambiguity."
		return findings.Note{Kind: "unavailable", RuleID: "R15", Text: text}
	}

	text += "That is a small enough share that it is unlikely to account for any loss reported below, " +
		"but it is worth knowing the capture is not quite complete."
	return findings.Note{Kind: "info", RuleID: "R15", Text: text}
}

// describeDropInterfaces names where the drops happened.
func describeDropInterfaces(drops []capture.InterfaceDrops) string {
	var named []capture.InterfaceDrops
	for _, d := range drops {
		if d.Dropped > 0 {
			named = append(named, d)
		}
	}
	switch len(named) {
	case 0:
		return "the capture interface"
	case 1:
		return "capture interface " + interfaceLabel(named[0])
	}

	out := "capture interfaces "
	for i, d := range named {
		switch {
		case i == len(named)-1:
			out += " and " + interfaceLabel(d)
		case i > 0:
			out += ", " + interfaceLabel(d)
		default:
			out += interfaceLabel(d)
		}
	}
	return out
}

func interfaceLabel(d capture.InterfaceDrops) string {
	if d.Name != "" {
		return d.Name
	}
	return fmt.Sprintf("#%d", d.ID)
}

// formatDropRatio renders a ratio with enough precision to stay honest at
// small values — "0.0%" would read as none at all. Distinct from
// formatPercent in format.go, which serves the loss rules' wording and uses a
// coarser precision; this is R15's own, moved verbatim from where drop
// reporting used to live.
func formatDropRatio(ratio float64) string {
	pct := ratio * 100
	switch {
	case pct <= 0:
		return "0%"
	case pct < 0.01:
		return "under 0.01%"
	case pct < 1:
		return fmt.Sprintf("%.2f%%", pct)
	case pct < 10:
		return fmt.Sprintf("%.1f%%", pct)
	}
	return fmt.Sprintf("%.0f%%", pct)
}

// formatShare renders part of whole as a percentage, never rounding a real
// proportion down to nothing. Moved verbatim from the report package, where
// the midstream gap text used to be assembled.
func formatShare(part, whole int) string {
	if whole <= 0 {
		return "0%"
	}
	pct := float64(part) * 100 / float64(whole)
	if pct > 0 && pct < 1 {
		return "under 1%"
	}
	return fmt.Sprintf("%.0f%%", pct)
}

// formatCount renders a count with thousands separators. Moved verbatim from
// the analysis package, where the drop note used to be assembled.
func formatCount(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}
