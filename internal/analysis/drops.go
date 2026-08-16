package analysis

import (
	"fmt"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Capture-host drop accounting.
//
// Packets the capturing machine discarded before writing them look exactly like
// packets lost on the network. A capture that dropped one packet in fifty will
// make a loss rule report loss that never happened — confidently, with frame
// references — which is the expensive failure mode section 9 of the brief names.
//
// This is R15 territory. R15 is not implemented, so the reading and reporting
// live in the engine alongside the other capture-quality facts already gathered
// here (snaplen, midstream proportion, one-way flows). When R15 lands it should
// take ownership of all of them together rather than this one moving alone.

// summariseDrops folds the reader's drop counters into the capture info.
func summariseDrops(info *CaptureInfo, drops []capture.InterfaceDrops, availability capture.DropAvailability) {
	info.DropAvailability = availability
	info.InterfaceDrops = drops

	var total uint64
	for _, d := range drops {
		total += d.Dropped
	}
	info.PacketsDropped = total

	// Measured against what the file would have contained had nothing been
	// dropped, so the figure means "share of traffic that never reached the
	// file" rather than "drops per packet that did".
	if denom := info.PacketsRead + total; denom > 0 && total > 0 {
		info.DropRatio = float64(total) / float64(denom)
	}
	info.DropsSignificant = total > 0 && info.DropRatio >= rules.Thresholds.R15KernelDropRatio
}

// dropQuality builds the gating flags rules consult.
//
// The basis sentence is written here, once, so that every rule that degrades
// for this reason gives the same account of why.
func dropQuality(info *CaptureInfo) rules.CaptureQuality {
	if !info.DropsSignificant {
		return rules.CaptureQuality{}
	}
	return rules.CaptureQuality{
		KernelDropsSignificant: true,
		KernelDropBasis: fmt.Sprintf(
			"The capture host itself dropped %s of %s packets (%s of the traffic it saw), so some apparent loss may be capture loss rather than loss on the network.",
			formatCount(info.PacketsDropped),
			formatCount(info.PacketsRead+info.PacketsDropped),
			formatPercent(info.DropRatio)),
	}
}

// dropNote is what the completeness reporting says about capture-host drops.
//
// There is always something to say. "The file records no drops" and "the file
// cannot record drops" are different statements, and only one of them is
// reassuring — reporting silence as the former is the false all-clear.
func dropNote(info *CaptureInfo) findings.Note {
	switch info.DropAvailability {
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

	if info.PacketsDropped == 0 {
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
		formatCount(info.PacketsDropped),
		formatCount(info.PacketsRead+info.PacketsDropped),
		formatPercent(info.DropRatio),
		describeDropInterfaces(info.InterfaceDrops))

	if info.DropsSignificant {
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

// formatPercent renders a ratio with enough precision to stay honest at small
// values — "0.0%" would read as none at all.
func formatPercent(ratio float64) string {
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

// formatCount renders a count with thousands separators.
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
