package analysis

import (
	"fmt"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Capture-host drop accounting.
//
// Packets the capturing machine discarded before writing them look exactly like
// packets lost on the network. A capture that dropped one packet in fifty will
// make a loss rule report loss that never happened — confidently, with frame
// references — which is the expensive failure mode section 9 of the brief names.
//
// The reading and the significance gating stay here: they have to run before
// Population is built, since R05/R06/R08 consult the gating result while they
// detect. The reporting — turning these facts into the note a reader sees —
// moved to R15 (internal/rules/r15_capture_quality.go), which is what "R15
// takes ownership" means for this fact in particular. summariseDrops and
// dropQuality are the half that stays: reading the counters and deciding
// whether they're significant enough to gate on is capture-parsing and
// gating logic, not reporting.

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
