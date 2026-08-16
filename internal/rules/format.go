package rules

import (
	"fmt"
	"math"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/findings"
)

// formatDuration renders a duration the way RULES.md's example wordings do:
// whole milliseconds below one second ("40ms", "340ms"), one decimal place of
// seconds at or above one ("1.8s", "4.2s").
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Round(time.Millisecond)/time.Millisecond)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// formatDurationCeil renders a duration rounded up to the next readable
// figure, for wordings of the form "the other 41 servers are under 40ms".
//
// The rounding is strictly upward — a value of exactly 40ms renders as 50ms —
// because the wording is an upper bound and "under 40ms" has to remain true of
// a peer sitting exactly on 40ms.
func formatDurationCeil(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Second {
		step := 10 * time.Millisecond
		return fmt.Sprintf("%dms", (d/step+1)*step/time.Millisecond)
	}
	secs := math.Floor(d.Seconds()*10)/10 + 0.1
	return fmt.Sprintf("%.1fs", secs)
}

// plural returns "" for one and "s" otherwise.
func plural(n uint64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// pluralInt is plural for signed counts.
func pluralInt(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// millis converts a duration to whole milliseconds for the metrics block,
// where a stable integer is preferable to a float.
func millis(d time.Duration) int64 {
	return int64(d.Round(time.Millisecond) / time.Millisecond)
}

// round3 rounds a float to three decimal places so metric values are stable
// and readable in golden files.
func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}

// finalisePackets completes a finding's packet list: the offset from the start
// of the capture, which is the clock Wireshark's time column shows, and the
// one-line summary in the shape its info column uses.
//
// Both are done here rather than at capture time because neither is settled
// until the run is over.
func finalisePackets(refs []findings.PacketRef, captureStart time.Time) []findings.PacketRef {
	if len(refs) == 0 {
		return nil
	}
	out := append([]findings.PacketRef(nil), refs...)
	findings.SetRelativeTimes(out, captureStart)
	for i := range out {
		out[i].Info = out[i].Summary()
	}
	return out
}
