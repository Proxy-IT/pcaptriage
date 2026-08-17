package analysis_test

// The tshark cross-validation harness: Wireshark's dissector run over the
// committed fixtures as an independent oracle for the engine's counts.
//
// tshark is an oracle, never a dependency. When it is not installed the whole
// harness skips with a visible notice and the suite stays green — BRIEF §2's
// rejection of a Wireshark dependency stands. What the oracle buys, when
// present, is independence: the synthesizer and the parser are written by the
// same hands and could share a wrong assumption; Wireshark's reading of the
// same bytes is the check neither of them can provide for the other.
//
// Exact numeric agreement is not required everywhere. Wireshark's expert
// heuristics legitimately differ from the engine's detection-time rules — the
// engine deliberately suppresses sub-floor stalls that tshark flags packet by
// packet. Every such case is documented per fixture in the tables below, with
// the reason. An undocumented divergence is a test failure, in either
// direction: agreement loosened globally would hide exactly the drift this
// harness exists to catch.
//
// Out of the oracle's reach: pcapng Interface Statistics Block drop counts.
// Neither tshark's field extractor (ISB is file metadata, not a frame) nor
// capinfos 4.6 (no drop output at all — checked against its full option list)
// surfaces them, so kernel-drop reading has no independent CLI oracle. It is
// covered by the synth round-trip (the fixture writes a known count, the
// engine must read exactly that) — a consistency check, not independence, and
// recorded here as the known gap rather than silently absent.

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// zeroWindowDivergence documents every fixture where tshark's zero-window
// count and the engine's reported total legitimately differ, and why. A
// fixture not listed here must agree exactly: the engine's summed R01
// total_count equals tshark's tcp.analysis.zero_window frame count.
var zeroWindowDivergence = map[string]struct {
	Tshark uint64
	Engine uint64
	Reason string
}{
	// The R01 negative fixture. tshark flags every zero-window segment as it
	// dissects; the engine's R01 suppresses at detection time because the
	// stalls sit below the 100ms cumulative floor (RULES.md R01) and one flow
	// is midstream with its first observed window zero, which is not a
	// transition into stall. Nine flagged segments, zero findings, by design —
	// this is the detection-time floor, not a display floor.
	"r01-brief-zero-windows": {Tshark: 9, Engine: 0,
		Reason: "sub-floor stalls suppressed at detection time per RULES.md R01"},
}

// lossFlagExpectation documents fixtures expected to contain loss-analysis
// artifacts — retransmissions, duplicate ACKs, out-of-order segments — before
// the rules that detect them exist. Every current fixture must be loss-clean:
// none of them models loss, so a nonzero count here means the synthesizer is
// emitting loss artifacts by accident, and five rules are about to be built on
// top of that accident. When Batch 1's loss fixtures land, they enter this
// table with their intended counts and the comparison gains an engine side.
var lossFlagExpectation = map[string]tsharkLossCounts{
	// Empty: every fixture in the suite today is expected loss-clean.
}

// tsharkLossCounts is the loss-relevant subset of a scan.
type tsharkLossCounts struct {
	Retransmissions uint64
	FastRetrans     uint64
	DuplicateAcks   uint64
	OutOfOrder      uint64
}

// tsharkScan is one pass of the oracle over one capture file.
type tsharkScan struct {
	Frames     uint64
	TCPFrames  uint64
	ZeroWindow uint64
	Loss       tsharkLossCounts

	// FirstTime and LastTime are the min and max frame timestamps in epoch
	// seconds — min and max, not first and last in file order, because the
	// fixtures are appended by flow and are not strictly time-ordered.
	FirstTime float64
	LastTime  float64
}

// findTshark locates the oracle without requiring it.
//
// PATH first, then the platforms' default install locations — the Windows
// installer in particular does not add itself to PATH. PCAPTRIAGE_TSHARK
// overrides both for an unusual install.
func findTshark() string {
	if p := os.Getenv("PCAPTRIAGE_TSHARK"); p != "" {
		return p
	}
	if p, err := exec.LookPath("tshark"); err == nil {
		return p
	}
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = []string{
			`C:\Program Files\Wireshark\tshark.exe`,
			`C:\Program Files (x86)\Wireshark\tshark.exe`,
		}
	case "darwin":
		candidates = []string{
			"/Applications/Wireshark.app/Contents/MacOS/tshark",
			"/opt/homebrew/bin/tshark",
			"/usr/local/bin/tshark",
		}
	default:
		candidates = []string{"/usr/bin/tshark", "/usr/local/bin/tshark"}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// runTsharkScan reads every frame once, extracting the analysis flags as
// tab-separated fields. Flag fields print "1" when Wireshark's expert analysis
// set them and nothing otherwise; counting non-empty columns counts flagged
// frames. One invocation per file keeps the harness at seconds, not minutes.
func runTsharkScan(t *testing.T, tshark, path string) tsharkScan {
	t.Helper()

	cmd := exec.Command(tshark,
		"-r", path,
		"-n", // no name resolution: the no-network posture applies to tests too
		"-T", "fields",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "tcp.stream",
		"-e", "tcp.analysis.retransmission",
		"-e", "tcp.analysis.fast_retransmission",
		"-e", "tcp.analysis.duplicate_ack",
		"-e", "tcp.analysis.out_of_order",
		"-e", "tcp.analysis.zero_window",
	)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark failed on %s: %v\n%s", path, err, errb.String())
	}

	scan := tsharkScan{FirstTime: math.Inf(1), LastTime: math.Inf(-1)}
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		// Columns follow the -e order above.
		field := func(i int) string {
			if i < len(cols) {
				return cols[i]
			}
			return ""
		}

		scan.Frames++
		if ts, err := strconv.ParseFloat(field(1), 64); err == nil {
			scan.FirstTime = math.Min(scan.FirstTime, ts)
			scan.LastTime = math.Max(scan.LastTime, ts)
		}
		if field(2) != "" {
			scan.TCPFrames++
		}
		if field(3) != "" {
			scan.Loss.Retransmissions++
		}
		if field(4) != "" {
			scan.Loss.FastRetrans++
		}
		if field(5) != "" {
			scan.Loss.DuplicateAcks++
		}
		if field(6) != "" {
			scan.Loss.OutOfOrder++
		}
		if field(7) != "" {
			scan.ZeroWindow++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading tshark output: %v", err)
	}
	return scan
}

// TestTsharkCrossValidation runs the oracle over every committed fixture in
// both container formats and holds the engine's counts to it.
func TestTsharkCrossValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-validation skipped in -short mode")
	}
	tshark := findTshark()
	if tshark == "" {
		t.Skip("SKIPPED: tshark not found on PATH or in default install locations — " +
			"the cross-validation oracle needs a Wireshark install; the engine does not")
	}
	t.Logf("oracle: %s", tshark)

	for _, f := range synth.Fixtures() {
		for _, format := range []string{"pcap", "pcapng"} {
			t.Run(f.Name+"/"+format, func(t *testing.T) {
				path := synth.FixturePath(f.Name, format)
				scan := runTsharkScan(t, tshark, path)

				res, err := analysis.Run(path, analysis.Options{})
				if err != nil {
					t.Fatalf("engine failed on a fixture tshark read fine: %v", err)
				}

				// Frame accounting. These must agree exactly: both sides are
				// counting records in the same file, and the report promises
				// its frame numbers match Wireshark's for the same file.
				if scan.Frames != res.Capture.PacketsRead {
					t.Errorf("packets read: engine %d, tshark %d", res.Capture.PacketsRead, scan.Frames)
				}
				if scan.TCPFrames != res.Capture.PacketsTCP {
					t.Errorf("TCP packets: engine %d, tshark %d", res.Capture.PacketsTCP, scan.TCPFrames)
				}

				// The capture window. Both sides take min and max over all
				// frames; a mismatch beyond float formatting means one of
				// them is trusting file order.
				engineSpan := res.Capture.LastPacketTime.Sub(res.Capture.FirstPacketTime).Seconds()
				oracleSpan := scan.LastTime - scan.FirstTime
				if math.Abs(engineSpan-oracleSpan) > 0.001 {
					t.Errorf("capture span: engine %.3fs, tshark %.3fs", engineSpan, oracleSpan)
				}

				// Zero-window events: tshark's per-segment expert flag against
				// the engine's summed R01 occurrence counts, with the
				// documented detection-floor divergences excepted.
				var engineZW uint64
				for _, fd := range res.Findings {
					if fd.RuleID == "R01" {
						engineZW += fd.TotalCount
					}
				}
				if d, ok := zeroWindowDivergence[f.Name]; ok {
					if scan.ZeroWindow != d.Tshark || engineZW != d.Engine {
						t.Errorf("documented zero-window divergence drifted: tshark %d (documented %d), engine %d (documented %d) — reason on file: %s",
							scan.ZeroWindow, d.Tshark, engineZW, d.Engine, d.Reason)
					}
				} else if scan.ZeroWindow != engineZW {
					t.Errorf("zero-window events: engine reports %d, tshark flags %d — undocumented divergence",
						engineZW, scan.ZeroWindow)
				}

				// Loss-analysis flags. No loss rules are built yet, so every
				// fixture must be loss-clean unless the table above says
				// otherwise; an accidental retransmission in a fixture is a
				// synthesizer bug the loss rules would inherit.
				want := lossFlagExpectation[f.Name] // zero value: loss-clean
				if scan.Loss != want {
					t.Errorf("loss flags diverge from documented expectation:\n  tshark   %+v\n  expected %+v",
						scan.Loss, want)
				}
			})
		}
	}
}

// TestOracleNoticeWhenAbsent makes the skip visible in CI logs even when the
// suite is green: the harness reporting it did not run is part of its
// contract, so a machine without Wireshark cannot silently masquerade as a
// cross-validated one.
func TestOracleNoticeWhenAbsent(t *testing.T) {
	if p := findTshark(); p != "" {
		t.Logf("tshark present at %s; cross-validation ran", p)
		return
	}
	fmt.Fprintln(os.Stderr,
		"NOTICE: tshark not installed — engine counts were NOT cross-validated against Wireshark on this run")
}
