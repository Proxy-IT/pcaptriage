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

// lossExpectation pins both sides of the loss comparison for one fixture:
// what Wireshark's expert analysis flags, and what the engine's classifier
// reports through its findings. Drift on either side fails.
type lossExpectation struct {
	Tshark tsharkLossCounts
	// EngineRTO, EngineFast, EngineReorder and EngineAsymmetric are the
	// counts the engine's R05, R06, R07 and R08 findings carry for this
	// fixture.
	EngineRTO        uint64
	EngineFast       uint64
	EngineReorder    uint64
	EngineAsymmetric uint64
	Reason           string
}

// lossFlagExpectation documents every fixture expected to contain
// loss-analysis artifacts. A fixture not listed here must be loss-clean on
// both sides: an accidental retransmission in a fixture that does not model
// one is a synthesizer bug the loss rules would inherit.
var lossFlagExpectation = map[string]lossExpectation{
	"r05-rto-burst": {
		Tshark:    tsharkLossCounts{Retransmissions: 3},
		EngineRTO: 3,
		Reason:    "three timer expiries across two episodes; engine and Wireshark agree exactly",
	},
	"r06-fast-retransmit": {
		Tshark:     tsharkLossCounts{Retransmissions: 2, FastRetrans: 2, DuplicateAcks: 6},
		EngineFast: 2,
		Reason: "Wireshark sets both the retransmission and fast_retransmission bits on the " +
			"same two frames the engine classifies as fast recovery; the six duplicate ACKs " +
			"are the two three-deep trigger runs",
	},
	"r07-reordering": {
		Tshark:        tsharkLossCounts{Retransmissions: 1, FastRetrans: 1, DuplicateAcks: 3, OutOfOrder: 4},
		EngineReorder: 5,
		Reason: "the deliberate divergence: Wireshark reads the reordered segment arriving " +
			"under a duplicate-ACK run as a fast retransmission, while the engine's IP ID " +
			"ordering check shows it was sent before the data that overtook it and " +
			"reclassifies it — the exact misread R07 exists to prevent. The other four " +
			"swaps agree as out-of-order",
	},
	"r07-reordering-v6": {
		Tshark:        tsharkLossCounts{OutOfOrder: 3},
		EngineReorder: 3,
		Reason: "IPv6 reordering with no duplicate-ACK runs: both sides classify all three " +
			"swaps as out-of-order on timing; the engine additionally lowers its confidence " +
			"to inferred because no IP ID exists to confirm original order",
	},
	"r08-asymmetric-loss": {
		Tshark:           tsharkLossCounts{Retransmissions: 24},
		EngineRTO:        22,
		EngineAsymmetric: 22,
		Reason: "24 timer-driven retransmissions total (22 forward, 2 reverse); R05 reports the " +
			"worse direction's 22 as its own finding and R08 reports the same 22 again as the " +
			"asymmetric-loss finding — the two rules answer different questions about the same " +
			"segments and are not mutually suppressing",
	},
	"r08-one-way": {
		Tshark:    tsharkLossCounts{Retransmissions: 3},
		EngineRTO: 3,
		Reason: "three timer-driven retransmissions on the only direction this capture point saw; " +
			"R05 reports them as an ordinary finding, R08 reports none — the comparison it makes " +
			"needs a reverse direction that was never captured, disclosed as an unavailable note " +
			"rather than silence",
	},

	// Batch 2's connection fixtures. A retried opening request is a
	// retransmission by Wireshark's definition — same sequence number, sent
	// again — and the oracle counts every one. The engine's loss classifier
	// deliberately does not: it skips segments carrying no data and every SYN,
	// because a connection attempt that is retried is R02's subject, and
	// counting the same retries again as packet loss would report one event
	// twice under two different names. The engine side of these entries is
	// zero for that reason, not because the retries went unnoticed — R02's
	// own counts, pinned in handshakeFixtures, are where they are accounted
	// for.
	"r02-syn-unanswered": {
		Tshark: tsharkLossCounts{Retransmissions: 4},
		Reason: "four retried opening requests, counted as retransmissions by the oracle and as R02 " +
			"attempts by the engine — the same four frames, under the name each tool uses for them",
	},
	"r02-syn-answered": {
		Tshark: tsharkLossCounts{Retransmissions: 1},
		Reason: "one retried opening request, on the flow that was answered on its second attempt",
	},
	"r02-capture-truncated": {
		Tshark: tsharkLossCounts{Retransmissions: 1},
		Reason: "one retried opening request, on the attempt the engine declines to report because the " +
			"capture ended before the window closed",
	},
}

// handshakeExpectation pins both sides of the connection-lifecycle
// comparison, added for Batch 2's R02 and R03.
//
// The oracle counts flags; the engine counts conclusions. The gap between
// them is the point: Wireshark can say "six opening requests and one
// acceptance", but only the engine says which unanswered attempt was silence
// worth reporting and which was a capture that stopped watching. Where those
// two numbers legitimately differ, the reason is recorded here.
type handshakeExpectation struct {
	Tshark tsharkHandshake
	// EngineUnanswered and EngineRefused are the totals the engine's R02 and
	// R03 findings carry for this fixture.
	EngineUnanswered uint64
	EngineRefused    uint64
	Reason           string
}

// handshakeFixtures pins the fixtures built to exercise R02 and R03. Other
// fixtures are covered by the arithmetic invariants in the test body, which
// hold for every capture without hand-entered numbers.
var handshakeFixtures = map[string]handshakeExpectation{
	"r02-syn-unanswered": {
		Tshark:           tsharkHandshake{SYNs: 11, SYNACKs: 6},
		EngineUnanswered: 5,
		Reason: "eleven opening requests: five unanswered retries on one flow, plus one each from the " +
			"six flows that were answered — which is what the six acceptances account for",
	},
	"r02-syn-answered": {
		Tshark: tsharkHandshake{SYNs: 7, SYNACKs: 6},
		Reason: "seven requests for six connections — one flow retried once before being answered — and " +
			"every one of them was accepted, so nothing went unanswered",
	},
	"r02-capture-truncated": {
		Tshark: tsharkHandshake{SYNs: 6, SYNACKs: 4},
		Reason: "the deliberate divergence: two of the six requests were never answered in this file, and " +
			"Wireshark can see that much, but both landed inside the capture-end window. The engine " +
			"declines to call that silence, because the capture stopped watching rather than the " +
			"reply failing to arrive — RULES.md's suppression, visible here as engine 0 against " +
			"an oracle that counts two",
	},
	"r03-syn-rejected": {
		Tshark:        tsharkHandshake{SYNs: 10, SYNACKs: 1, Resets: 9},
		EngineRefused: 9,
		Reason:        "nine refused attempts and one accepted connection to the same host; engine and oracle agree exactly",
	},
	"r03-syn-accepted": {
		Tshark: tsharkHandshake{SYNs: 6, SYNACKs: 6, Resets: 1},
		Reason: "the second deliberate divergence: the oracle counts one reset, the engine reports no " +
			"refusals. That reset closed a connection that had already completed its transfer — a " +
			"way of closing, not a way of refusing — and reading it as a refusal is exactly the " +
			"mistake this fixture exists to catch",
	},
	"r03-forged-reset": {
		Tshark:        tsharkHandshake{SYNs: 6, SYNACKs: 1, Resets: 5},
		EngineRefused: 5,
		Reason: "five refusals plus one established connection, whose traffic supplies the TTL baseline " +
			"the refusals are compared against; counts agree, and the engine additionally degrades " +
			"the finding to inferred because those TTLs disagree",
	},
}

// tsharkLossCounts is the loss-relevant subset of a scan.
type tsharkLossCounts struct {
	Retransmissions uint64
	FastRetrans     uint64
	DuplicateAcks   uint64
	OutOfOrder      uint64
}

// tsharkHandshake is the connection-lifecycle subset of a scan, added for
// Batch 2's R02 and R03. Wireshark has no "this attempt went unanswered"
// expert flag — silence is not an event it can mark — so the oracle counts
// the raw flags instead and the arithmetic between them is what corroborates
// the engine: opening requests, acceptances, and refusals.
type tsharkHandshake struct {
	// SYNs counts bare opening requests, retries included.
	SYNs uint64
	// SYNACKs counts acceptances.
	SYNACKs uint64
	// Resets counts every RST, whether it refused an attempt or ended an
	// established connection — telling those apart is the engine's job, and
	// the split is asserted through the engine side of the comparison.
	Resets uint64
}

// tsharkScan is one pass of the oracle over one capture file.
type tsharkScan struct {
	Frames     uint64
	TCPFrames  uint64
	ZeroWindow uint64
	Loss       tsharkLossCounts
	Handshake  tsharkHandshake

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
		// Raw flag bits for the handshake-outcome comparison. Field 8.
		"-e", "tcp.flags",
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
		// tcp.flags arrives as a hex string ("0x0002"). The three bits this
		// harness reads are SYN (0x02), ACK (0x10) and RST (0x04).
		if raw := field(8); raw != "" {
			if flags, err := strconv.ParseUint(strings.TrimPrefix(raw, "0x"), 16, 32); err == nil {
				syn, ack, rst := flags&0x02 != 0, flags&0x10 != 0, flags&0x04 != 0
				switch {
				case rst:
					scan.Handshake.Resets++
				case syn && ack:
					scan.Handshake.SYNACKs++
				case syn:
					scan.Handshake.SYNs++
				}
			}
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

				// Loss-analysis flags, both sides. The oracle's counts and the
				// engine's are each pinned per fixture; a fixture not in the
				// table must be loss-clean on both.
				want := lossFlagExpectation[f.Name] // zero value: loss-clean
				if scan.Loss != want.Tshark {
					t.Errorf("tshark loss flags diverge from documented expectation:\n  tshark   %+v\n  expected %+v\n  reason on file: %s",
						scan.Loss, want.Tshark, want.Reason)
				}
				var engRTO, engFast, engReorder, engAsym uint64
				for _, fd := range res.Findings {
					switch fd.RuleID {
					case "R05":
						engRTO += fd.TotalCount
					case "R06":
						engFast += fd.TotalCount
					case "R07":
						engReorder += fd.TotalCount
					case "R08":
						engAsym += fd.TotalCount
					}
				}
				if engRTO != want.EngineRTO || engFast != want.EngineFast ||
					engReorder != want.EngineReorder || engAsym != want.EngineAsymmetric {
					t.Errorf("engine loss classification diverges from documented expectation:\n"+
						"  engine   rto=%d fast=%d reorder=%d asymmetric=%d\n"+
						"  expected rto=%d fast=%d reorder=%d asymmetric=%d\n  reason on file: %s",
						engRTO, engFast, engReorder, engAsym,
						want.EngineRTO, want.EngineFast, want.EngineReorder, want.EngineAsymmetric, want.Reason)
				}

				// Connection lifecycle, both sides.
				var engUnanswered, engRefused uint64
				for _, fd := range res.Findings {
					switch fd.RuleID {
					case "R02":
						engUnanswered += fd.TotalCount
					case "R03":
						engRefused += fd.TotalCount
					}
				}

				// Invariants that hold for every capture, no hand-entered
				// numbers required: a refusal is always a reset and an
				// unanswered attempt is always an opening request, so the
				// engine can never claim more of either than exist on the
				// wire. Cheap, and they catch the counting bugs a pinned
				// table would only catch on the fixtures it covers.
				if engRefused > scan.Handshake.Resets {
					t.Errorf("engine reports %d refusals but the capture holds only %d resets — "+
						"every refusal is a reset, so this count cannot exceed it",
						engRefused, scan.Handshake.Resets)
				}
				if engUnanswered > scan.Handshake.SYNs {
					t.Errorf("engine reports %d unanswered attempts but the capture holds only %d opening requests",
						engUnanswered, scan.Handshake.SYNs)
				}

				hs, pinned := handshakeFixtures[f.Name]
				if !pinned {
					return
				}
				if scan.Handshake != hs.Tshark {
					t.Errorf("tshark handshake flags diverge from documented expectation:\n"+
						"  tshark   %+v\n  expected %+v\n  reason on file: %s",
						scan.Handshake, hs.Tshark, hs.Reason)
				}
				if engUnanswered != hs.EngineUnanswered || engRefused != hs.EngineRefused {
					t.Errorf("engine handshake classification diverges from documented expectation:\n"+
						"  engine   unanswered=%d refused=%d\n  expected unanswered=%d refused=%d\n  reason on file: %s",
						engUnanswered, engRefused, hs.EngineUnanswered, hs.EngineRefused, hs.Reason)
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
