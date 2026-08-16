package analysis_test

import (
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/findings"
)

// TestR01PacketEvidenceShowsTheContrast is the point of the packet view: a run
// of Win=0 frames does not explain itself. The window it collapsed from and the
// update that reopened it are what make it legible.
func TestR01PacketEvidenceShowsTheContrast(t *testing.T) {
	res := runFixture(t, "r01-zero-window-stall")

	got := findingsFor(res, "R01")
	if len(got) != 1 {
		t.Fatalf("want one R01 finding, got %d", len(got))
	}
	packets := got[0].Packets
	if len(packets) == 0 {
		t.Fatal("finding carries no packets, so the reader is given no evidence to look at")
	}

	var flagged, context int
	var sawZeroWindow, sawWindowUpdate, sawNonZeroBefore bool
	for _, p := range packets {
		switch p.Role {
		case findings.RoleFlagged:
			flagged++
			if p.Window != 0 {
				t.Errorf("frame %d is flagged by R01 but advertises Win=%d", p.Frame, p.Window)
			}
		case findings.RoleContext:
			context++
			if p.Window == 0 {
				t.Errorf("frame %d is context for R01 but also advertises a zero window", p.Frame)
			}
		default:
			t.Errorf("frame %d has no role", p.Frame)
		}
		for _, m := range p.Markers {
			if m == "TCP ZeroWindow" {
				sawZeroWindow = true
			}
			if m == "TCP Window Update" {
				sawWindowUpdate = true
			}
		}
	}

	if flagged == 0 {
		t.Error("no flagged packets")
	}
	if context < 2 {
		t.Errorf("got %d context packets, want the window before the stall and the update that ended it", context)
	}
	if !sawZeroWindow {
		t.Error("no packet carries the TCP ZeroWindow annotation Wireshark would show")
	}
	if !sawWindowUpdate {
		t.Error("the window update that ended the longest stall is not shown")
	}

	// The context frame preceding the stall must actually precede it.
	first := packets[0]
	if first.Role != findings.RoleContext {
		t.Errorf("the first row is %q; the reader should meet the healthy window first", first.Role)
	}
	if first.Window == 0 {
		t.Error("the opening context row does not show a non-zero window")
	}
	sawNonZeroBefore = first.Window > 0
	if !sawNonZeroBefore {
		t.Error("nothing establishes that the receiver was accepting data beforehand")
	}

	// Frames ascend, so the table reads in the order Wireshark shows them.
	for i := 1; i < len(packets); i++ {
		if packets[i-1].Frame >= packets[i].Frame {
			t.Fatalf("packets are not in frame order: %d then %d", packets[i-1].Frame, packets[i].Frame)
		}
	}

	// Every stall's recovery has to appear, not just the last one. Showing a
	// run of flagged frames with only a final window update after them reads as
	// one unbroken stall; the fixture has two, separated by a recovery.
	stalls := 0
	for i, p := range packets {
		if p.Role == findings.RoleFlagged && (i == 0 || packets[i-1].Role == findings.RoleContext) {
			stalls++
		}
	}
	updates := 0
	for _, p := range packets {
		for _, m := range p.Markers {
			if m == "TCP Window Update" {
				updates++
			}
		}
	}
	if updates < stalls {
		t.Errorf("%d stall runs are shown but only %d window updates; the table implies the stalls ran together", stalls, updates)
	}

	// Every row must explain its own part.
	for _, p := range packets {
		if strings.TrimSpace(p.Note) == "" {
			t.Errorf("frame %d has no note saying what it shows", p.Frame)
		}
	}
}

// TestR04PacketEvidenceShowsRequestAndResponse checks that the measurement is
// visible: the request, the response, and the gap between them.
func TestR04PacketEvidenceShowsRequestAndResponse(t *testing.T) {
	res := runFixture(t, "r04-server-response-outlier")

	got := findingsFor(res, "R04")
	if len(got) != 1 {
		t.Fatalf("want one R04 finding, got %d", len(got))
	}
	packets := got[0].Packets
	if len(packets) != 2 {
		t.Fatalf("want the request and the response, got %d packets", len(packets))
	}

	req, resp := packets[0], packets[1]
	if req.Role != findings.RoleContext {
		t.Errorf("first row role = %q, want context (the request)", req.Role)
	}
	if resp.Role != findings.RoleFlagged {
		t.Errorf("second row role = %q, want flagged (the response)", resp.Role)
	}
	if req.Frame >= resp.Frame {
		t.Errorf("the request (frame %d) does not precede the response (frame %d)", req.Frame, resp.Frame)
	}
	if req.PayloadLen == 0 || resp.PayloadLen == 0 {
		t.Error("both rows should carry data; a pure ACK is neither a request nor a response")
	}

	// The gap between the two rows is the thing the finding reports, so it has
	// to be the slowest exchange rather than an arbitrary one.
	gap := resp.Time.Sub(req.Time).Seconds()
	if gap < 4.0 {
		t.Errorf("gap between request and response is %.3fs; the finding reports a 4.1s maximum, so the slowest exchange was not the one kept", gap)
	}
	if !strings.Contains(resp.Note, "round trip") {
		t.Errorf("the response row does not explain the subtraction: %q", resp.Note)
	}
}

// TestPacketEvidenceCarriesNoPayload is the "no payload bytes in output"
// guarantee applied to the one feature most likely to breach it.
func TestPacketEvidenceCarriesNoPayload(t *testing.T) {
	for _, name := range []string{"r01-zero-window-stall", "r04-server-response-outlier", "mixed-findings"} {
		res := runFixture(t, name)
		for _, f := range res.Findings {
			for _, p := range f.Packets {
				// Payload length is a derived metric and is fine; the bytes
				// themselves must have no field to live in.
				if p.PayloadLen < 0 {
					t.Errorf("%s frame %d: negative payload length", name, p.Frame)
				}
				for _, s := range []string{p.Src, p.Dst, p.Info, p.Note, p.Flags, p.Protocol} {
					if strings.ContainsRune(s, 0x00) {
						t.Errorf("%s frame %d: raw bytes leaked into a text field", name, p.Frame)
					}
				}
			}
		}
	}
}

// TestPacketEvidenceIsBounded checks the repetition cap reaches the packet view
// too: a finding standing for thousands of events must not carry thousands of
// packet records.
func TestPacketEvidenceIsBounded(t *testing.T) {
	for _, name := range []string{"r01-zero-window-stall", "r01-brief-zero-windows", "mixed-findings"} {
		res := runFixture(t, name)
		for _, f := range res.Findings {
			// Up to MaxFrames flagged, plus a small number of context rows.
			if len(f.Packets) > findings.MaxFrames+5 {
				t.Errorf("%s: finding %q carries %d packets, beyond the cap",
					name, f.Title, len(f.Packets))
			}
		}
	}
}

// TestPacketEvidenceStaysOutOfTheReport pins the decision that the packet view
// is app-only for now. If it is ever surfaced in the JSON, the schema version
// has to move with it.
func TestPacketEvidenceStaysOutOfTheReport(t *testing.T) {
	got := renderFixture(t, "r01-zero-window-stall", "pcap")
	for _, banned := range []string{`"packets"`, `"rel_seconds"`, "TCP ZeroWindow"} {
		if strings.Contains(string(got), banned) {
			t.Errorf("the JSON report contains %q; packet evidence is app-only until the schema is bumped for it", banned)
		}
	}
}
