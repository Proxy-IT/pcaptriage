package analysis_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestOffloadIsJudgedAgainstTheNegotiatedMSS is the detection R13's
// degradation gate rests on.
//
// Two captures with identical traffic, differing only in whether the handshake
// advertised an MSS. The oversized segments are the same in both. Only the one
// that negotiated a maximum can be said to exceed it, and only that one
// produces the finding — because the claim is about what the connection agreed
// to, not about what a link probably carries.
func TestOffloadIsJudgedAgainstTheNegotiatedMSS(t *testing.T) {
	run := func(t *testing.T, withMSS bool) *analysis.Result {
		t.Helper()
		b := synth.New()
		c := b.NewConn(synth.ConnOpts{
			Client: "10.1.1.5:44100", Server: "10.2.2.7:443",
			ClientISN: 1000, ServerISN: 5000,
		})
		if withMSS {
			c.HandshakeWithOptions(0, 10*1000*1000, 1460, true)
		} else {
			c.Handshake(0, 10*1000*1000)
		}
		// A segment far larger than any Ethernet link carries, which is what
		// an endpoint capture shows before the NIC splits it.
		c.ServerData(50*1000*1000, 24000)
		c.ClientAck(60*1000*1000, 65535)
		c.FinClose(80*1000*1000, 5*1000*1000)

		data, err := b.Pcapng()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "offload.pcapng")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := analysis.Run(path, analysis.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("negotiated", func(t *testing.T) {
		res := run(t, true)
		if !res.Quality.OffloadArtifacts {
			t.Fatal("a 24000-byte segment on a connection that negotiated 1460 was not reported " +
				"as an offload artifact")
		}
		for _, want := range []string{"24,000", "1460", "before the sending interface split them"} {
			if !strings.Contains(res.Quality.OffloadBasis, want) {
				t.Errorf("the basis does not mention %q:\n  %s", want, res.Quality.OffloadBasis)
			}
		}
		var noted bool
		for _, n := range res.Notes {
			if n.RuleID == "R15" && strings.Contains(n.Text, "depends on segment size") {
				noted = true
			}
		}
		if !noted {
			t.Error("R15 emitted no note for the offload artifacts")
		}
	})

	t.Run("not negotiated", func(t *testing.T) {
		res := run(t, false)
		if res.Quality.OffloadArtifacts {
			t.Error("an offload artifact was claimed on a flow that never negotiated an MSS; " +
				"without the negotiation there is nothing the segment can be said to exceed")
		}
		for _, n := range res.Notes {
			if n.RuleID == "R15" && strings.Contains(n.Text, "depends on segment size") {
				t.Error("R15 noted offload artifacts with no negotiated maximum to compare against")
			}
		}
	})
}
