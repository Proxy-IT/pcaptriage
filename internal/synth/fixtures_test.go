package synth_test

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// update regenerates the committed fixtures and golden files instead of
// checking them:
//
//	go test ./... -update
var update = flag.Bool("update", false, "rewrite committed fixtures and golden files")

// Update reports whether the -update flag was given. The golden tests in other
// packages register their own flag; this one is the source of truth for the
// fixture files themselves.
func Update() bool { return *update }

// TestFixturesAreCommitted keeps the committed capture files and the code that
// builds them in step.
//
// The fixtures are generated, not captured, so they could just be built in
// memory at test time. They are committed anyway because a change to the
// builder that silently alters what a fixture represents would otherwise be
// invisible: the rule tests would keep passing against a different capture.
// This test turns that into a diff.
func TestFixturesAreCommitted(t *testing.T) {
	if *update {
		if err := os.MkdirAll(synth.FixtureDir(), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			b := f.Build()
			if b.Len() == 0 {
				t.Fatal("fixture produced no frames")
			}

			formats := map[string]func() ([]byte, error){
				"pcap":   b.Pcap,
				"pcapng": b.Pcapng,
			}
			for _, format := range []string{"pcap", "pcapng"} {
				got, err := formats[format]()
				if err != nil {
					t.Fatalf("render %s: %v", format, err)
				}

				path := synth.FixturePath(f.Name, format)
				if *update {
					if err := os.WriteFile(path, got, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}

				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v\nrun `go test ./... -update` to generate committed fixtures", err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("committed %s fixture differs from what the builder now produces (%d bytes committed, %d built)\n"+
						"if the change is intended, rerun with -update and review the diff", format, len(want), len(got))
				}
			}
		})
	}
}

// TestFixtureBuildIsDeterministic checks the builder itself before anything
// downstream relies on it.
func TestFixtureBuildIsDeterministic(t *testing.T) {
	for _, f := range synth.Fixtures() {
		t.Run(f.Name, func(t *testing.T) {
			first, err := f.Build().Pcap()
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 8; i++ {
				again, err := f.Build().Pcap()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(first, again) {
					t.Fatalf("build %d differs from build 0", i+1)
				}
			}
		})
	}
}
