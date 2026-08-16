package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestExitCodes records what the development harness currently does.
//
// This is **not** a compatibility contract and nothing may depend on it. The
// CLI is an in-repo development tool, not a shipped product, and BRIEF.md
// section 13 explicitly withdrew the exit-code commitment. If a change to the
// tool makes different codes more convenient, change them and update this test
// — it exists to make such a change visible, not to prevent it.
//
// It is kept rather than deleted because it still catches something worth
// catching: a capture the tool cannot read silently starting to exit zero would
// make a fixture script look like it passed.
func TestExitCodes(t *testing.T) {
	dir := t.TempDir()

	notACapture := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notACapture, []byte("this is not a capture file"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "success",
			args: []string{synth.FixturePath("mixed-findings", "pcap"), "--json", filepath.Join(dir, "out.json")},
			want: exitOK,
		},
		{
			name: "capture unreadable",
			args: []string{notACapture, "--json", filepath.Join(dir, "a.json")},
			want: exitCaptureUnusable,
		},
		{
			name: "capture missing",
			args: []string{filepath.Join(dir, "absent.pcap"), "--json", filepath.Join(dir, "b.json")},
			want: exitCaptureUnusable,
		},
		{
			name: "no input given",
			args: nil,
			want: exitToolError,
		},
		{
			name: "too many inputs",
			args: []string{"a.pcap", "b.pcap"},
			want: exitToolError,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := run(c.args); got != c.want {
				t.Errorf("exit code = %d, want %d", got, c.want)
			}
		})
	}
}

// TestRefusesToWriteOverInput is the read-only guarantee at the command line.
// Captures are frequently incident evidence, so the tool refuses before doing
// any work rather than discovering the collision at write time.
func TestRefusesToWriteOverInput(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(synth.FixturePath("r01-zero-window-stall", "pcap"))
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "evidence.pcap")
	if err := os.WriteFile(input, src, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := run([]string{input, "--json", input}); got != exitToolError {
		t.Errorf("exit code = %d, want %d", got, exitToolError)
	}

	after, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(src) {
		t.Fatalf("input capture was overwritten: %d bytes, was %d", len(after), len(src))
	}

	// The same file reached by a different path must also be refused.
	if got := run([]string{input, "--json", filepath.Join(dir, ".", "evidence.pcap")}); got != exitToolError {
		t.Errorf("indirect path: exit code = %d, want %d", got, exitToolError)
	}
}

// TestJSONOutputIsValid checks that the written document parses and carries the
// version stamps a reader needs to tell "the network changed" from "the tool
// changed".
func TestJSONOutputIsValid(t *testing.T) {
	out := filepath.Join(t.TempDir(), "findings.json")
	if got := run([]string{synth.FixturePath("r04-server-response-outlier", "pcap"), "--json", out}); got != exitOK {
		t.Fatalf("exit code = %d", got)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Tool          struct {
			Version        string `json:"version"`
			RulesetVersion string `json:"ruleset_version"`
			Build          string `json:"build"`
		} `json:"tool"`
		Findings []struct {
			Title string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc.SchemaVersion == "" {
		t.Error("schema_version is empty")
	}
	if doc.Tool.RulesetVersion == "" {
		t.Error("ruleset_version is empty; wording and thresholds must be versioned separately from the code")
	}
	if doc.Tool.Build == "" {
		t.Error("build note is empty; a partial rule set must say so or a clean report reads as an all-clear")
	}
	if len(doc.Findings) != 1 {
		t.Errorf("got %d findings, want 1", len(doc.Findings))
	}
}
