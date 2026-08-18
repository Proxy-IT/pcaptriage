package gui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// The Windows version resource and manifest are compiled from winres/winres.json
// into rsrc_windows_amd64.syso, which is committed so an ordinary build needs no
// go-winres. Two things can go wrong with that arrangement, and neither fails
// loudly on its own:
//
//   - The .syso goes missing. Deleting it makes `wails build` (without
//     -nopackage) succeed where it previously failed with "too many .rsrc
//     sections" — and the binary that comes out has an empty version block,
//     which is what Task Manager and SmartScreen's unknown-publisher prompt
//     read. A hard build error traded for silent metadata loss.
//   - The .syso goes stale. Someone edits winres.json and does not re-run
//     `go generate .`, so the shipped binary keeps the old strings. BRIEF
//     records this happening once already: the copyright said "Apache-2.0
//     licensed" for a while after the licence changed, and nothing failed,
//     "because it is not covered by any test".
//
// This is that test.

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(synth.FixtureDir()))
}

// winresVersionInfo is the slice of winres.json this test cares about: the
// per-language string table that becomes the binary's version block.
type winresVersionInfo struct {
	RTVersion map[string]map[string]struct {
		Info map[string]map[string]string `json:"info"`
	} `json:"RT_VERSION"`
}

func TestCommittedResourceMatchesItsSource(t *testing.T) {
	root := repoRoot(t)

	syso, err := os.ReadFile(filepath.Join(root, "rsrc_windows_amd64.syso"))
	if err != nil {
		t.Fatalf("rsrc_windows_amd64.syso is missing: %v\n\n"+
			"It carries the version resource and manifest, and it is committed on purpose. "+
			"If a build failed with \"too many .rsrc sections\", the fix is `wails build -nopackage` "+
			"(see README) — not removing this file, which makes the build pass and the version block empty.", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, "winres", "winres.json"))
	if err != nil {
		t.Fatal(err)
	}
	var src winresVersionInfo
	if err := json.Unmarshal(raw, &src); err != nil {
		t.Fatal(err)
	}

	// Resource strings are UTF-16LE inside the .syso, so the source values are
	// encoded rather than the resource decoded — no PE parsing needed to answer
	// "did this string make it in".
	contains := func(s string) bool {
		u := utf16.Encode([]rune(s))
		b := make([]byte, 0, len(u)*2)
		for _, r := range u {
			b = append(b, byte(r), byte(r>>8))
		}
		return strings.Contains(string(syso), string(b))
	}

	var checked int
	for _, langs := range src.RTVersion {
		for _, block := range langs {
			for _, strs := range block.Info {
				for key, want := range strs {
					checked++
					if !contains(want) {
						t.Errorf("winres.json sets %s=%q but the committed .syso does not contain it; "+
							"the resource is stale — re-run `go generate .` (needs go-winres)", key, want)
					}
				}
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d version strings found in winres.json; the parse is wrong and this test "+
			"would pass without checking anything", checked)
	}
}

// TestCopyrightAgreesEverywhere closes the specific drift BRIEF records: the
// copyright line lives in three places and only one of them is legally load
// bearing, so the other two can go stale without anything noticing.
func TestCopyrightAgreesEverywhere(t *testing.T) {
	root := repoRoot(t)

	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// LICENSE is the source of truth; the other two restate it for Windows.
	const holder = "Copyright (c) 2026 Proxy-IT"
	if !strings.Contains(read("LICENSE"), holder) {
		t.Fatalf("LICENSE does not carry %q — this test is anchored to the wrong string "+
			"and every assertion below is meaningless", holder)
	}

	for _, f := range []string{"wails.json", "winres/winres.json"} {
		if !strings.Contains(read(f), holder) {
			t.Errorf("%s does not carry the LICENSE copyright holder %q; "+
				"it is compiled into the binary's properties dialog and has drifted from the licence before", f, holder)
		}
	}

	// And the two Windows copies must agree with each other exactly, not merely
	// both mention the holder — the licence name is the part that went stale.
	lic := func(f string) string {
		s := read(f)
		i := strings.Index(s, holder)
		if i < 0 {
			return ""
		}
		rest := s[i:]
		if j := strings.IndexAny(rest, "\"\n"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	if a, b := lic("wails.json"), lic("winres/winres.json"); a != b {
		t.Errorf("wails.json says %q and winres/winres.json says %q; "+
			"they are compiled into the same binary and must not disagree", a, b)
	}
}
