package synth

import (
	"path/filepath"
	"runtime"
)

// repoRoot resolves the module root from this file's compile-time location.
func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("synth: cannot resolve repository root")
	}
	// .../internal/synth/paths.go -> .../
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// FixtureDir is where committed fixture captures live.
func FixtureDir() string { return filepath.Join(repoRoot(), "testdata", "fixtures") }

// GoldenDir is where committed golden reports live.
func GoldenDir() string { return filepath.Join(repoRoot(), "testdata", "golden") }

// FixturePath returns the committed path for a fixture in the given container
// format, which is "pcap" or "pcapng".
func FixturePath(name, format string) string {
	return filepath.Join(FixtureDir(), name+"."+format)
}

// GoldenPath returns the committed golden report path for a fixture.
func GoldenPath(name string) string {
	return filepath.Join(GoldenDir(), name+".json")
}
