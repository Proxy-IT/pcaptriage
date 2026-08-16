package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withConfigDir points os.UserConfigDir at a temporary directory for the test.
//
// On every platform Go resolves it from an environment variable, so this is the
// supported way to redirect it without touching the developer's real config.
func withConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	switch {
	case os.Getenv("APPDATA") != "" || isWindows():
		t.Setenv("APPDATA", dir)
	default:
		t.Setenv("XDG_CONFIG_HOME", dir)
		t.Setenv("HOME", dir)
	}
	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if !strings.HasPrefix(got, dir) {
		t.Fatalf("config path %q did not land under the test directory %q", got, dir)
	}
	return dir
}

func isWindows() bool { return os.PathSeparator == '\\' }

// TestMissingFileIsNotAnError is the first-run case: no file, defaults apply,
// and nothing is written until something is saved.
func TestMissingFileIsNotAnError(t *testing.T) {
	withConfigDir(t)

	res := Load()
	if res.Existed {
		t.Error("reported a file that does not exist")
	}
	if res.Notice != "" {
		t.Errorf("first run produced a notice: %q", res.Notice)
	}
	if res.Preferences != Defaults() {
		t.Errorf("got %+v, want defaults %+v", res.Preferences, Defaults())
	}
	if _, err := os.Stat(res.Path); !os.IsNotExist(err) {
		t.Error("Load created the file; it should only be written on save")
	}
}

// TestSaveThenLoadRoundTrips checks the mechanism end to end, and that the file
// is something a person could open and read.
func TestSaveThenLoadRoundTrips(t *testing.T) {
	withConfigDir(t)

	if err := Save(Preferences{Timezone: "Europe/London"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	res := Load()
	if !res.Existed {
		t.Error("saved file was not found on load")
	}
	if res.Notice != "" {
		t.Errorf("clean load produced a notice: %q", res.Notice)
	}
	if res.Preferences.Timezone != "Europe/London" {
		t.Errorf("timezone = %q", res.Preferences.Timezone)
	}
	if res.Preferences.Schema != SchemaVersion {
		t.Errorf("schema = %d, want %d", res.Preferences.Schema, SchemaVersion)
	}

	raw, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "\n  ") {
		t.Error("the file is not indented; it is meant to be hand-readable")
	}
	if !strings.HasSuffix(text, "\n") {
		t.Error("the file does not end in a newline")
	}
	for _, want := range []string{`"schema"`, `"timezone"`} {
		if !strings.Contains(text, want) {
			t.Errorf("file is missing %s:\n%s", want, text)
		}
	}
}

// TestCorruptFileIsNotACrash covers the case that matters most: a bad file must
// not stop someone analysing a capture, and must not be silently destroyed.
func TestCorruptFileIsNotACrash(t *testing.T) {
	withConfigDir(t)

	path, _ := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	const garbage = "{ this is not json at all"
	if err := os.WriteFile(path, []byte(garbage), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Load()
	if res.Preferences != Defaults() {
		t.Errorf("got %+v, want defaults", res.Preferences)
	}
	if res.Notice == "" {
		t.Fatal("a corrupt file produced no notice; the user would never know")
	}
	for _, want := range []string{"defaults", "left unchanged"} {
		if !strings.Contains(res.Notice, want) {
			t.Errorf("notice does not mention %q: %q", want, res.Notice)
		}
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != garbage {
		t.Error("the corrupt file was overwritten; it must be left intact so the user can fix it")
	}
}

// TestUnknownTimezoneFallsBackAndSaysSo checks a file that parses but asks for
// something this machine cannot do.
func TestUnknownTimezoneFallsBackAndSaysSo(t *testing.T) {
	withConfigDir(t)

	path, _ := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(Preferences{Schema: SchemaVersion, Timezone: "Mars/Olympus_Mons"})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	res := Load()
	if res.Preferences.Timezone != TimezoneLocal {
		t.Errorf("timezone = %q, want %q", res.Preferences.Timezone, TimezoneLocal)
	}
	if !strings.Contains(res.Notice, "timezone") {
		t.Errorf("notice does not explain the timezone problem: %q", res.Notice)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(body) {
		t.Error("the file was rewritten; it must be left intact")
	}
}

// TestPartialFileGetsDefaultsForMissingFields checks that a hand-edited file
// with one key in it does not zero out everything else.
func TestPartialFileGetsDefaultsForMissingFields(t *testing.T) {
	withConfigDir(t)

	path, _ := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"timezone":"UTC"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	res := Load()
	if res.Notice != "" {
		t.Errorf("unexpected notice: %q", res.Notice)
	}
	if res.Preferences.Timezone != "UTC" {
		t.Errorf("timezone = %q", res.Preferences.Timezone)
	}
	if res.Preferences.Schema != SchemaVersion {
		t.Errorf("schema = %d, want the default %d", res.Preferences.Schema, SchemaVersion)
	}
}

// TestNewerSchemaIsLeftAlone checks the forward-compatibility case: a file from
// a future version is not reinterpreted or overwritten.
func TestNewerSchemaIsLeftAlone(t *testing.T) {
	withConfigDir(t)

	path, _ := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":99,"timezone":"Europe/London"}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	res := Load()
	if res.Preferences != Defaults() {
		t.Errorf("got %+v, want defaults", res.Preferences)
	}
	if !strings.Contains(res.Notice, "newer version") {
		t.Errorf("notice does not explain the version mismatch: %q", res.Notice)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(body) {
		t.Error("the file was overwritten")
	}
}

// TestLocation checks the resolution the timezone preference exists for.
func TestLocation(t *testing.T) {
	for _, tz := range []string{"", TimezoneLocal} {
		loc, err := (Preferences{Timezone: tz}).Location()
		if err != nil || loc == nil {
			t.Errorf("Location(%q) = %v, %v", tz, loc, err)
		}
	}
	if _, err := (Preferences{Timezone: "UTC"}).Location(); err != nil {
		t.Errorf("UTC should resolve: %v", err)
	}
	loc, err := (Preferences{Timezone: "Nowhere/Nothing"}).Location()
	if err == nil {
		t.Error("an unknown zone should report an error")
	}
	if loc == nil {
		t.Error("an unknown zone should still return a usable location")
	}
}

// TestSaveIsAtomic checks that a failed write cannot leave a half-written file
// where a readable one used to be.
func TestSaveIsAtomic(t *testing.T) {
	withConfigDir(t)

	if err := Save(Preferences{Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	if err := Save(Preferences{Timezone: "Europe/London"}); err != nil {
		t.Fatal(err)
	}

	path, _ := Path()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
	if got := Load().Preferences.Timezone; got != "Europe/London" {
		t.Errorf("second save did not take: %q", got)
	}
}
