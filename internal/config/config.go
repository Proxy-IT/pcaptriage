// Package config reads and writes the application's preferences file.
//
// This is one of only two things the app ever writes to disk — preferences and,
// later, user-entered host labels. Analysis results are never persisted
// automatically: the capture file is the persistence, and the engine is
// deterministic, so reopening a file re-derives byte-identical results. Saving
// analysis output happens only through an explicit export action.
//
// The file is JSON and meant to be readable and hand-editable. A user who wants
// to know what the app stores about them should be able to open one file and
// see all of it.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion is the config file's format version, so a future change can
// migrate rather than guess.
const SchemaVersion = 1

// AppDir is the subdirectory of the OS config directory that holds the file.
const AppDir = "pcaptriage"

// FileName is the preferences file's name.
const FileName = "config.json"

// TimezoneLocal selects the machine's local timezone.
//
// It is the default because the user's next step after reading a finding is
// correlating it against application logs, which are almost always in local
// time. Silently defaulting to UTC turns a five-minute correlation into an hour.
const TimezoneLocal = "local"

// Theme preference values.
//
// ThemeLight is the default. Dark mode is real, tested and shipped this
// session, but it is also new: the severity palette carries safety-relevant
// meaning (which finding to look at first), and that palette has had far less
// real-capture exposure in its dark form than in light. ThemeSystem would
// silently opt every dark-OS user in on first launch, before any of them have
// chosen pcaptriage's dark mode specifically — the wrong default for a build
// where "do it properly or defer it" is the standard the palette was held to.
// A user who wants dark, in either form, still has it one edit away.
const (
	ThemeLight  = "light"
	ThemeDark   = "dark"
	ThemeSystem = "system"
)

// Preferences is the whole of what the app stores.
//
// Every field must be safe to hand-edit and safe to be missing: a preferences
// file is not a place to keep anything the app cannot do without.
type Preferences struct {
	// Schema is the format version of the file this was read from.
	Schema int `json:"schema"`
	// Timezone is an IANA name such as "Europe/London", or TimezoneLocal.
	//
	// Not yet wired into report rendering — this session establishes the
	// mechanism, not the feature.
	Timezone string `json:"timezone"`
	// Theme is ThemeLight, ThemeDark, or ThemeSystem.
	//
	// Not yet wired to a settings control — this session establishes the
	// mechanism and applies the resolved value at startup, the same state the
	// timezone preference has been in since it was added. Wiring both to a
	// settings control is still open work.
	Theme string `json:"theme"`
}

// Defaults returns the preferences used when no file exists, or when the file
// cannot be understood.
func Defaults() Preferences {
	return Preferences{
		Schema:   SchemaVersion,
		Timezone: TimezoneLocal,
		Theme:    ThemeLight,
	}
}

// validTheme reports whether s is one of the recognised theme values.
func validTheme(s string) bool {
	return s == ThemeLight || s == ThemeDark || s == ThemeSystem
}

// ValidateTheme reports an error when Theme is set to something this build
// does not recognise. An empty Theme is not an error — like an empty
// Timezone, it means no preference is being asserted, not an invalid one.
func (p Preferences) ValidateTheme() error {
	if p.Theme == "" || validTheme(p.Theme) {
		return nil
	}
	return fmt.Errorf("theme %q is not one of %s, %s, %s", p.Theme, ThemeLight, ThemeDark, ThemeSystem)
}

// Location resolves the timezone preference to a *time.Location.
//
// A preference naming a zone this machine does not have resolves to local
// rather than failing: a report in the wrong timezone is a nuisance, and a
// report that will not render is not.
func (p Preferences) Location() (*time.Location, error) {
	if p.Timezone == "" || p.Timezone == TimezoneLocal {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		return time.Local, fmt.Errorf("timezone %q is not a zone this machine knows: %w", p.Timezone, err)
	}
	return loc, nil
}

// Path returns the preferences file's full path.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no configuration directory is available on this system: %w", err)
	}
	return filepath.Join(dir, AppDir, FileName), nil
}

// Result is what Load returns: the preferences to use, and a plain-language
// notice when they are not the ones on disk.
type Result struct {
	Preferences Preferences
	// Path is where the file was looked for, whether or not it existed.
	Path string
	// Existed reports whether a file was found.
	Existed bool
	// Notice is empty on a clean load. When set, it says what went wrong and
	// what the app did instead, in terms a non-expert can act on.
	//
	// It is deliberately not an error: a bad preferences file must not stop
	// someone analysing a capture.
	Notice string
}

// Load reads the preferences file.
//
// A missing file is not a failure — defaults apply and nothing is written until
// something is saved. A file that cannot be parsed is not a failure either:
// defaults apply, a notice is returned, and the file is left exactly as it is.
// Overwriting it would destroy whatever the user was in the middle of editing,
// which is the one thing worse than ignoring it.
func Load() Result {
	res := Result{Preferences: Defaults()}

	path, err := Path()
	if err != nil {
		res.Notice = "Preferences could not be located on this system, so the defaults are in use. " + err.Error()
		return res
	}
	res.Path = path

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res // first run; defaults, no notice, nothing written
		}
		res.Notice = fmt.Sprintf(
			"The preferences file at %s could not be read, so the defaults are in use. It has been left unchanged. (%v)",
			path, err)
		return res
	}
	res.Existed = true

	var got Preferences
	if err := json.Unmarshal(raw, &got); err != nil {
		res.Notice = fmt.Sprintf(
			"The preferences file at %s is not valid JSON, so the defaults are in use. It has been left unchanged so you can fix or delete it. (%v)",
			path, err)
		return res
	}

	// Merge onto defaults rather than trusting the file wholesale, so a file
	// missing a field gets the default for it instead of a zero value.
	prefs := Defaults()
	if got.Timezone != "" {
		prefs.Timezone = got.Timezone
	}
	if got.Theme != "" {
		prefs.Theme = got.Theme
	}
	if got.Schema != 0 {
		prefs.Schema = got.Schema
	}

	if _, err := prefs.Location(); err != nil {
		res.Notice = fmt.Sprintf(
			"The preferences file at %s asks for a timezone this machine does not have, so local time is in use. It has been left unchanged. (%v)",
			path, err)
		prefs.Timezone = TimezoneLocal
	}

	// Same shape as the timezone check: a value the file did set, but that
	// this build does not recognise, falls back rather than reaching the
	// frontend as an opaque string CSS has no rule for.
	if !validTheme(prefs.Theme) {
		res.Notice = fmt.Sprintf(
			"The preferences file at %s asks for a theme this build does not recognise (%q), so %s is in use. It has been left unchanged.",
			path, prefs.Theme, ThemeLight)
		prefs.Theme = ThemeLight
	}

	if prefs.Schema > SchemaVersion {
		res.Notice = fmt.Sprintf(
			"The preferences file at %s was written by a newer version of this app (format %d, this build understands %d). It has been left unchanged and the defaults are in use.",
			path, prefs.Schema, SchemaVersion)
		res.Preferences = Defaults()
		return res
	}

	res.Preferences = prefs
	return res
}

// Save writes the preferences file, creating the directory if needed.
//
// The write goes to a temporary file in the same directory and is then renamed
// over the target, so an interrupted write cannot leave a half-written file
// where a readable one used to be.
func Save(p Preferences) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("could not create the configuration directory: %w", err)
	}

	p.Schema = SchemaVersion
	// Indented and newline-terminated: the file is meant to be opened and read
	// by a person, not only by this program.
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), FileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("could not write preferences: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename has succeeded

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("could not write preferences: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not write preferences: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("could not replace the preferences file: %w", err)
	}
	return nil
}
