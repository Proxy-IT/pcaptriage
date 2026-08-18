package report

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Accessibility has sat in BACKLOG as a standing criterion since the UX
// deep-dive without ever being exercised. These tests are what make it real:
// the ratios are computed from the token declarations themselves, so a hex
// edited to look better and left failing breaks the build rather than shipping.
//
// Thresholds are WCAG 2.1 AA: 4.5:1 for body text, 3:1 for large text and for
// UI boundaries that carry meaning on their own.
const (
	aaBody = 4.5
	aaUI   = 3.0
)

// tokenColour pulls one declared value out of tokens.css. Reading the sheet
// rather than restating the hexes is the whole point — a table of expected
// values here would be a second source of the palette, which is the thing
// tokens.css exists to prevent.
func tokenColour(t *testing.T, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s*--` + regexp.QuoteMeta(name) + `\s*:\s*([^;]+);`)
	m := re.FindStringSubmatch(tokensSource)
	if m == nil {
		t.Fatalf("tokens.css declares no --%s", name)
	}
	return strings.TrimSpace(m[1])
}

// srgbToLinear inverts the sRGB transfer function, per WCAG's definition of
// relative luminance.
func srgbToLinear(c float64) float64 {
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

// parseColour handles the two forms the tokens use: #rrggbb, and rgba() over a
// known backdrop. An rgba token is composited onto that backdrop first, because
// a translucent value has no luminance of its own to measure.
func parseColour(t *testing.T, v string, over [3]float64) [3]float64 {
	t.Helper()
	v = strings.TrimSpace(v)

	if strings.HasPrefix(v, "rgba(") {
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(v, "rgba("), ")"), ",")
		if len(parts) != 4 {
			t.Fatalf("cannot parse %q", v)
		}
		var ch [3]float64
		for i := 0; i < 3; i++ {
			n, err := strconv.ParseFloat(strings.TrimSpace(parts[i]), 64)
			if err != nil {
				t.Fatalf("cannot parse %q: %v", v, err)
			}
			ch[i] = n / 255
		}
		a, err := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
		if err != nil {
			t.Fatalf("cannot parse %q: %v", v, err)
		}
		for i := 0; i < 3; i++ {
			ch[i] = ch[i]*a + over[i]*(1-a)
		}
		return ch
	}

	h := strings.TrimPrefix(v, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		t.Fatalf("cannot parse colour %q", v)
	}
	var ch [3]float64
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			t.Fatalf("cannot parse colour %q: %v", v, err)
		}
		ch[i] = float64(n) / 255
	}
	return ch
}

func luminance(ch [3]float64) float64 {
	return 0.2126*srgbToLinear(ch[0]) + 0.7152*srgbToLinear(ch[1]) + 0.0722*srgbToLinear(ch[2])
}

func ratio(fg, bg [3]float64) float64 {
	lf, lb := luminance(fg), luminance(bg)
	if lf < lb {
		lf, lb = lb, lf
	}
	return (lf + 0.05) / (lb + 0.05)
}

// contrast resolves two token names and returns their ratio. Translucent
// foregrounds composite over the background being measured against.
func contrast(t *testing.T, fg, bg string) float64 {
	t.Helper()
	bgc := parseColour(t, tokenColour(t, bg), [3]float64{1, 1, 1})
	fgc := parseColour(t, tokenColour(t, fg), bgc)
	return ratio(fgc, bgc)
}

type pair struct {
	fg, bg string
	min    float64
	what   string
}

// lightPairs is every text-on-background and meaningful-boundary combination
// the light theme actually renders. Kept as data so Part 2's dark theme extends
// the table rather than forking the test.
func lightPairs() []pair {
	return []pair{
		// Body text, everywhere it lands.
		{"ink", "page", aaBody, "primary text on the page"},
		{"ink", "surface", aaBody, "primary text on a card"},
		{"ink", "wash", aaBody, "primary text on a tinted panel"},
		{"ink-2", "page", aaBody, "secondary text on the page"},
		{"ink-2", "surface", aaBody, "secondary text on a card"},
		{"ink-2", "wash", aaBody, "secondary text on a tinted panel"},
		{"ink-muted", "page", aaBody, "muted text on the page"},
		{"ink-muted", "surface", aaBody, "muted text on a card"},
		{"ink-muted", "wash", aaBody, "muted text on a tinted panel"},

		// The identity accent, in content.
		{"accent", "page", aaBody, "link text on the page"},
		{"accent", "surface", aaBody, "link text on a card"},
		{"accent", "wash", aaBody, "link text on a tinted panel"},
		{"accent", "accent-wash", aaBody, "link text on its own hover background"},
		{"accent-strong", "surface", aaBody, "link hover text"},
		{"on-accent", "accent", aaBody, "label on a filled accent button"},

		// Focus, which has to be visible as a boundary rather than as text.
		{"focus", "page", aaUI, "focus ring against the page"},
		{"focus", "surface", aaUI, "focus ring against a card"},
		{"focus", "accent-wash", aaUI, "focus ring against a hovered control"},

		// Severity. Unchanged by the identity work, re-measured because the
		// surfaces under them moved from warm to cool.
		{"sev-significant", "surface", aaBody, "significant badge text"},
		{"sev-significant", "sev-significant-wash", aaBody, "significant badge on its wash"},
		{"sev-worth-noting", "surface", aaBody, "worth-noting badge text"},
		{"sev-worth-noting", "sev-worth-noting-wash", aaBody, "worth-noting badge on its wash"},
		{"sev-informational", "surface", aaBody, "informational badge text"},
		{"sev-informational", "sev-informational-wash", aaBody, "informational badge on its wash"},
		{"ok", "surface", aaBody, "strong-coverage clean text"},
		{"ok", "ok-wash", aaBody, "strong-coverage clean on its wash"},
	}
}

// barPairs covers the one dark surface in the interface. A focus ring tuned
// for a light page disappears on ink, which is exactly why the bar carries its
// own ring token and why it is measured here rather than assumed.
func barPairs() []pair {
	return []pair{
		{"bar-ink", "bar-surface", aaBody, "nav link on the bar"},
		{"bar-ink", "bar-surface-raised", aaBody, "nav link on a hovered pill"},
		{"bar-ink-strong", "bar-surface", aaBody, "app name on the bar"},
		{"bar-ink-strong", "bar-surface-raised", aaBody, "hovered nav link"},
		{"bar-ink-muted", "bar-surface", aaBody, "tagline on the bar"},
		{"bar-accent", "bar-surface", aaBody, "active nav link"},
		{"bar-accent", "bar-surface-raised", aaBody, "active nav link on its pill"},
		{"bar-focus", "bar-surface", aaUI, "focus ring against the bar"},
		{"bar-focus", "bar-surface-raised", aaUI, "focus ring against a pill"},
	}
}

func TestPaletteMeetsContrastThresholds(t *testing.T) {
	for _, group := range []struct {
		name  string
		pairs []pair
	}{
		{"light", lightPairs()},
		{"bar", barPairs()},
	} {
		t.Run(group.name, func(t *testing.T) {
			for _, p := range group.pairs {
				got := contrast(t, p.fg, p.bg)
				if got < p.min {
					t.Errorf("--%s on --%s is %.2f:1, want at least %.1f:1 (%s)",
						p.fg, p.bg, got, p.min, p.what)
				}
			}
		})
	}
}

// TestContrastReport prints the measured table. Not an assertion — the
// checkpoint report has to quote real numbers, and re-deriving them by hand
// each time is how a stale figure ends up in a document.
func TestContrastReport(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("run with -v to print the contrast table")
	}
	for _, group := range []struct {
		name  string
		pairs []pair
	}{
		{"light surfaces", lightPairs()},
		{"ink bar", barPairs()},
	} {
		fmt.Printf("\n%s\n", strings.ToUpper(group.name))
		for _, p := range group.pairs {
			fmt.Printf("  %-44s %5.2f:1  (min %.1f)  %s\n",
				"--"+p.fg+" on --"+p.bg, contrast(t, p.fg, p.bg), p.min, p.what)
		}
	}
}
