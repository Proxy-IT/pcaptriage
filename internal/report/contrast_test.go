package report

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

// Accessibility had been a standing review criterion since the UX deep-dive
// without ever being exercised. These tests are what make it real:
// the ratios are computed from the token declarations themselves, so a hex
// edited to look better and left failing breaks the build rather than shipping.
//
// Thresholds are WCAG 2.1 AA: 4.5:1 for body text, 3:1 for large text and for
// UI boundaries that carry meaning on their own.
const (
	aaBody = 4.5
	aaUI   = 3.0
)

// themedTokens resolves every token to the value it has under theme, the same
// way a browser's cascade would: dark starts from the light declarations and
// overlays whatever the [data-theme="dark"] block redeclares, so a
// theme-invariant token (the bar, the chart ramp, type, radii) still resolves
// correctly even though dark never mentions it.
//
// Reading the explicit [data-theme="dark"] block rather than the OS-media-
// query one is arbitrary but not a gap: TestDarkOverridesAgreeWithEachOther
// is what guarantees the two agree, so this test does not need to check both.
func themedTokens(t *testing.T, theme string) map[string]string {
	t.Helper()
	src := stripCSSComments(tokensSource)

	light := declarationsIn(t, src, `:root \{`)
	if theme == "light" {
		return light
	}

	dark := declarationsIn(t, src, `:root\[data-theme="dark"\] \{`)
	merged := make(map[string]string, len(light))
	for k, v := range light {
		merged[k] = v
	}
	for k, v := range dark {
		merged[k] = v
	}
	return merged
}

// tokenColour pulls one token's resolved value for theme. Reading the sheet
// rather than restating the hexes is the whole point — a table of expected
// values here would be a second source of the palette, which is the thing
// tokens.css exists to prevent.
func tokenColour(t *testing.T, theme, name string) string {
	t.Helper()
	v, ok := themedTokens(t, theme)[name]
	if !ok {
		t.Fatalf("tokens.css declares no --%s resolvable under theme %q", name, theme)
	}
	return v
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

// contrast resolves two token names under theme and returns their ratio.
// Translucent foregrounds composite over the background being measured
// against.
func contrast(t *testing.T, theme, fg, bg string) float64 {
	t.Helper()
	bgc := parseColour(t, tokenColour(t, theme, bg), [3]float64{1, 1, 1})
	fgc := parseColour(t, tokenColour(t, theme, fg), bgc)
	return ratio(fgc, bgc)
}

type pair struct {
	fg, bg string
	min    float64
	what   string
}

// themedPairs is every text-on-background and meaningful-boundary combination
// the app's own content renders — the tokens that actually change between
// light and dark. Kept as data, checked against both themes' resolved values,
// so dark extends this table rather than forking the test: one set of pairs
// that must hold whichever theme is in force, exactly the shape 2b's brief
// asks for ("extend it rather than duplicating it").
func themedPairs() []pair {
	return []pair{
		// Body text, everywhere it lands.
		{"ink-primary", "page", aaBody, "primary text on the page"},
		{"ink-primary", "surface", aaBody, "primary text on a card"},
		{"ink-primary", "wash", aaBody, "primary text on a tinted panel"},
		{"ink-secondary", "page", aaBody, "secondary text on the page"},
		{"ink-secondary", "surface", aaBody, "secondary text on a card"},
		{"ink-secondary", "wash", aaBody, "secondary text on a tinted panel"},
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

// TestPaletteMeetsContrastThresholds checks every themed pair under both
// themes, and the bar pairs once — the bar is theme-invariant (see tokens.css:
// dark mode does not redeclare it, because it is already the dark surface),
// so its ratios cannot differ by theme and checking it under "dark" as well
// would only re-run the identical arithmetic under a different label.
func TestPaletteMeetsContrastThresholds(t *testing.T) {
	// An accessibility check that iterates an empty pair list passes while
	// verifying no contrast at all, and reads in CI exactly like one that
	// verified every pair. Both generators are asserted non-empty first.
	if len(themedPairs()) == 0 {
		t.Fatal("themedPairs() is empty, so no contrast ratio would be checked")
	}
	if len(barPairs()) == 0 {
		t.Fatal("barPairs() is empty, so the ink bar's contrast would go unchecked")
	}

	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			for _, p := range themedPairs() {
				got := contrast(t, theme, p.fg, p.bg)
				if got < p.min {
					t.Errorf("--%s on --%s is %.2f:1, want at least %.1f:1 (%s)",
						p.fg, p.bg, got, p.min, p.what)
				}
			}
		})
	}
	t.Run("bar", func(t *testing.T) {
		for _, p := range barPairs() {
			got := contrast(t, "light", p.fg, p.bg)
			if got < p.min {
				t.Errorf("--%s on --%s is %.2f:1, want at least %.1f:1 (%s)",
					p.fg, p.bg, got, p.min, p.what)
			}
		}
	})
}

// TestContrastReport prints the measured table for both themes. Not an
// assertion — the checkpoint report has to quote real numbers, and
// re-deriving them by hand each time is how a stale figure ends up in a
// document.
func TestContrastReport(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("run with -v to print the contrast table")
	}
	for _, theme := range []string{"light", "dark"} {
		fmt.Printf("\n%s THEME\n", strings.ToUpper(theme))
		for _, p := range themedPairs() {
			fmt.Printf("  %-44s %5.2f:1  (min %.1f)  %s\n",
				"--"+p.fg+" on --"+p.bg, contrast(t, theme, p.fg, p.bg), p.min, p.what)
		}
	}
	fmt.Printf("\nINK BAR (theme-invariant)\n")
	for _, p := range barPairs() {
		fmt.Printf("  %-44s %5.2f:1  (min %.1f)  %s\n",
			"--"+p.fg+" on --"+p.bg, contrast(t, "light", p.fg, p.bg), p.min, p.what)
	}
}

// ---------------------------------------------------------------- perceptual
//
// Contrast ratio answers "can this be read". It does not answer "does this
// look like the colour it is supposed to be" — a ratio is computed from
// luminance alone, so a saturated red and a desaturated brown at the same
// luminance score identically. Severity's two informal rules — "significant
// reads hotter than worth-noting reads hotter than informational" and
// "neutral is not green" — are both claims about how a colour *looks*, which
// needs CIELAB, not WCAG. These two tests are what make Part 1 and 2b's
// colour-science reasoning (chroma, hue) checkable rather than eyeballed —
// the same measurements used to derive the dark palette, run here as
// assertions against whatever the tokens actually declare.

// labChannel and its inverse implement CIE L*a*b* via the standard D65 path,
// matching the arithmetic used throughout this session's colour derivation
// (and the browser-side measurements from Part 1's checkpoint).
func labChannel(t float64) float64 {
	const delta = 6.0 / 29.0
	if t > delta*delta*delta {
		return math.Cbrt(t)
	}
	return t/(3*delta*delta) + 4.0/29.0
}

// lab converts an sRGB hex colour to CIE L*a*b*, returning L*, a*, b*.
func lab(t *testing.T, hex string) (l, a, b float64) {
	t.Helper()
	ch := parseColour(t, hex, [3]float64{1, 1, 1})
	r, g, bl := srgbToLinear(ch[0]), srgbToLinear(ch[1]), srgbToLinear(ch[2])

	x := r*0.4124 + g*0.3576 + bl*0.1805
	y := r*0.2126 + g*0.7152 + bl*0.0722
	z := r*0.0193 + g*0.1192 + bl*0.9505

	const xn, yn, zn = 0.95047, 1.0, 1.08883
	fx, fy, fz := labChannel(x/xn), labChannel(y/yn), labChannel(z/zn)

	l = 116*fy - 16
	a = 500 * (fx - fy)
	b = 200 * (fy - fz)
	return
}

// chroma is CIELAB's C*ab: how far a colour sits from grey, independent of
// how light or dark it is. This is what "saturated" means numerically.
func chroma(t *testing.T, hex string) float64 {
	_, a, b := lab(t, hex)
	return math.Hypot(a, b)
}

// hue is CIELAB's h_ab in degrees, 0-360. Meaningless at zero chroma (a grey
// has no hue), which is why every use of it below is paired with a chroma
// floor first.
func hue(t *testing.T, hex string) float64 {
	_, a, b := lab(t, hex)
	d := math.Atan2(b, a) * 180 / math.Pi
	if d < 0 {
		d += 360
	}
	return d
}

// hotChroma is the floor a severity colour must clear to read as "hot" —
// saturated and warm — rather than a tinted neutral. informationalCeiling is
// the ceiling the neutral level must stay under.
//
// 30 rather than a rounder number: it is set just below the least-saturated
// of the four real "hot" values across both themes (light --ok, C*ab 38.8 —
// green is the hardest hue to make both AA-legible and highly saturated at
// once, so it is the tightest fit of the four, not amber or red), with margin
// kept below it rather than raised to meet a round number, and every other
// hot value (65-71 light, 57-59 dark) clears it with room to spare. The gap
// to informationalCeiling stays wide (30 vs 20 against real informational
// values of 1.9-8.1) because this is a legibility signal, not a threshold
// meant to be approached.
const (
	hotChroma            = 30.0
	informationalCeiling = 20.0
)

// TestSeverityOrderingReadsHotter checks the "significant reads hotter than
// worth-noting reads hotter than informational" rule directly, in both
// themes, rather than trusting it holds because the light values were chosen
// by eye and the dark values were derived to match.
//
// "Hotter" is operationalised as two independent claims, both of which must
// hold: significant and worth-noting are both clearly saturated (chroma
// clears hotChroma) while informational is clearly not (chroma stays under
// informationalCeiling) — the chroma gap that reads as "warm colour" versus
// "no colour" — and between the two warm levels, significant sits at a lower
// hue angle than worth-noting, i.e. closer to red than to amber, which is the
// specific way redder reads hotter than more-orange on this part of the wheel.
func TestSeverityOrderingReadsHotter(t *testing.T) {
	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			sig := tokenColour(t, theme, "sev-significant")
			wn := tokenColour(t, theme, "sev-worth-noting")
			info := tokenColour(t, theme, "sev-informational")

			cSig, cWn, cInfo := chroma(t, sig), chroma(t, wn), chroma(t, info)
			if cSig < hotChroma {
				t.Errorf("sev-significant (%s) has chroma %.1f, wanted >= %.1f — it does not read as saturated", sig, cSig, hotChroma)
			}
			if cWn < hotChroma {
				t.Errorf("sev-worth-noting (%s) has chroma %.1f, wanted >= %.1f — it does not read as saturated", wn, cWn, hotChroma)
			}
			if cInfo >= informationalCeiling {
				t.Errorf("sev-informational (%s) has chroma %.1f, wanted < %.1f — it reads as coloured, not neutral", info, cInfo, informationalCeiling)
			}

			hSig, hWn := hue(t, sig), hue(t, wn)
			if hSig >= hWn {
				t.Errorf("sev-significant hue %.1f°  is not below sev-worth-noting hue %.1f° — significant no longer reads redder/hotter", hSig, hWn)
			}
		})
	}
}

// TestSeverityIsPerceptuallyDistinctFromNeutral is the neutral-not-green rule,
// checked at the level the eye actually reads rather than at the level of
// which CSS class rendered.
//
// TestCleanBannerIsNeutralWhenCoverageIsGappy and the export's equivalent
// already prove the *class* is withheld correctly — a gappy clean result never
// carries "coverage-strong", in either theme, because the class only exists in
// the markup and does not vary with which theme resolves its colours. What
// those tests cannot show is whether the fallback a reader actually sees when
// the class is absent could be mistaken for green. This test closes that gap:
// --ok must stay clearly saturated and green-hued, and --sev-informational
// (what "no colour" actually looks like on this card) must stay clearly
// desaturated, in both themes — so the two states cannot converge by
// coincidence of a future palette edit.
func TestSeverityIsPerceptuallyDistinctFromNeutral(t *testing.T) {
	const greenHueMin, greenHueMax = 100.0, 180.0

	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			ok := tokenColour(t, theme, "ok")
			info := tokenColour(t, theme, "sev-informational")

			cOk, cInfo := chroma(t, ok), chroma(t, info)
			if cOk < hotChroma {
				t.Errorf("--ok (%s) has chroma %.1f, wanted >= %.1f — the strong-coverage colour barely reads as coloured at all", ok, cOk, hotChroma)
			}
			if cInfo >= informationalCeiling {
				t.Errorf("--sev-informational (%s) has chroma %.1f, wanted < %.1f — the neutral fallback reads as coloured, "+
					"which is exactly what could be mistaken for the green it must not be", info, cInfo, informationalCeiling)
			}

			hOk := hue(t, ok)
			if hOk < greenHueMin || hOk > greenHueMax {
				t.Errorf("--ok (%s) has hue %.1f°, outside the green range [%.0f, %.0f] — "+
					"it no longer reads as the colour its name promises", ok, hOk, greenHueMin, greenHueMax)
			}
		})
	}
}

// TestAccentStaysQuieterThanSeverity is a cheap, permanent proxy for a
// measurement this package cannot make itself.
//
// The real claim — does the identity accent out-pull the significant badge
// to the eye, in a rendered findings view — depends on how much text area
// each colour actually covers on screen, which depends on the DOM, the
// fixture, and the browser rendering it; no Go test here can compute that
// (the screenshot/visual-verification gap already names this class of
// limitation, and it applied exactly this session: dark mode's
// --accent-strong shipped once at C*ab 27, was measured in a real browser
// against a real findings view, found to out-pull the significant badge
// 1.48x to 1, and was brought down to C*ab 14 — see the derivation comment in
// tokens.css for the full account and the re-measured 1.20x-the-other-way
// result).
//
// What this test can hold, cheaply and permanently, is the qualitative
// version of the same rule: the accent must never be *as saturated as* a
// severity colour, in either theme. That would not by itself have caught this
// session's regression (27 is still under hotChroma's 30), but it catches the
// coarser mistake a future edit is more likely to make — reaching for a
// vivid, fully-saturated accent the way the identity's own reference palette
// almost did — and it is the ceiling every accent value this session derived
// actually respects, light and dark alike.
func TestAccentStaysQuieterThanSeverity(t *testing.T) {
	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			for _, name := range []string{"accent", "accent-strong"} {
				hex := tokenColour(t, theme, name)
				c := chroma(t, hex)
				if c >= hotChroma {
					t.Errorf("--%s (%s) has chroma %.1f, wanted < %.1f (severity's own saturation floor) — "+
						"an accent this saturated risks outpulling the badge it must never compete with",
						name, hex, c, hotChroma)
				}
			}
		})
	}
}

// TestSeverityBadgesSurviveGreyscalePrint is Part 3's print requirement made
// checkable: the report's @media print block sets body to pure white and
// doubles .tag-sev's border width, on the theory that colour may not survive
// the printer but the word and the box around it still will. That theory
// depends on every severity foreground actually being dark enough to read as
// a visible line once hue is discarded — WCAG relative luminance is exactly a
// weighted greyscale conversion, so contrast-against-white is the same
// measurement a black-and-white printer or photocopier effectively performs.
//
// The export never themes (TestExportedHTMLLocksToLightTheme), so only the
// light values are checked here — there is no dark print state for this to
// hold for.
//
// significant, worth-noting and ok are checked directly; informational is
// checked as it actually prints, not as a hypothetical fourth hue: its badge
// text is --ink-secondary and its border is --outline, the same "no colour"
// treatment the screen render uses, because informational is deliberately the
// one tier that does not compete for the eye even in colour.
func TestSeverityBadgesSurviveGreyscalePrint(t *testing.T) {
	white := [3]float64{1, 1, 1}

	check := func(label, hex string) {
		t.Helper()
		fg := parseColour(t, hex, white)
		got := ratio(fg, white)
		if got < aaBody {
			t.Errorf("%s (%s) is %.2f:1 against white, want >= %.1f:1 — "+
				"on a greyscale printer this would print too pale to read as a bordered badge",
				label, hex, got, aaBody)
		}
	}

	check("--sev-significant", tokenColour(t, "light", "sev-significant"))
	check("--sev-worth-noting", tokenColour(t, "light", "sev-worth-noting"))
	check("--ok", tokenColour(t, "light", "ok"))
	check("--ink-secondary (informational's badge text)", tokenColour(t, "light", "ink-secondary"))
}
