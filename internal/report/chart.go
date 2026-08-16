package report

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
)

// Server-rendered SVG charts, per BRIEF.md section 4: no JavaScript, nothing
// fetched, tiny, and they print cleanly. Static — there is no zoom or hover,
// which is the accepted trade for a report that has to open with no network
// access and survive being emailed to a vendor.
//
// Colour is carried by CSS classes rather than inline hex, so the print
// stylesheet can adjust it in one place. The ramp is a single blue hue stepped
// light to dark; nothing here uses a severity scale, because the tool makes no
// severity claim and a red bar would assert one.

// Chart geometry. Every dimension is fixed, so the same data always produces
// byte-identical markup.
const (
	chartWidth   = 680
	labelGutter  = 180
	valueGutter  = 92
	chartRowH    = 30
	chartBarH    = 18 // at or under the 24px cap: the band's leftover is air
	chartTopPad  = 10
	chartBotPad  = 12
	barRadius    = 4
	stackGap     = 2 // surface gap; white does the separating, never a stroke
	maxLabelRune = 24
)

func plotWidth() float64 { return float64(chartWidth - labelGutter - valueGutter) }

// Bar is one row of a horizontal bar chart.
type Bar struct {
	// Label names the subject, shown in the left gutter.
	Label string
	// Value is the bar's magnitude, in the chart's units.
	Value float64
	// Part is a leading portion of Value drawn as a darker segment. Zero
	// leaves the bar as a single fill.
	Part float64
	// ValueText is the direct label at the bar tip.
	ValueText string
}

// svg accumulates markup.
type svg struct{ b strings.Builder }

func (s *svg) openf(format string, args ...any) { fmt.Fprintf(&s.b, format, args...) }

// text writes an SVG text node with its content escaped. Every string that
// reaches a chart came out of a capture, which is attacker-controlled data.
func (s *svg) text(x, y float64, class, anchor, content string) {
	s.openf(`<text x="%s" y="%s" class="%s" text-anchor="%s" dominant-baseline="middle">%s</text>`,
		f2(x), f2(y), class, anchor, template.HTMLEscapeString(content))
}

// barPath renders a horizontal bar with a rounded data-end and square baseline
// end, per the mark spec. Bars shorter than the radius fall back to a plain
// rectangle so the corner arc cannot invert.
func barPath(x, y, w, h, r float64) string {
	if w <= 0 {
		return ""
	}
	if w <= r {
		return fmt.Sprintf(`M%s,%s h%s v%s h-%s Z`, f2(x), f2(y), f2(w), f2(h), f2(w))
	}
	return fmt.Sprintf(`M%s,%s H%s A%s,%s 0 0 1 %s,%s V%s A%s,%s 0 0 1 %s,%s H%s Z`,
		f2(x), f2(y),
		f2(x+w-r), f2(r), f2(r), f2(x+w), f2(y+r),
		f2(y+h-r), f2(r), f2(r), f2(x+w-r), f2(y+h),
		f2(x))
}

// squarePath renders a bar with both ends square, used for the leading segment
// of a stacked bar.
func squarePath(x, y, w, h float64) string {
	if w <= 0 {
		return ""
	}
	return fmt.Sprintf(`M%s,%s h%s v%s h-%s Z`, f2(x), f2(y), f2(w), f2(h), f2(w))
}

// BarChart renders a horizontal bar chart.
//
// Every bar is directly labelled with its value, so no number is reachable only
// by reading a colour or measuring against a gridline. That is also why there
// are no gridlines: direct labels come before gridlines.
//
// reference, when positive, draws a threshold line at that value. It is dashed
// deliberately — it is a threshold rather than chrome — and is described in the
// caption rather than labelled in place, where it would collide with the axis
// on the common case of a threshold near zero.
func BarChart(bars []Bar, reference float64, title string) template.HTML {
	if len(bars) == 0 {
		return ""
	}

	max := reference
	for _, b := range bars {
		if b.Value > max {
			max = b.Value
		}
	}
	if max <= 0 {
		max = 1
	}

	height := chartTopPad + len(bars)*chartRowH + chartBotPad
	pw := plotWidth()

	var s svg
	// No xmlns: an HTML parser puts <svg> in the SVG namespace on its own, and
	// omitting it keeps the report free of any URL at all, dereferenced or not.
	s.openf(`<svg class="chart" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">`,
		chartWidth, height, chartWidth, height, template.HTMLEscapeString(title))
	s.openf(`<title>%s</title>`, template.HTMLEscapeString(title))

	// Baseline: a solid hairline, one step off the surface. Bars grow from it.
	s.openf(`<line x1="%d" y1="%d" x2="%d" y2="%s" class="axis"/>`,
		labelGutter, chartTopPad-4, labelGutter, f2(float64(height-chartBotPad+4)))

	for i, b := range bars {
		y := float64(chartTopPad + i*chartRowH)
		barY := y + (chartRowH-chartBarH)/2
		mid := y + chartRowH/2

		s.text(float64(labelGutter-10), mid, "lbl", "end", truncate(b.Label, maxLabelRune))

		w := b.Value / max * pw
		part := b.Part / max * pw

		switch {
		case b.Part > 0 && part+stackGap < w:
			// Stacked: the leading segment is a portion of the whole, separated
			// by a gap in the surface colour rather than by a stroke.
			s.openf(`<path d="%s" class="fill-strong"/>`,
				squarePath(float64(labelGutter), barY, part, chartBarH))
			s.openf(`<path d="%s" class="fill-soft"/>`,
				barPath(float64(labelGutter)+part+stackGap, barY, w-part-stackGap, chartBarH, barRadius))
		default:
			s.openf(`<path d="%s" class="fill-strong"/>`,
				barPath(float64(labelGutter), barY, w, chartBarH, barRadius))
		}

		s.text(float64(labelGutter)+w+8, mid, "val", "start", b.ValueText)
	}

	if reference > 0 {
		x := float64(labelGutter) + reference/max*pw
		s.openf(`<line x1="%s" y1="%d" x2="%s" y2="%s" class="threshold"/>`,
			f2(x), chartTopPad-4, f2(x), f2(float64(height-chartBotPad+4)))
	}

	s.b.WriteString(`</svg>`)
	return template.HTML(s.b.String())
}

// StackSegment is one segment of a part-to-whole bar.
type StackSegment struct {
	Label string
	Count int
	// Class selects the ordinal ramp step. Steps run dark to light as
	// completeness decreases, so more observed protocol state reads as more ink.
	Class string
}

// StackedBar renders a single part-to-whole bar.
//
// Segments are separated by a gap in the surface colour, and every segment's
// count and share appear in the legend beside the chart, so nothing is encoded
// by colour alone.
func StackedBar(segments []StackSegment, title string) template.HTML {
	total := 0
	for _, seg := range segments {
		total += seg.Count
	}
	if total <= 0 {
		return ""
	}

	const (
		h     = 22
		width = 680
	)

	var s svg
	s.openf(`<svg class="chart chart-stack" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">`,
		width, h, width, h, template.HTMLEscapeString(title))
	s.openf(`<title>%s</title>`, template.HTMLEscapeString(title))

	// Count the segments that will actually be drawn, so the gap budget is
	// right and the bar always fills the full width.
	drawn := 0
	for _, seg := range segments {
		if seg.Count > 0 {
			drawn++
		}
	}
	gaps := float64(0)
	if drawn > 1 {
		gaps = float64(drawn-1) * stackGap
	}
	avail := float64(width) - gaps

	x := 0.0
	placed := 0
	for _, seg := range segments {
		if seg.Count == 0 {
			continue
		}
		placed++
		w := float64(seg.Count) / float64(total) * avail
		if placed == drawn {
			w = float64(width) - x // absorb rounding into the final segment
		}
		switch {
		case placed == drawn && drawn > 1:
			s.openf(`<path d="%s" class="%s"/>`, barPath(x, 0, w, h, barRadius), seg.Class)
		case drawn == 1:
			s.openf(`<path d="%s" class="%s"/>`, barPath(x, 0, w, h, barRadius), seg.Class)
		default:
			s.openf(`<path d="%s" class="%s"/>`, squarePath(x, 0, w, h), seg.Class)
		}
		x += w + stackGap
	}

	s.b.WriteString(`</svg>`)
	return template.HTML(s.b.String())
}

// f2 formats a coordinate to two decimal places. Fixed precision keeps the
// markup byte-identical between runs.
func f2(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// truncate shortens an axis label that would overrun the gutter. Labels are
// endpoints and flow keys, which are short in the IPv4 case and can be long in
// the IPv6 one.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// formatMillis renders a millisecond count the way the finding wordings do:
// whole milliseconds below a second, one decimal place of seconds above it.
func formatMillis(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	if ms < 1000 {
		return strconv.FormatInt(ms, 10) + "ms"
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}
