// Package scoring implements the significance model from RULES.md.
//
//	significance = base_weight × impact × scope × deviation
//
// The result orders findings and nothing else. It is not a severity rating and
// is never shown to the user as a number.
//
// RULES.md fixes the range of each factor but not the curve inside it. The
// curves chosen here are documented on each function; they are calibration
// decisions, not derived constants, and should be revisited against real
// captures alongside the thresholds.
package scoring

import "math"

// Scope is how broadly a condition reaches, from RULES.md's scoring table.
type Scope float64

const (
	// ScopeFlow is one flow.
	ScopeFlow Scope = 0.8
	// ScopeHost is one host.
	ScopeHost Scope = 1.2
	// ScopeMultiHost is several hosts but not all of them.
	ScopeMultiHost Scope = 1.6
	// ScopeCaptureWide is every host in the capture.
	ScopeCaptureWide Scope = 2.0
)

// ScopeFor picks a scope band from how many hosts a condition touches out of
// how many are present.
func ScopeFor(affectedHosts, affectedFlows, totalHosts int) Scope {
	switch {
	case affectedHosts <= 1 && affectedFlows <= 1:
		return ScopeFlow
	case affectedHosts <= 1:
		return ScopeHost
	case totalHosts > 1 && affectedHosts >= totalHosts:
		return ScopeCaptureWide
	default:
		return ScopeMultiHost
	}
}

// Proximity multiplies significance when a condition occurs close to a
// failure, per RULES.md's proximity bonus.
const Proximity = 1.5

// ProximityWindowSeconds is how close to a RST, connection timeout, or the end
// of a flow that transferred no data the condition has to be.
const ProximityWindowSeconds = 2.0

// Impact maps seconds of measurable stall or delay onto RULES.md's 1.0–5.0
// band.
//
// The curve is 1 + 2·log10(1+s), clamped: a tenth of a second scores 1.08, one
// second 1.60, ten seconds 3.08, and a hundred seconds or more saturates at
// 5.0. Log scaling is what stops a long tail of small delays from outranking a
// single large stall.
func Impact(seconds float64) float64 {
	if seconds <= 0 || math.IsNaN(seconds) {
		return 1.0
	}
	v := 1.0 + 2.0*math.Log10(1.0+seconds)
	return clamp(v, 1.0, 5.0)
}

// Deviation maps a value's ratio to its population median onto RULES.md's
// 0.5–3.0 band.
//
// Where no peer group exists the result is fixed at 1.0 and the report says
// comparative ranking was unavailable. Where the population median is zero —
// every peer is clean — the value is at the top of the band, which is the case
// RULES.md calls out as the thing worth reading first.
func Deviation(value, populationMedian float64, peerGroup bool) float64 {
	if !peerGroup {
		return 1.0
	}
	if populationMedian <= 0 {
		if value > 0 {
			return 3.0
		}
		return 1.0
	}
	return clamp(value/populationMedian, 0.5, 3.0)
}

// Inputs are the factors behind one finding's significance.
type Inputs struct {
	BaseWeight float64
	// ImpactSeconds is the measurable stall or delay attributable to the
	// condition.
	ImpactSeconds float64
	Scope         Scope
	// Value and PopulationMedian are the same metric for this subject and for
	// the population it is compared against.
	Value            float64
	PopulationMedian float64
	PeerGroup        bool
	// Proximate reports that the condition occurred within
	// ProximityWindowSeconds of a failure.
	Proximate bool
}

// Significance computes the ordering score for a finding.
func Significance(in Inputs) float64 {
	s := in.BaseWeight *
		Impact(in.ImpactSeconds) *
		float64(in.Scope) *
		Deviation(in.Value, in.PopulationMedian, in.PeerGroup)
	if in.Proximate {
		s *= Proximity
	}
	return s
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
