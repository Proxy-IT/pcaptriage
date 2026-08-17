package rules

import "github.com/Proxy-IT/pcaptriage/internal/findings"

// SeverityFor maps a significance score onto the three-word vocabulary.
//
// This is calibration, not detection. The score already decided the order; this
// decides which word the reader sees beside it, because order alone does not
// tell anyone whether three findings are three curiosities or three fires.
//
// Nothing is suppressed. A finding below the lowest boundary is still shown,
// still ranked in the same position, and still carries its full wording — it is
// simply labelled as context. There is no display floor, and this function must
// not become one.
func SeverityFor(significance float64) findings.Severity {
	switch {
	case significance >= Thresholds.SeveritySignificantFloor:
		return findings.SeveritySignificant
	case significance >= Thresholds.SeverityWorthNotingFloor:
		return findings.SeverityWorthNoting
	default:
		return findings.SeverityInformational
	}
}

// CoverageStrength describes whether a clean result is well enough covered for
// the report to present it positively.
type CoverageStrength struct {
	// Strong permits the clean banner to use green.
	Strong bool
	// Reason states why it is not strong, for the report to show. Empty when
	// Strong is true.
	Reason string
}

// AssessCoverage decides whether a clean capture's coverage justifies an
// unqualified presentation.
//
// gaps is how many checks could not run on this capture; unbuilt is how many
// planned checks do not exist yet. Both withhold green, for the same reason
// stated differently: in the first case the tool could not look, in the second
// there is nothing to look with.
func AssessCoverage(gaps, unbuilt int) CoverageStrength {
	if Thresholds.CoverageStrongRequiresNoGaps && gaps > 0 {
		return CoverageStrength{Reason: "some checks could not run on this capture"}
	}
	if Thresholds.CoverageStrongRequiresCompleteRuleSet && unbuilt > 0 {
		return CoverageStrength{Reason: "not all of the planned checks are built yet"}
	}
	return CoverageStrength{Strong: true}
}
