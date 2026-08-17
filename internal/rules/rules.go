// Package rules implements the detection rules from RULES.md.
//
// Each rule is an independent detector. It consumes per-flow state on the
// packet path, keeps whatever it needs to survive flow eviction in its own
// retained aggregates, and emits zero or more findings at the end of the run
// once the comparative baselines are complete.
//
// The wording in RULES.md is the specification. It is parameterised here, not
// paraphrased: no rule states a cause.
//
// This build implements R01, R04, and the loss cluster R05/R06/R07. The
// remaining v1 rules are not present yet, which the report says explicitly —
// via BuildDisclosure, derived from the registry — so it cannot be read as an
// all-clear.
package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/findings"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
)

// Meta describes a rule for the checks list and for --list-checks.
type Meta struct {
	ID         string
	Name       string
	BaseWeight float64
	Summary    string
}

// Detector is one rule.
//
// The lifecycle is: NewFlow once per flow, OnPacket for every packet on it,
// OnFlowEnd exactly once when the flow is evicted or the capture ends, then
// Emit once for the run.
//
// OnFlowEnd is the boundary between the two memory tiers. Anything a rule
// wants at Emit time has to be moved into the rule's own retained aggregates
// there, because the flow state is discarded immediately afterwards.
type Detector interface {
	Meta() Meta

	// NewFlow returns the rule's per-flow state, or nil if it keeps none.
	NewFlow() any

	// OnPacket folds one packet in. fs is what NewFlow returned; fl is the
	// shared flow state, already updated with this packet.
	OnPacket(fs any, fl *flow.State, pkt *capture.Packet, dir flow.Direction)

	// OnFlowEnd runs once per flow, before its state is discarded.
	OnFlowEnd(fs any, fl *flow.State)

	// Emit produces findings and notes for the run.
	Emit(pop *Population, out *findings.Store)
}

// CaptureQuality carries the facts about the capture itself that make other
// rules' findings less certain than they look.
//
// This is the gating seam R15 owns. It has no consumers yet: the rules that
// must read it — R05, R06 and R08, whose loss findings are the ones capture
// loss can counterfeit — are not implemented. It exists now because the
// detection that fills it is implemented, and a fact the tool has established
// but has nowhere to put is a fact it will forget to use later.
//
// A rule consuming this degrades a finding to inferred and states the basis; it
// does not suppress the finding. The loss may well be real — the point is that
// this capture cannot prove it either way.
type CaptureQuality struct {
	// KernelDropsSignificant reports that the capture host discarded enough of
	// the capture that apparent packet loss may be capture loss instead.
	//
	// R05, R06 and R08 must consult this when they are built.
	KernelDropsSignificant bool
	// KernelDropBasis is the sentence a degraded finding states as its reason.
	// Empty when KernelDropsSignificant is false.
	KernelDropBasis string
}

// Population is the capture-wide context a rule compares its subjects against.
//
// This is the mechanism that makes findings meaningful: most of what makes
// something interesting is that it differs from its peers in the same file, so
// the baseline is the capture itself and no external reference data is needed.
type Population struct {
	// TCPFlows is how many distinct TCP flows were observed.
	TCPFlows int
	// TCPHosts are the distinct addresses that took part in TCP flows,
	// ascending.
	TCPHosts []netip.Addr

	// MidstreamFlows, PartialFlows and CompleteFlows partition TCPFlows by
	// capture completeness.
	MidstreamFlows int
	PartialFlows   int
	CompleteFlows  int

	CaptureStart time.Time
	CaptureEnd   time.Time

	// Quality is what the capture itself can and cannot support. Rules whose
	// findings depend on the capture being faithful consult it before claiming
	// certainty.
	Quality CaptureQuality
}

// TotalHosts reports how many distinct hosts took part in TCP flows.
func (p *Population) TotalHosts() int { return len(p.TCPHosts) }

// Default returns a fresh detector set in rule-interaction order.
//
// RULES.md fixes the order in three places: R15 gates degradation flags for
// R04, R08, R10, R13 and R14; R07 runs before R05 and R06, and suppresses
// their findings for reclassified segments; R08 runs after both.
//
// The loss cluster shares one classifier. R07 sits ahead of R05 and R06 and
// owns its packet path — the interaction order made literal — while R05 and
// R06 read the classification at Emit. A fresh analyzer per call keeps runs
// independent of each other.
func Default() []Detector {
	loss := newLossAnalyzer()
	return []Detector{
		NewZeroWindowStall(),
		NewServerResponseOutlier(),
		NewOutOfOrderNotLoss(loss),
		NewRTORetransmission(loss),
		NewFastRetransmission(loss),
	}
}

// TotalV1Rules is how many rules the finished v1 rule set contains, per
// RULES.md's fifteen-rule ceiling.
//
// Every disclosure of the build state — the home screen, the clean-capture
// screen, the exported report, the About page — derives its "N of 15" from this
// constant and len(AllMeta()), so no surface can carry its own count and
// quietly go stale as rules land.
const TotalV1Rules = 15

// AllMeta returns the metadata for every implemented rule, ascending by ID.
//
// Sorted here rather than by each consumer: the detector list is in
// interaction order, which is an engine concern, while every surface that
// lists the checks — the home screen, the guide index, the report — wants
// rule order.
func AllMeta() []Meta {
	ds := Default()
	out := make([]Meta, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Meta())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// BuildDisclosure is the sentence every report carries about how much of the
// v1 rule set exists. Derived from the registry so it cannot go stale as rules
// land — the enumerated names are what lets a reader check the claim against
// the checks table beside it.
func BuildDisclosure() string {
	metas := AllMeta()
	names := make([]string, 0, len(metas))
	for _, m := range metas {
		names = append(names, m.ID+" "+m.Name)
	}
	return fmt.Sprintf(
		"Partial build: %d of the %d v1 rules are implemented (%s). Every other condition in the v1 rule set was not looked for at all.",
		len(metas), TotalV1Rules, strings.Join(names, ", "))
}
