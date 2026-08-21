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
// This build implements R01, R04, and the loss cluster R05/R06/R07/R08. The
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

// RawObserver is implemented by rules that need packets the flow machinery
// never offers them.
//
// The Detector lifecycle is built around TCP conversations: NewFlow, OnPacket
// for packets on that flow, OnFlowEnd. R11 reads DNS over UDP, which has no
// flow to hang off — the engine counts a UDP frame as non-TCP and moves on —
// so a rule that needs it has to be handed the packet directly.
//
// Optional and additive rather than a change to Detector, because eleven rules
// have no use for it and widening the interface would make every one of them
// carry an empty method to say so.
//
// The packet is the engine's reused buffer: valid for the call and not
// afterwards. A rule keeping anything from it must copy the values out, the
// same rule OnPacket already follows.
type RawObserver interface {
	OnRawPacket(pkt *capture.Packet)
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

	// OffloadArtifacts reports that the capture contains segments larger than
	// the connections carrying them negotiated, which means the capture was
	// taken before the sending NIC split them.
	//
	// R13 must consult this: its whole second signal is "large segments fail
	// while small ones succeed", and on an offloaded capture apparent segment
	// size is not wire segment size, so the sizes the signal rests on are not
	// the sizes that travelled.
	OffloadArtifacts bool
	// OffloadBasis is the sentence a degraded finding states as its reason.
	// Empty when OffloadArtifacts is false.
	OffloadBasis string

	// HeadersUnreliable reports that enough frames carried an impossible
	// header length that the ones which did decode cannot be assumed faithful
	// either.
	//
	// This is a different kind of doubt from the two above. Kernel drops and
	// offload leave the surviving frames accurate — the gap is in what is
	// missing, or in what a size means. Rewritten header bytes put every
	// derived fact in question at once: flags, sequence numbers and the flow
	// structure built from them. Nothing downstream can repair that, so the
	// only honest response is to say so where the findings are read.
	HeadersUnreliable bool
	// HeaderBasis is the sentence stating the reason. Empty when
	// HeadersUnreliable is false.
	HeaderBasis string
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
	// OneWayFlows is how many flows were captured in one direction only.
	OneWayFlows int
	// FlowsEvicted is how many flows were discarded mid-run because the
	// concurrent flow cap was reached, before the capture ended.
	FlowsEvicted uint64

	CaptureStart time.Time
	CaptureEnd   time.Time

	// PacketsRead is every frame the reader produced, TCP or not — R15's
	// wording states drop counts against what the capture host saw, which
	// includes non-TCP traffic.
	PacketsRead uint64
	// PacketsTCP and PacketsMalformed are the two halves of the material the
	// TCP rules draw on: frames that decoded, and frames that claimed a header
	// length no sender could have written. R15 reports their ratio.
	PacketsTCP       uint64
	PacketsMalformed uint64
	// PacketsClipped is how many frames arrived with fewer bytes than they
	// carried on the wire. Snaplen and SnaplenKnown are what the file declares
	// about that; SnaplenKnown is false when it declares no limit, which the
	// format spells as zero and which must never be read as a zero-byte cap.
	PacketsClipped uint64
	Snaplen        uint32
	SnaplenKnown   bool
	// DropAvailability, InterfaceDrops, PacketsDropped and DropRatio are the
	// capture-host drop facts R15 reports on. Quality.KernelDropsSignificant
	// (below) is the gating decision already derived from DropRatio; R15
	// reads both — the raw facts to state them, the gating flag to decide
	// which of the two messages ("dropped, and it may explain apparent loss"
	// vs "dropped, but too little to matter") applies.
	DropAvailability capture.DropAvailability
	InterfaceDrops   []capture.InterfaceDrops
	PacketsDropped   uint64
	DropRatio        float64

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
// R15 is listed first, matching that interaction order, though the gating
// fact it depends on (Population.Quality) is actually computed by the engine
// before any detector's Emit runs — R15's own Emit only writes the notes the
// capture-quality facts justify, so its list position here is documentation
// of the dependency rather than a requirement Emit ordering enforces.
//
// The loss cluster shares one classifier. R07 sits ahead of R05 and R06 and
// owns its packet path — the interaction order made literal — while R05, R06
// and R08 read the classification at Emit; R08 last, since it consumes R05
// and R06's per-direction totals. A fresh analyzer per call keeps runs
// independent of each other.
func Default() []Detector {
	loss := newLossAnalyzer()
	return []Detector{
		NewCaptureQualityRule(),
		NewZeroWindowStall(),
		NewSynUnanswered(),
		NewSynRejected(),
		NewServerResponseOutlier(),
		NewOutOfOrderNotLoss(loss),
		NewRTORetransmission(loss),
		NewFastRetransmission(loss),
		NewAsymmetricLoss(loss),
		NewResetMidTransfer(),
		NewConnectionChurn(),
		NewRTTOutlier(),
		NewPMTUBlackhole(),
		NewDNSFailure(),
		NewTLSHandshakeFailure(),
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
	if len(metas) >= TotalV1Rules {
		// The rule set is complete. This sentence has to carry the same
		// caution the partial one did without the crutch of an obvious gap to
		// point at: "all fifteen built" is a fact about the tool, and a reader
		// who takes it as a fact about their capture has been misled by it.
		//
		// So it states what the fifteen are and then says plainly that a
		// condition outside them is a condition nobody looked for. A complete
		// rule set is not complete coverage, and this is the only place the
		// report can say so.
		return fmt.Sprintf(
			"Complete v1 rule set: all %d rules are implemented (%s). These fifteen conditions are "+
				"what this tool looks for; anything outside them was not examined, so a quiet result "+
				"means these checks found nothing rather than that the capture is healthy.",
			TotalV1Rules, strings.Join(names, ", "))
	}
	return fmt.Sprintf(
		"Partial build: %d of the %d v1 rules are implemented (%s). Every other condition in the v1 rule set was not looked for at all.",
		len(metas), TotalV1Rules, strings.Join(names, ", "))
}
