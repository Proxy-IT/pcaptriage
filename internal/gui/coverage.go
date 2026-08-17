package gui

import (
	"github.com/Proxy-IT/pcaptriage/internal/rules"
)

// Coverage — what a run examined and what it could not — is assembled by the
// report package and carried inside the report document, so the clean-capture
// screen here and the exported HTML and JSON render the same struct. It was
// assembled in this package first; it moved when the exports gained the same
// §9 false-all-clear exposure the clean screen was built to fix, and nothing
// coverage-shaped should be reintroduced here.

// checkInfos is the implemented rule set, from the registry.
//
// Shared with the home screen rather than restated: two lists of what the tool
// checks would eventually disagree, and the one on the clean screen is the one
// a reader is relying on when they decide the capture is fine.
func checkInfos() []CheckInfo {
	metas := rules.AllMeta()
	out := make([]CheckInfo, 0, len(metas))
	for _, m := range metas {
		out = append(out, CheckInfo{ID: m.ID, Name: m.Name, Summary: m.Summary})
	}
	return out
}
