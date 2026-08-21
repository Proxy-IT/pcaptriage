package capture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// classification records, for every decode error this package defines, whether
// it means the frame's headers were rewritten (true) or merely that the frame
// was incomplete or carried something this build does not decode (false).
//
// The distinction drives R15's malformed-header guard, and getting it wrong is
// costly in both directions: a false entry that should be true lets a corrupt
// capture produce confident findings, and a true entry that should be false
// tells someone with a perfectly good header-only capture that their file is
// damaged.
var classification = map[string]bool{
	// Rewritten: a length field holding a value no sender could have written.
	"ErrBadIPv4IHL":    true,
	"ErrBadIPv4Length": true,
	"ErrBadTCPOffset":  true,

	// Incomplete: the length fields are correct, the bytes are missing. This
	// is what every sliced or snaplen-truncated capture produces.
	"ErrShortEthernet": false,
	"ErrShortVLAN":     false,
	"ErrShortIPv4":     false,
	"ErrShortIPv6":     false,
	"ErrShortIPv6Ext":  false,
	"ErrShortTCP":      false,
	"ErrShortUDP":      false,

	// Ordinary traffic this build does not decode, or a limit of this decoder.
	// None of these is a defect in the frame.
	"ErrUnknownEtherType": false,
	"ErrFragment":         false,
	"ErrNotTCP":           false,
	"ErrVLANDepth":        false,
	"ErrIPv6ExtDepth":     false,
}

// errorValues pairs the names above with the values, so the table is checked
// against real behaviour rather than against itself.
func errorValues() map[string]error {
	return map[string]error{
		"ErrBadIPv4IHL":       ErrBadIPv4IHL,
		"ErrBadIPv4Length":    ErrBadIPv4Length,
		"ErrBadTCPOffset":     ErrBadTCPOffset,
		"ErrShortEthernet":    ErrShortEthernet,
		"ErrShortVLAN":        ErrShortVLAN,
		"ErrShortIPv4":        ErrShortIPv4,
		"ErrShortIPv6":        ErrShortIPv6,
		"ErrShortIPv6Ext":     ErrShortIPv6Ext,
		"ErrShortTCP":         ErrShortTCP,
		"ErrShortUDP":         ErrShortUDP,
		"ErrUnknownEtherType": ErrUnknownEtherType,
		"ErrFragment":         ErrFragment,
		"ErrNotTCP":           ErrNotTCP,
		"ErrVLANDepth":        ErrVLANDepth,
		"ErrIPv6ExtDepth":     ErrIPv6ExtDepth,
	}
}

// TestIsImpossibleHeaderClassifiesEveryDecodeError checks the classifier
// against the table above.
//
// ErrShortTCP is the entry that matters most. A capture sliced mid-header
// produces nothing else, and classifying it as corruption would report every
// header-only capture as damaged — the false positive this check was designed
// around.
func TestIsImpossibleHeaderClassifiesEveryDecodeError(t *testing.T) {
	values := errorValues()
	if len(values) != len(classification) {
		t.Fatalf("errorValues() lists %d errors, the classification table %d; "+
			"an assertion that runs over neither is no assertion", len(values), len(classification))
	}
	for name, err := range values {
		want, ok := classification[name]
		if !ok {
			t.Errorf("%s has no entry in the classification table", name)
			continue
		}
		if got := IsImpossibleHeader(err); got != want {
			t.Errorf("IsImpossibleHeader(%s) = %v, want %v", name, got, want)
		}
	}
}

// TestClassificationTableCoversEveryDecodeError closes the class rather than
// the instance: a decode error added to the package must be classified, or
// this fails. Without it a new error silently defaults to "not corruption",
// which is the direction that loses information quietly.
func TestClassificationTableCoversEveryDecodeError(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "decode.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	values := errorValues()
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range spec.Names {
			if len(name.Name) < 3 || name.Name[:3] != "Err" {
				continue
			}
			found++
			if _, ok := classification[name.Name]; !ok {
				t.Errorf("decode.go defines %s but the classification table does not list it: "+
					"decide whether it means the headers were rewritten or merely incomplete", name.Name)
			}
			if _, ok := values[name.Name]; !ok {
				t.Errorf("decode.go defines %s but errorValues() does not, so it is never exercised", name.Name)
			}
		}
		return true
	})

	if found == 0 {
		t.Fatal("parsed no decode errors out of decode.go; this test would pass on an empty file")
	}
	if found != len(values) {
		t.Errorf("decode.go defines %d errors, errorValues() lists %d", found, len(values))
	}
}
