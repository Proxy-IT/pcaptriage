package capture

import (
	"reflect"
	"strings"
	"testing"
)

// appLayerAllowlist is every field this build may extract from application
// payload, named individually.
//
// This list is the guarantee. Before Batch 3 the decoder never looked at
// payload at all, so "no payload bytes in output" was structural in the
// strongest sense — there was nothing to leak because nothing was read. R11
// and R12 need to read payload, so the guarantee moved to a weaker but still
// structural form: **payload is parsed, and only these named scalars survive
// it.**
//
// A weaker guarantee needs a compensating guard, which is this file. Adding a
// field here is a deliberate act with a reviewer attached; adding one without
// updating this list fails the test below. That is the difference between a
// guarantee and a comment.
var appLayerAllowlist = []string{
	// DNS. Header only — the question section carries the name being looked
	// up and is never parsed, because R11 reports how many lookups failed and
	// how long they took, never which names.
	"DNSPresent",
	"DNSIsResponse",
	"DNSID",
	"DNSRcode",
	"DNSQuestions",
	"DNSAnswers",

	// TLS. Record and handshake framing, the alert numbers, the negotiated
	// version, and one certificate expiry as a Unix second. No subject, no
	// issuer, no server name, no key material.
	"TLSPresent",
	"TLSRecordType",
	"TLSHandshakeType",
	"TLSAlertLevel",
	"TLSAlertDesc",
	"TLSVersion",
	"TLSCertNotAfter",
}

// TestAppLayerExtractionIsAllowlisted holds the new guarantee to its list.
//
// Two directions, because either alone is escapable. A field on Packet whose
// name marks it as application-layer must appear in the allowlist, so a new
// extraction cannot arrive unannounced. And every name in the allowlist must
// exist, so the list cannot rot into a description of a struct that has moved
// on.
func TestAppLayerExtractionIsAllowlisted(t *testing.T) {
	allowed := map[string]bool{}
	for _, n := range appLayerAllowlist {
		allowed[n] = true
	}

	found := map[string]bool{}
	ty := reflect.TypeOf(Packet{})
	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		// The prefixes are the marker. A future protocol adds its own and
		// must add itself here at the same time.
		if !strings.HasPrefix(name, "DNS") && !strings.HasPrefix(name, "TLS") {
			continue
		}
		found[name] = true
		if !allowed[name] {
			t.Errorf("Packet.%s extracts from application payload but is not in appLayerAllowlist. "+
				"Add it deliberately, with a comment saying what it holds and why the rule needs it — "+
				"this list is what keeps \"no payload bytes in output\" a guarantee rather than a habit.",
				name)
		}
	}

	for _, n := range appLayerAllowlist {
		if !found[n] {
			t.Errorf("appLayerAllowlist names %s, which no longer exists on Packet; the list has "+
				"gone stale and is no longer describing what is extracted", n)
		}
	}

	if len(found) == 0 {
		t.Fatal("no application-layer fields found at all, so this test asserted nothing")
	}
}

// TestAppLayerFieldsCannotHoldPayload is the shape half of the guarantee.
//
// packetHasByteSlice already forbids a byte slice or string anywhere on
// Packet. This narrows it to the application-layer fields specifically and
// says why: a scalar can hold a count, a code or a date, and cannot hold a
// hostname, a certificate subject, or a span of someone's traffic. The
// distinction matters because those are exactly the things an application
// decoder is tempted to keep.
func TestAppLayerFieldsCannotHoldPayload(t *testing.T) {
	ty := reflect.TypeOf(Packet{})
	var checked int
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if !strings.HasPrefix(f.Name, "DNS") && !strings.HasPrefix(f.Name, "TLS") {
			continue
		}
		checked++
		switch f.Type.Kind() {
		case reflect.Bool,
			reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int:
			// A named scalar. Cannot carry payload.
		default:
			t.Errorf("Packet.%s is a %s. Application-layer fields must be scalars: anything with "+
				"a length can carry a name, a subject, or a span of payload, and this guarantee is "+
				"enforced by the shape of the struct rather than by review.", f.Name, f.Type.Kind())
		}
	}
	if checked == 0 {
		t.Fatal("no application-layer fields found, so this test asserted nothing")
	}
	t.Logf("checked %d application-layer fields, all scalar", checked)
}
