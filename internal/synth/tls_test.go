package synth

import (
	"bytes"
	"testing"
	"time"
)

// TestFixtureCertIsDeterministic guards the property the whole committed
// fixture suite rests on. A certificate built from real randomness would
// produce different bytes on every regeneration, so every golden touching one
// would churn for no reason and no committed fixture could be reproduced.
//
// The second half matters as much as the first: identical bytes for different
// expiry dates would mean the date never reached the certificate, and R12
// would be reading a constant.
func TestFixtureCertIsDeterministic(t *testing.T) {
	exp := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a := TLSCertificate(exp)
	b := TLSCertificate(exp)
	if !bytes.Equal(a, b) {
		t.Fatal("the same expiry produced different certificate bytes; fixtures would churn on " +
			"every regeneration and could not be reproduced")
	}
	c := TLSCertificate(exp.Add(24 * time.Hour))
	if bytes.Equal(a, c) {
		t.Fatal("a different expiry produced identical bytes, so the date is not reaching the cert")
	}
	t.Logf("certificate record: %d bytes, stable across calls", len(a))
}
