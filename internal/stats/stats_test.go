package stats

import (
	"math"
	"testing"
)

// TestNearestRank pins the percentile method. It is nearest-rank rather than
// an interpolating method so every reported figure is a value that was
// actually observed, and therefore a value the reader can go and find in a
// frame.
func TestNearestRank(t *testing.T) {
	five := []float64{1, 2, 3, 4, 5}
	cases := []struct {
		sorted []float64
		p      float64
		want   float64
	}{
		{five, 0.5, 3},
		{five, 0.95, 5},
		{five, 1.0, 5},
		{five, 0.01, 1},
		{[]float64{1}, 0.95, 1},
		{nil, 0.5, 0},
	}
	for _, c := range cases {
		if got := NearestRank(c.sorted, c.p); got != c.want {
			t.Errorf("NearestRank(%v, %v) = %v, want %v", c.sorted, c.p, got, c.want)
		}
	}

	// Twenty samples: p95 by nearest rank is the second largest, which is what
	// makes RULES.md's example figures reproducible in the R04 fixture.
	twenty := make([]float64, 20)
	for i := range twenty {
		twenty[i] = float64(i + 1)
	}
	if got := NearestRank(twenty, 0.95); got != 19 {
		t.Errorf("p95 of 1..20 = %v, want 19", got)
	}
}

// TestMedianWithZeros checks the comparative baseline. A condition present on
// a handful of flows in a capture full of clean ones must compare against the
// clean ones, otherwise the only flows in the population are the faulty ones
// and every fault looks normal.
func TestMedianWithZeros(t *testing.T) {
	cases := []struct {
		vs    []float64
		total int
		want  float64
	}{
		// Three stalling flows among thirteen: the median flow is clean.
		{[]float64{4.2, 1.5, 0.6}, 13, 0},
		// Every flow stalling by a similar amount is background, not a finding.
		{[]float64{1, 1, 1, 1, 1}, 5, 1},
		{[]float64{1, 2, 3}, 3, 2},
		{nil, 10, 0},
		{[]float64{5}, 0, 5},
	}
	for _, c := range cases {
		if got := MedianWithZeros(c.vs, c.total); got != c.want {
			t.Errorf("MedianWithZeros(%v, %d) = %v, want %v", c.vs, c.total, got, c.want)
		}
	}
}

// TestSamplerIsDeterministic is the determinism requirement applied to the
// place it is most easily lost. The sampler decimates rather than
// reservoir-sampling precisely so that no random source is involved.
func TestSamplerIsDeterministic(t *testing.T) {
	build := func() *Sampler {
		var s Sampler
		for i := 0; i < MaxSamples*4; i++ {
			s.Add(float64((i*7919)%10007) / 1000)
		}
		return &s
	}

	first := build()
	for run := 0; run < 8; run++ {
		again := build()
		for _, p := range []float64{0.5, 0.95, 1.0} {
			if a, b := first.Percentile(p), again.Percentile(p); a != b {
				t.Fatalf("run %d: p%v = %v, first run gave %v", run, p, b, a)
			}
		}
		if first.Count() != again.Count() {
			t.Fatalf("run %d: Count = %d, first run gave %d", run, again.Count(), first.Count())
		}
	}
}

// TestSamplerStaysBounded is the memory promise: a server answering millions
// of requests must not accumulate a sample per request.
func TestSamplerStaysBounded(t *testing.T) {
	var s Sampler
	for i := 0; i < MaxSamples*10; i++ {
		s.Add(float64(i))
		if len(s.values) > MaxSamples {
			t.Fatalf("sampler holds %d values after %d observations, cap is %d",
				len(s.values), i+1, MaxSamples)
		}
	}
	if s.Count() != uint64(MaxSamples*10) {
		t.Errorf("Count = %d, want %d — the full count must survive decimation", s.Count(), MaxSamples*10)
	}
	if !s.Decimated() {
		t.Error("Decimated = false; percentiles from a decimated sample must be declared as such")
	}
}

// TestSamplerDecimationStaysRepresentative checks that decimation keeps a
// sample spread across the whole stream rather than biasing to the start,
// which is what keeping the first N would do.
func TestSamplerDecimationStaysRepresentative(t *testing.T) {
	var s Sampler
	const n = MaxSamples * 8
	for i := 0; i < n; i++ {
		s.Add(float64(i))
	}

	// With a uniform 0..n-1 stream, the median of the retained sample should
	// land near the middle of the range.
	median := s.Percentile(0.5)
	want := float64(n) / 2
	if math.Abs(median-want) > float64(n)*0.05 {
		t.Errorf("median of a uniform 0..%d stream = %v, want near %v — decimation is biased", n-1, median, want)
	}
	if got := s.Max(); got < float64(n)*0.9 {
		t.Errorf("Max = %v after a 0..%d stream; the tail was dropped", got, n-1)
	}
}
