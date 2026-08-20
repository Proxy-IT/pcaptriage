// Package stats provides the percentile and sampling primitives the rules
// share.
//
// Everything here is deterministic. The sampler decimates rather than
// reservoir-samples, so no random source is involved and the same input always
// produces the same percentiles.
package stats

import (
	"math"
	"sort"
)

// MaxSamples bounds the values a Sampler retains per subject. Beyond this the
// sampler decimates, keeping a uniform sample across the whole stream rather
// than the first N, which would bias percentiles toward the start of the
// capture.
const MaxSamples = 16384

// Sampler collects float64 observations under a memory bound.
type Sampler struct {
	values []float64
	count  uint64

	// stride is how many observations one retained sample stands for. It
	// doubles each time the buffer fills.
	stride uint64
	// pending counts observations seen since the last one was retained.
	pending uint64
}

// Add records an observation.
func (s *Sampler) Add(v float64) {
	s.count++
	if s.stride == 0 {
		s.stride = 1
	}

	s.pending++
	if s.pending < s.stride {
		return
	}
	s.pending = 0

	s.values = append(s.values, v)
	if len(s.values) >= MaxSamples {
		s.decimate()
	}
}

// decimate halves the retained set by keeping every second value and doubles
// the stride, so the sample stays uniform over everything seen so far.
func (s *Sampler) decimate() {
	keep := s.values[:0]
	for i := 0; i < len(s.values); i += 2 {
		keep = append(keep, s.values[i])
	}
	s.values = keep
	s.stride *= 2
}

// Count reports how many observations were added, including those not
// retained.
func (s *Sampler) Count() uint64 { return s.count }

// Decimated reports whether percentiles are computed from a decimated sample
// rather than every observation.
func (s *Sampler) Decimated() bool { return s.stride > 1 }

// Percentile returns the value at percentile p (0 < p <= 1) using the
// nearest-rank method on the sorted sample: index = ceil(p*n) - 1.
//
// Nearest-rank is used rather than an interpolating method because it always
// returns an observed value, which keeps the reported figure something the
// user can go and find in a frame.
func (s *Sampler) Percentile(p float64) float64 {
	if len(s.values) == 0 {
		return 0
	}
	sorted := s.sorted()
	return NearestRank(sorted, p)
}

// Min returns the smallest retained value.
//
// Paired with Max so a caller can describe the spread of a sample without
// reaching for percentiles, which is what a check reporting whether a
// measurement was steady or variable actually needs.
func (s *Sampler) Min() float64 {
	if len(s.values) == 0 {
		return 0
	}
	m := s.values[0]
	for _, v := range s.values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// Max returns the largest retained value.
func (s *Sampler) Max() float64 {
	if len(s.values) == 0 {
		return 0
	}
	m := s.values[0]
	for _, v := range s.values[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func (s *Sampler) sorted() []float64 {
	out := make([]float64, len(s.values))
	copy(out, s.values)
	sort.Float64s(out)
	return out
}

// NearestRank returns the p-th percentile of an already sorted slice.
func NearestRank(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// Median returns the median of vs. vs is not modified.
func Median(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	sorted := make([]float64, len(vs))
	copy(sorted, vs)
	sort.Float64s(sorted)
	return NearestRank(sorted, 0.5)
}

// MedianWithZeros returns the median of a population of size total in which
// only vs are non-zero and the remainder are zero.
//
// Rules use this so their comparative baseline includes the peers that are
// clean. A condition present on one flow while forty are clean should deviate
// strongly from the population; a condition present on all of them is
// background.
func MedianWithZeros(vs []float64, total int) float64 {
	// A caller that understates the population cannot be allowed to shrink it
	// below the values it already supplied, or the non-zero observations would
	// be discarded in favour of zeros that do not exist.
	if len(vs) > total {
		total = len(vs)
	}
	if total <= 0 {
		return 0
	}
	zeros := total - len(vs)

	idx := int(math.Ceil(0.5*float64(total))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx < zeros {
		return 0
	}

	sorted := make([]float64, len(vs))
	copy(sorted, vs)
	sort.Float64s(sorted)
	return sorted[idx-zeros]
}
