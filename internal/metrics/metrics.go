// Package metrics is Anteroom's own minimal metrics registry with Prometheus
// text exposition. Hand-rolled on purpose: the exposition format is small
// enough that a correct writer costs less than a client library's transitive
// tree.
//
// The model is deliberately the old SNMP one, which is also the Prometheus
// one: monotonic counters that start at zero when the process starts and only
// go up. The scraper computes rates and detects restarts (via
// process_start_time_seconds); the gate's cost per event is a single atomic
// add.
//
// Constraints that keep this package small and the hot path cheap:
//   - Registration happens at startup only; scraping never allocates series.
//   - Vectors carry exactly one label, and every label value is pre-registered
//     at construction. With() on an unregistered value returns a shared
//     "unknown" child rather than growing the series set — a typo'd or future
//     decision string can never panic the gate or leak unbounded cardinality.
//   - Histograms have fixed buckets, Prometheus semantics: `le` is inclusive,
//     buckets are exposed cumulatively, +Inf equals _count.
//
// Consistency note: a histogram's _sum, _count, and buckets are each atomic
// but are not read under a common lock, so a scrape racing an Observe can see
// them differ by one observation. Prometheus tolerates this; a mutex on the
// request path would be the wrong trade.
package metrics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing value.
type Counter struct {
	v atomic.Uint64
}

func (c *Counter) Inc()          { c.v.Add(1) }
func (c *Counter) Add(n uint64)  { c.v.Add(n) }
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a value that can go up and down.
type Gauge struct {
	v atomic.Int64
}

func (g *Gauge) Inc()         { g.v.Add(1) }
func (g *Gauge) Dec()         { g.v.Add(-1) }
func (g *Gauge) Set(v int64)  { g.v.Store(v) }
func (g *Gauge) Value() int64 { return g.v.Load() }

// Histogram is a fixed-bucket cumulative histogram.
type Histogram struct {
	bounds []float64       // upper bounds, ascending; +Inf is implicit
	counts []atomic.Uint64 // len(bounds)+1; last is the +Inf overflow
	sum    atomic.Uint64   // math.Float64bits, updated by CAS
	count  atomic.Uint64
}

func newHistogram(buckets []float64) *Histogram {
	b := make([]float64, len(buckets))
	copy(b, buckets)
	sort.Float64s(b)
	return &Histogram{bounds: b, counts: make([]atomic.Uint64, len(b)+1)}
}

// Observe records one value. `le` is inclusive, per Prometheus: a value equal
// to a bound lands in that bound's bucket.
func (h *Histogram) Observe(v float64) {
	i := sort.SearchFloat64s(h.bounds, v) // first bound >= v, len(bounds) if none
	h.counts[i].Add(1)
	h.count.Add(1)
	for {
		old := h.sum.Load()
		next := math.Float64bits(math.Float64frombits(old) + v)
		if h.sum.CompareAndSwap(old, next) {
			return
		}
	}
}

// snapshot returns cumulative bucket counts (one per bound, then +Inf), the
// total count, and the sum.
func (h *Histogram) snapshot() (cum []uint64, count uint64, sum float64) {
	cum = make([]uint64, len(h.bounds)+1)
	var running uint64
	for i := range h.counts {
		running += h.counts[i].Load()
		cum[i] = running
	}
	return cum, h.count.Load(), math.Float64frombits(h.sum.Load())
}

// unknownLabel is where With() sends values nobody registered. It shows up in
// the output only once it has actually been hit, so a clean deployment never
// exposes it, and a miscounted one exposes exactly one extra series.
const unknownLabel = "unknown"

// CounterVec is a family of counters distinguished by one label whose values
// are fixed at construction.
type CounterVec struct {
	label    string
	order    []string
	children map[string]*Counter
	unknown  *Counter
}

// With returns the child for a pre-registered label value, or the shared
// "unknown" child for anything else. Never nil, never allocates.
func (v *CounterVec) With(value string) *Counter {
	if c, ok := v.children[value]; ok {
		return c
	}
	return v.unknown
}

// HistogramVec is a family of histograms distinguished by one label whose
// values are fixed at construction.
type HistogramVec struct {
	label    string
	order    []string
	children map[string]*Histogram
	unknown  *Histogram
}

func (v *HistogramVec) With(value string) *Histogram {
	if h, ok := v.children[value]; ok {
		return h
	}
	return v.unknown
}

// family is one exposition family: HELP, TYPE, and however many samples its
// kind produces at scrape time.
type family struct {
	name string
	typ  string // "counter", "gauge", "histogram"
	help string

	counter    *Counter
	gauge      *Gauge
	gaugeFn    func() float64
	histogram  *Histogram
	counterVec *CounterVec
	histVec    *HistogramVec
	constVal   float64
	constLbls  string // preformatted `k="v",k2="v2"` pairs, already escaped
	isConst    bool
}

// Registry holds families in registration order, which makes the exposition
// output deterministic — exact-string golden tests depend on that.
type Registry struct {
	mu       sync.Mutex
	families []*family
	names    map[string]bool
}

func NewRegistry() *Registry {
	return &Registry{names: map[string]bool{}}
}

func (r *Registry) add(f *family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[f.name] {
		// Registration is startup-only and programmer-controlled; a duplicate
		// is a bug that must not silently split one family in two.
		panic(fmt.Sprintf("metrics: %q registered twice", f.name))
	}
	r.names[f.name] = true
	r.families = append(r.families, f)
}

// Counter registers and returns a plain counter.
func (r *Registry) Counter(name, help string) *Counter {
	c := &Counter{}
	r.add(&family{name: name, typ: "counter", help: help, counter: c})
	return c
}

// CounterVec registers a one-label counter family with a fixed value set.
func (r *Registry) CounterVec(name, help, label string, values ...string) *CounterVec {
	v := &CounterVec{
		label:    label,
		order:    append([]string(nil), values...),
		children: make(map[string]*Counter, len(values)),
		unknown:  &Counter{},
	}
	for _, val := range values {
		v.children[val] = &Counter{}
	}
	r.add(&family{name: name, typ: "counter", help: help, counterVec: v})
	return v
}

// Gauge registers and returns a settable gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	g := &Gauge{}
	r.add(&family{name: name, typ: "gauge", help: help, gauge: g})
	return g
}

// GaugeFunc registers a gauge whose value is computed at each scrape.
func (r *Registry) GaugeFunc(name, help string, fn func() float64) {
	r.add(&family{name: name, typ: "gauge", help: help, gaugeFn: fn})
}

// Histogram registers a fixed-bucket histogram. Bounds are sorted; +Inf is
// implicit and must not be passed.
func (r *Registry) Histogram(name, help string, buckets []float64) *Histogram {
	h := newHistogram(buckets)
	r.add(&family{name: name, typ: "histogram", help: help, histogram: h})
	return h
}

// HistogramVec registers a one-label histogram family with a fixed value set.
func (r *Registry) HistogramVec(name, help string, buckets []float64, label string, values ...string) *HistogramVec {
	v := &HistogramVec{
		label:    label,
		order:    append([]string(nil), values...),
		children: make(map[string]*Histogram, len(values)),
		unknown:  newHistogram(buckets),
	}
	for _, val := range values {
		v.children[val] = newHistogram(buckets)
	}
	r.add(&family{name: name, typ: "histogram", help: help, histVec: v})
	return v
}

// ConstMetric registers a fixed-value sample, e.g. build info. labels are
// preformatted `k="v",k2="v2"` pairs; the caller escapes values (EscapeLabel).
func (r *Registry) ConstMetric(name, typ, help, labels string, value float64) {
	r.add(&family{name: name, typ: typ, help: help, isConst: true, constLbls: labels, constVal: value})
}
