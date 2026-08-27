package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// contentType is the Prometheus text exposition format, version 0.0.4 — what
// every scraper (Prometheus, Alloy, VictoriaMetrics, the OTel collector's
// prometheus receiver) negotiates by default.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// WritePrometheus writes every family in registration order.
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.Lock()
	fams := append([]*family(nil), r.families...)
	r.mu.Unlock()
	for _, f := range fams {
		fmt.Fprintf(w, "# HELP %s %s\n", f.name, escapeHelp(f.help))
		fmt.Fprintf(w, "# TYPE %s %s\n", f.name, f.typ)
		f.write(w)
	}
}

// Handler serves the exposition on GET/HEAD.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", contentType)
		r.WritePrometheus(w)
	})
}

// WriteJSON writes the same snapshot as one JSON object keyed by family name:
// counters and gauges as numbers, vectors as {label-value: number}, histograms
// as {count, sum, buckets: {le: cumulative-count}}. For humans and scripts;
// scrapers should use the Prometheus form.
func (r *Registry) WriteJSON(w io.Writer) error {
	r.mu.Lock()
	fams := append([]*family(nil), r.families...)
	r.mu.Unlock()
	out := make(map[string]any, len(fams))
	for _, f := range fams {
		out[f.name] = f.jsonValue()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// write emits one family's sample lines.
func (f *family) write(w io.Writer) {
	switch {
	case f.counter != nil:
		fmt.Fprintf(w, "%s %d\n", f.name, f.counter.Value())
	case f.gauge != nil:
		fmt.Fprintf(w, "%s %d\n", f.name, f.gauge.Value())
	case f.gaugeFn != nil:
		fmt.Fprintf(w, "%s %s\n", f.name, formatFloat(f.gaugeFn()))
	case f.isConst:
		if f.constLbls != "" {
			fmt.Fprintf(w, "%s{%s} %s\n", f.name, f.constLbls, formatFloat(f.constVal))
		} else {
			fmt.Fprintf(w, "%s %s\n", f.name, formatFloat(f.constVal))
		}
	case f.counterVec != nil:
		v := f.counterVec
		for _, val := range v.order {
			fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", f.name, v.label, EscapeLabel(val), v.children[val].Value())
		}
		// The unknown child appears only once something actually landed in it,
		// so a clean deployment exposes no series nobody registered.
		if n := v.unknown.Value(); n > 0 {
			fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", f.name, v.label, unknownLabel, n)
		}
	case f.histogram != nil:
		writeHistogram(w, f.name, "", f.histogram)
	case f.histVec != nil:
		v := f.histVec
		for _, val := range v.order {
			writeHistogram(w, f.name, fmt.Sprintf("%s=\"%s\",", v.label, EscapeLabel(val)), v.children[val])
		}
		if v.unknown.count.Load() > 0 {
			writeHistogram(w, f.name, fmt.Sprintf("%s=\"%s\",", v.label, unknownLabel), v.unknown)
		}
	}
}

// writeHistogram emits the cumulative bucket series, _sum, and _count.
// labelPrefix is either empty or `name="value",` — the trailing comma composes
// with the le label.
func writeHistogram(w io.Writer, name, labelPrefix string, h *Histogram) {
	cum, count, sum := h.snapshot()
	for i, bound := range h.bounds {
		fmt.Fprintf(w, "%s_bucket{%sle=\"%s\"} %d\n", name, labelPrefix, formatFloat(bound), cum[i])
	}
	fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", name, labelPrefix, count)
	lbls := strings.TrimSuffix(labelPrefix, ",")
	if lbls != "" {
		fmt.Fprintf(w, "%s_sum{%s} %s\n", name, lbls, formatFloat(sum))
		fmt.Fprintf(w, "%s_count{%s} %d\n", name, lbls, count)
	} else {
		fmt.Fprintf(w, "%s_sum %s\n", name, formatFloat(sum))
		fmt.Fprintf(w, "%s_count %d\n", name, count)
	}
}

func (f *family) jsonValue() any {
	switch {
	case f.counter != nil:
		return f.counter.Value()
	case f.gauge != nil:
		return f.gauge.Value()
	case f.gaugeFn != nil:
		return f.gaugeFn()
	case f.isConst:
		if f.constLbls != "" {
			return map[string]any{"labels": f.constLbls, "value": f.constVal}
		}
		return f.constVal
	case f.counterVec != nil:
		m := make(map[string]uint64, len(f.counterVec.order)+1)
		for _, val := range f.counterVec.order {
			m[val] = f.counterVec.children[val].Value()
		}
		if n := f.counterVec.unknown.Value(); n > 0 {
			m[unknownLabel] = n
		}
		return m
	case f.histogram != nil:
		return histogramJSON(f.histogram)
	case f.histVec != nil:
		m := make(map[string]any, len(f.histVec.order)+1)
		for _, val := range f.histVec.order {
			m[val] = histogramJSON(f.histVec.children[val])
		}
		if f.histVec.unknown.count.Load() > 0 {
			m[unknownLabel] = histogramJSON(f.histVec.unknown)
		}
		return m
	}
	return nil
}

func histogramJSON(h *Histogram) any {
	cum, count, sum := h.snapshot()
	buckets := make(map[string]uint64, len(h.bounds)+1)
	for i, bound := range h.bounds {
		buckets[formatFloat(bound)] = cum[i]
	}
	buckets["+Inf"] = count
	return map[string]any{"count": count, "sum": sum, "buckets": buckets}
}

// formatFloat is the exposition float form: shortest round-trip, +Inf spelled
// the Prometheus way.
func formatFloat(v float64) string {
	if math.IsInf(v, +1) {
		return "+Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// EscapeLabel escapes a label VALUE per the exposition format. Every value
// this package emits today is a compile-time identifier, but the writer must
// be correct in isolation.
func EscapeLabel(s string) string {
	return labelEscaper.Replace(s)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeHelp(s string) string {
	return helpEscaper.Replace(s)
}

var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

// startTime approximates process start closely enough for
// process_start_time_seconds, whose job is letting a scraper compute uptime
// and detect restarts.
var startTime = time.Now()

// memCache shares one ReadMemStats (a stop-the-world pause) across the several
// memstats gauges of a single scrape. One second of staleness is invisible at
// scrape intervals of 15-60s.
type memCache struct {
	mu sync.Mutex
	at time.Time
	ms runtime.MemStats
}

func (m *memCache) get() runtime.MemStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at.IsZero() || time.Since(m.at) > time.Second {
		runtime.ReadMemStats(&m.ms)
		m.at = time.Now()
	}
	return m.ms
}

// RegisterRuntime adds the process- and Go-runtime families every scraper
// expects: start time (restart detection), goroutines, memory, build info.
// Called once by the admin server, not by the gate — request-path code stays
// ignorant of runtime introspection.
func RegisterRuntime(r *Registry) {
	r.GaugeFunc("process_start_time_seconds",
		"Unix time the process started, for uptime and restart detection.",
		func() float64 { return float64(startTime.UnixNano()) / 1e9 })
	r.GaugeFunc("go_goroutines",
		"Number of goroutines that currently exist.",
		func() float64 { return float64(runtime.NumGoroutine()) })
	mc := &memCache{}
	r.GaugeFunc("go_memstats_alloc_bytes",
		"Bytes of allocated heap objects.",
		func() float64 { return float64(mc.get().HeapAlloc) })
	r.GaugeFunc("go_memstats_sys_bytes",
		"Bytes of memory obtained from the OS.",
		func() float64 { return float64(mc.get().Sys) })
	r.GaugeFunc("go_memstats_heap_objects",
		"Number of allocated heap objects.",
		func() float64 { return float64(mc.get().HeapObjects) })

	r.ConstMetric("anteroom_build_info", "gauge",
		"Build information. Constant 1; the interesting parts are the labels.",
		buildLabels(), 1)
}

// Revision overrides the commit the Go toolchain stamps into the binary. Set it
// at link time:
//
//	-ldflags "-X github.com/radiustechsystems/anteroom/internal/metrics.Revision=$(git rev-parse HEAD)"
//
// It exists for builds that cannot see a repository. The container image
// excludes .git from its build context deliberately (.dockerignore: anything
// reachable there can end up in an intermediate layer), so the automatic stamp
// is unavailable in the one build people actually deploy, and would stay
// unavailable forever without a way to pass it in.
var Revision string

// Version overrides the module version the Go toolchain stamps into the binary,
// set the same way at link time:
//
//	-ldflags "-X <module>/internal/metrics.Version=v1.2.3"
//
// It exists for the release image. Main.Version is "(devel)" unless the binary
// was installed as module@version, so a `go build` — which is how every image is
// built — has no version to report even when one exists: the tag it was
// published under. The release workflow passes that tag verbatim, so
// `version="v1.2.3"` on a running gate is a string that can be checked out.
//
// A version still does not identify a build; see buildLabels. This narrows the
// gap between an image tag and the code inside it, and nothing more.
var Version string

// buildLabels assembles the anteroom_build_info label set.
//
// A version does not identify a build. Main.Version is "(devel)" for anything
// not installed as module@version, which is every binary built from a checkout
// — so an operator reading version="(devel)" off a running gate cannot answer
// "which code is this?", and that is the question that decides whether a given
// fix is deployed. The toolchain already records the answer as VCS build
// settings; nothing was reading them.
//
// Every label is emitted unconditionally, "unknown" where the value is missing.
// A series whose label SET varies between builds is a different series to a
// scraper, so a dashboard or alert joining on anteroom_build_info would stop
// matching the moment someone built without a repository — which is exactly the
// build whose identity is least obvious and most worth reporting.
func buildLabels() string {
	version, revision, revTime, modified := "unknown", "unknown", "unknown", "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" {
			version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				revTime = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
	}
	// The linker flag wins: it is only ever set by a build that knows the stamp
	// is missing, and "unknown" is the value it is replacing.
	if Revision != "" {
		revision = Revision
	}
	if Version != "" {
		version = Version
	}
	// Keep the full hash so the revision remains unambiguous as history grows.
	return fmt.Sprintf("version=\"%s\",revision=\"%s\",revision_time=\"%s\",modified=\"%s\",goversion=\"%s\"",
		EscapeLabel(version), EscapeLabel(revision), EscapeLabel(revTime),
		EscapeLabel(modified), EscapeLabel(runtime.Version()))
}
