package metrics

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestExpositionGolden pins the exact output: registration order, HELP/TYPE
// lines, label quoting, histogram cumulation. Scrapers parse this by spec, so
// the bytes are the contract.
func TestExpositionGolden(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("test_events_total", "Events seen.")
	c.Add(3)
	g := r.Gauge("test_in_flight", "Currently active.")
	g.Set(2)
	r.GaugeFunc("test_temperature", "Computed at scrape.", func() float64 { return 36.6 })
	v := r.CounterVec("test_decisions_total", "By decision.", "decision", "allow", "deny")
	v.With("allow").Inc()
	v.With("allow").Inc()
	v.With("deny").Inc()
	h := r.Histogram("test_duration_seconds", "How long.", []float64{0.5, 1, 5})
	h.Observe(0.4)
	h.Observe(1) // le is inclusive: lands in the le="1" bucket
	h.Observe(9) // beyond all bounds: +Inf only
	r.ConstMetric("test_build_info", "gauge", "Build.", `version="v1.2.3"`, 1)

	var sb strings.Builder
	r.WritePrometheus(&sb)
	want := `# HELP test_events_total Events seen.
# TYPE test_events_total counter
test_events_total 3
# HELP test_in_flight Currently active.
# TYPE test_in_flight gauge
test_in_flight 2
# HELP test_temperature Computed at scrape.
# TYPE test_temperature gauge
test_temperature 36.6
# HELP test_decisions_total By decision.
# TYPE test_decisions_total counter
test_decisions_total{decision="allow"} 2
test_decisions_total{decision="deny"} 1
# HELP test_duration_seconds How long.
# TYPE test_duration_seconds histogram
test_duration_seconds_bucket{le="0.5"} 1
test_duration_seconds_bucket{le="1"} 2
test_duration_seconds_bucket{le="5"} 2
test_duration_seconds_bucket{le="+Inf"} 3
test_duration_seconds_sum 10.4
test_duration_seconds_count 3
# HELP test_build_info Build.
# TYPE test_build_info gauge
test_build_info{version="v1.2.3"} 1
`
	if got := sb.String(); got != want {
		t.Errorf("exposition mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestHistogramVecAndUnknownFallback(t *testing.T) {
	r := NewRegistry()
	v := r.CounterVec("test_total", "t.", "kind", "a")
	hv := r.HistogramVec("test_seconds", "t.", []float64{1}, "kind", "a")

	// Unregistered values must not panic, must not create new series, and must
	// stay invisible until actually hit.
	var sb strings.Builder
	r.WritePrometheus(&sb)
	if strings.Contains(sb.String(), "unknown") {
		t.Errorf("unknown series exposed before any hit:\n%s", sb.String())
	}
	v.With("never-registered").Inc()
	v.With("also-never").Inc()
	hv.With("nope").Observe(0.5)
	sb.Reset()
	r.WritePrometheus(&sb)
	out := sb.String()
	if !strings.Contains(out, `test_total{kind="unknown"} 2`) {
		t.Errorf("two unregistered increments should share one unknown child:\n%s", out)
	}
	if !strings.Contains(out, `test_seconds_bucket{kind="unknown",le="1"} 1`) {
		t.Errorf("unregistered histogram observation missing from unknown child:\n%s", out)
	}
}

func TestHistogramBucketEdges(t *testing.T) {
	h := newHistogram([]float64{1, 2, 4})
	for _, v := range []float64{0.5, 1, 1.5, 2, 3, 4, 100} {
		h.Observe(v)
	}
	cum, count, sum := h.snapshot()
	// le inclusive: 0.5,1 -> le=1; +1.5,2 -> le=2; +3,4 -> le=4; 100 overflows.
	if cum[0] != 2 || cum[1] != 4 || cum[2] != 6 {
		t.Errorf("cumulative buckets = %v, want [2 4 6]", cum[:3])
	}
	if count != 7 || cum[len(cum)-1] != 7 {
		t.Errorf("count = %d, +Inf = %d, want 7", count, cum[len(cum)-1])
	}
	if want := 0.5 + 1 + 1.5 + 2 + 3 + 4 + 100; math.Abs(sum-want) > 1e-9 {
		t.Errorf("sum = %v, want %v", sum, want)
	}
	for i := 1; i < len(cum); i++ {
		if cum[i] < cum[i-1] {
			t.Errorf("cumulative buckets not monotonic: %v", cum)
		}
	}
}

// TestConcurrency drives every mutating operation from many goroutines under
// -race and checks the totals are exact — the whole point of the atomics.
func TestConcurrency(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "t.")
	g := r.Gauge("g", "t.")
	v := r.CounterVec("v_total", "t.", "k", "x", "y")
	h := r.Histogram("h_seconds", "t.", []float64{0.5, 1})

	const workers, per = 8, 1000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.Inc()
				g.Inc()
				g.Dec()
				v.With("x").Inc()
				h.Observe(0.25)
				var sb strings.Builder
				if i%100 == 0 { // scrape while writing
					r.WritePrometheus(&sb)
				}
			}
		}()
	}
	wg.Wait()
	if c.Value() != workers*per {
		t.Errorf("counter = %d, want %d", c.Value(), workers*per)
	}
	if g.Value() != 0 {
		t.Errorf("gauge = %d, want 0", g.Value())
	}
	if v.With("x").Value() != workers*per {
		t.Errorf("vec = %d, want %d", v.With("x").Value(), workers*per)
	}
	_, count, sum := h.snapshot()
	if count != workers*per {
		t.Errorf("hist count = %d, want %d", count, workers*per)
	}
	if want := 0.25 * workers * per; math.Abs(sum-want) > 1e-6 {
		t.Errorf("hist sum = %v, want %v", sum, want)
	}
}

func TestLabelEscaping(t *testing.T) {
	r := NewRegistry()
	v := r.CounterVec("e_total", "t.", "k", "a\"b\\c\nd")
	v.With("a\"b\\c\nd").Inc()
	var sb strings.Builder
	r.WritePrometheus(&sb)
	if !strings.Contains(sb.String(), `e_total{k="a\"b\\c\nd"} 1`) {
		t.Errorf("label not escaped per exposition spec:\n%s", sb.String())
	}
}

func TestGaugeFuncEvaluatedPerScrape(t *testing.T) {
	r := NewRegistry()
	n := 0.0
	r.GaugeFunc("f", "t.", func() float64 { n++; return n })
	var sb strings.Builder
	r.WritePrometheus(&sb)
	sb.Reset()
	r.WritePrometheus(&sb)
	if !strings.Contains(sb.String(), "f 2\n") {
		t.Errorf("GaugeFunc should be re-evaluated each scrape:\n%s", sb.String())
	}
}

func TestHandlerContentTypeAndMethods(t *testing.T) {
	r := NewRegistry()
	r.Counter("x_total", "t.")
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Content-Type"); got != contentType {
		t.Errorf("Content-Type = %q, want %q", got, contentType)
	}
	post, err := srv.Client().Post(srv.URL, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 405 {
		t.Errorf("POST status = %d, want 405", post.StatusCode)
	}
}

func TestWriteJSON(t *testing.T) {
	r := NewRegistry()
	r.Counter("j_total", "t.").Add(5)
	r.CounterVec("jv_total", "t.", "k", "a").With("a").Inc()
	r.Histogram("jh_seconds", "t.", []float64{1}).Observe(0.5)

	var sb strings.Builder
	if err := r.WriteJSON(&sb); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, sb.String())
	}
	if out["j_total"] != float64(5) {
		t.Errorf("j_total = %v, want 5", out["j_total"])
	}
	vec, ok := out["jv_total"].(map[string]any)
	if !ok || vec["a"] != float64(1) {
		t.Errorf("jv_total = %v, want {a: 1}", out["jv_total"])
	}
	hist, ok := out["jh_seconds"].(map[string]any)
	if !ok || hist["count"] != float64(1) || hist["sum"] != 0.5 {
		t.Errorf("jh_seconds = %v, want count 1 sum 0.5", out["jh_seconds"])
	}
}

func TestRegisterRuntime(t *testing.T) {
	r := NewRegistry()
	RegisterRuntime(r)
	var sb strings.Builder
	r.WritePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{
		"process_start_time_seconds", "go_goroutines",
		"go_memstats_alloc_bytes", "go_memstats_sys_bytes", "go_memstats_heap_objects",
		"anteroom_build_info{version=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("runtime metrics missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "go_goroutines 0\n") {
		t.Error("go_goroutines reported 0, which cannot be true of a running test")
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering the same name twice should panic")
		}
	}()
	r := NewRegistry()
	r.Counter("dup_total", "t.")
	r.Counter("dup_total", "t.")
}

// The label SET is the contract, not any particular value. A build with no
// repository in sight must still emit every key, because a scraper that sees a
// label appear or vanish sees two different series — and a build with no
// repository in sight is precisely the one whose identity is worth reporting.
func TestBuildInfoLabelSetIsComplete(t *testing.T) {
	got := buildLabels()
	for _, key := range []string{"version=", "revision=", "revision_time=", "modified=", "goversion="} {
		if !strings.Contains(got, key) {
			t.Errorf("anteroom_build_info lacks %q: %s", key, got)
		}
	}
	// Empty is worse than "unknown": it reads as a known-blank revision.
	for _, empty := range []string{`version=""`, `revision=""`, `revision_time=""`, `modified=""`} {
		if strings.Contains(got, empty) {
			t.Errorf("%s rather than a placeholder: %s", empty, got)
		}
	}
}

// The container image cannot be stamped by the toolchain — .dockerignore keeps
// .git out of the build context — so the linker flag is the only path to a
// revision for the build people actually deploy.
func TestBuildInfoHonoursLinkerRevision(t *testing.T) {
	defer func(prev string) { Revision = prev }(Revision)

	Revision = "0123456789abcdef0123456789abcdef01234567"
	if got := buildLabels(); !strings.Contains(got, `revision="`+Revision+`"`) {
		t.Errorf("-X override ignored: %s", got)
	}

	Revision = ""
	if got := buildLabels(); strings.Contains(got, `revision=""`) {
		t.Errorf("an unset override blanked the revision instead of leaving it: %s", got)
	}
}

// Same story for the version, one step removed: the toolchain has a value for
// it ("(devel)") and that value is useless, so the release workflow passes the
// published tag. This is what makes an image tag traceable to a commit through
// /metrics alone.
func TestBuildInfoHonoursLinkerVersion(t *testing.T) {
	defer func(prev string) { Version = prev }(Version)

	Version = "v1.2.3-beta.1"
	if got := buildLabels(); !strings.Contains(got, `version="`+Version+`"`) {
		t.Errorf("-X override ignored: %s", got)
	}

	Version = ""
	if got := buildLabels(); strings.Contains(got, `version=""`) {
		t.Errorf("an unset override blanked the version instead of leaving it: %s", got)
	}
}
