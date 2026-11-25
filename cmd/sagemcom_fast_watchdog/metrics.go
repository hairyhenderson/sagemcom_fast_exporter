package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/internal/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsNamespace = "sagemcom_fast_watchdog"

// Values of the result label on reboots_total.
const (
	rebootInitiated = "initiated"
	rebootRejected  = "rejected"
	rebootFailed    = "failed"
	rebootDryRun    = "dry_run"
)

// Values of the result label on wan_checks_total.
const (
	wanCheckUp    = "up"
	wanCheckDown  = "down"
	wanCheckError = "error"
)

// metrics holds the watchdog's counters and histogram, which are updated as
// things happen, and the descriptors for the gauges, which Collect computes
// from the watchdog's published state.
type metrics struct {
	probes          *prometheus.CounterVec
	probeDuration   *prometheus.HistogramVec
	reboots         *prometheus.CounterVec
	wanChecks       *prometheus.CounterVec
	sessionFailures prometheus.Counter

	connectivityUp *prometheus.Desc
	outageStart    *prometheus.Desc
	lastReboot     *prometheus.Desc
	gaveUp         *prometheus.Desc
	buildInfo      *prometheus.Desc
}

func newMetrics(targets []string) *metrics {
	desc := func(name, help string, constLabels prometheus.Labels) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(metricsNamespace, "", name), help, nil, constLabels)
	}

	m := &metrics{
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "probes_total",
			Help:      "Connectivity probes by target and result. Probes cancelled because another target answered first are not counted.",
		}, []string{"target", "result"}),
		probeDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "probe_duration_seconds",
			Help:      "Time taken by connectivity probes, successful or not.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"target"}),
		reboots: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reboots_total",
			Help:      "Reboot attempts by the WAN state that triggered them (reason) and outcome (result).",
		}, []string{"reason", "result"}),
		wanChecks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "wan_checks_total",
			Help:      "Checks of the WAN status the device reports, made during outages, by result.",
		}, []string{"result"}),
		sessionFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "device_session_failures_total",
			Help:      "Attempts to log in to the device (to check its WAN status or reboot it) that failed.",
		}),

		connectivityUp: desc("connectivity_up",
			"1 if the last connectivity check reached at least one probe target, 0 if not.", nil),
		outageStart: desc("outage_start_timestamp_seconds",
			"When the current outage began, as a Unix timestamp. 0 when connectivity is up.", nil),
		lastReboot: desc("last_reboot_timestamp_seconds",
			"When the device was last rebooted (or a reboot was rejected) during the current outage, as a Unix timestamp. 0 if none.", nil),
		gaveUp: desc("gave_up",
			"1 if the watchdog has stopped rebooting until connectivity recovers, 0 otherwise.", nil),
		buildInfo: desc("build_info", "Build information. Always 1.",
			prometheus.Labels{"version": version.Version, "revision": version.GitCommit}),
	}

	// initialise the series we know about so they're present (at 0) from the
	// first scrape, rather than appearing only once something happens
	for _, target := range targets {
		m.probes.WithLabelValues(target, "success")
		m.probes.WithLabelValues(target, "failure")
	}

	for _, result := range []string{wanCheckUp, wanCheckDown, wanCheckError} {
		m.wanChecks.WithLabelValues(result)
	}

	return m
}

func (m *metrics) observeProbe(target string, ok bool, d time.Duration) {
	result := "failure"
	if ok {
		result = "success"
	}

	m.probes.WithLabelValues(target, result).Inc()
	m.probeDuration.WithLabelValues(target).Observe(d.Seconds())
}

// gaugeState is the part of the watchdog's state that Collect reports. The
// loop owns the watchdog's fields and can block for minutes at a time (a
// reboot's settle delay), so rather than locking those, it copies them here
// with publish whenever they change.
type gaugeState struct {
	outageStart    time.Time
	lastReboot     time.Time
	connectivityUp bool
	gaveUp         bool
}

// publish makes the watchdog's current state visible to Collect.
func (w *watchdog) publish() {
	st := gaugeState{
		outageStart:    w.outageStart,
		lastReboot:     w.lastReboot,
		connectivityUp: w.connectivityUp,
		gaveUp:         w.gaveUpLogged,
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.published = st
}

var _ prometheus.Collector = (*watchdog)(nil)

// Describe implements [prometheus.Collector].
func (w *watchdog) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{w.m.connectivityUp, w.m.outageStart, w.m.lastReboot, w.m.gaveUp, w.m.buildInfo} {
		ch <- d
	}

	w.m.probes.Describe(ch)
	w.m.probeDuration.Describe(ch)
	w.m.reboots.Describe(ch)
	w.m.wanChecks.Describe(ch)
	w.m.sessionFailures.Describe(ch)
}

// Collect implements [prometheus.Collector].
func (w *watchdog) Collect(ch chan<- prometheus.Metric) {
	w.mu.Lock()
	st := w.published
	w.mu.Unlock()

	gauge := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}

	gauge(w.m.connectivityUp, boolFloat(st.connectivityUp))
	gauge(w.m.outageStart, timestamp(st.outageStart))
	gauge(w.m.lastReboot, timestamp(st.lastReboot))
	gauge(w.m.gaveUp, boolFloat(st.gaveUp))
	gauge(w.m.buildInfo, 1)

	w.m.probes.Collect(ch)
	w.m.probeDuration.Collect(ch)
	w.m.reboots.Collect(ch)
	w.m.wanChecks.Collect(ch)
	w.m.sessionFailures.Collect(ch)
}

// timestamp is t as Unix seconds, or 0 for the zero time.
func timestamp(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}

	return float64(t.UnixNano()) / 1e9
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}

	return 0
}

// serveMetrics serves /metrics on addr until ctx is done. A failure to listen
// is logged, not returned: rebooting the device matters more than metrics.
func serveMetrics(ctx context.Context, addr string, gatherer prometheus.Gatherer) {
	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		slog.ErrorContext(ctx, "could not listen for metrics; continuing without them",
			slog.String("addr", addr), slog.Any("err", err))

		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{EnableOpenMetrics: true}))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.InfoContext(ctx, "serving metrics", slog.String("addr", ln.Addr().String()))

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, "metrics server stopped", slog.Any("err", err))
		}
	}()
}
