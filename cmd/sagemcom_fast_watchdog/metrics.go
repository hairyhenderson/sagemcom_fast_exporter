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
	"github.com/prometheus/client_golang/prometheus/collectors"
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

type metrics struct {
	connectivityUp  prometheus.Gauge
	probes          *prometheus.CounterVec
	probeDuration   *prometheus.HistogramVec
	outageStart     prometheus.Gauge
	reboots         *prometheus.CounterVec
	lastReboot      prometheus.Gauge
	gaveUp          prometheus.Gauge
	wanChecks       *prometheus.CounterVec
	sessionFailures prometheus.Counter
}

// newMetrics creates the watchdog's metrics and registers them, along with
// build info and the standard Go and process collectors, on reg.
//
//nolint:funlen // one metric definition after another
func newMetrics(reg prometheus.Registerer, targets []string) *metrics {
	m := &metrics{
		connectivityUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "connectivity_up",
			Help:      "1 if the last connectivity check reached at least one probe target, 0 if not.",
		}),
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
		outageStart: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "outage_start_timestamp_seconds",
			Help:      "When the current outage began, as a Unix timestamp. 0 when connectivity is up.",
		}),
		reboots: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reboots_total",
			Help:      "Reboot attempts by the WAN state that triggered them (reason) and outcome (result).",
		}, []string{"reason", "result"}),
		lastReboot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "last_reboot_timestamp_seconds",
			Help:      "When the device was last rebooted (or a reboot was rejected) during the current outage, as a Unix timestamp. 0 if none.",
		}),
		gaveUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "gave_up",
			Help:      "1 if the watchdog has stopped rebooting until connectivity recovers, 0 otherwise.",
		}),
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
	}

	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   metricsNamespace,
		Name:        "build_info",
		Help:        "Build information. Always 1.",
		ConstLabels: prometheus.Labels{"version": version.Version, "revision": version.GitCommit},
	})
	buildInfo.Set(1)

	reg.MustRegister(
		m.connectivityUp, m.probes, m.probeDuration, m.outageStart, m.reboots,
		m.lastReboot, m.gaveUp, m.wanChecks, m.sessionFailures, buildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

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

func setTimestamp(g prometheus.Gauge, t time.Time) {
	if t.IsZero() {
		g.Set(0)

		return
	}

	g.Set(float64(t.UnixNano()) / 1e9)
}

func boolGauge(g prometheus.Gauge, v bool) {
	if v {
		g.Set(1)
	} else {
		g.Set(0)
	}
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
