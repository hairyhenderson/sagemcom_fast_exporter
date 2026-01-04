package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
	"github.com/hairyhenderson/sagemcom_fast_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

//nolint:gochecknoglobals
var tracer = otel.Tracer("github.com/hairyhenderson/sagemcom_fast_exporter/cmd/sagemcom_fast_exporter")

type config struct {
	Host       string
	Username   string
	AuthMethod string
	Password   string
	Addr       string
	LogLevel   string
	Refresh    time.Duration
}

func main() {
	cfg := &config{}
	if err := parseFlags(flag.CommandLine, cfg); err != nil {
		slog.Error("parseFlags", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := run(ctx, cfg); err != nil {
		slog.ErrorContext(ctx, "exiting with error", "err", err)
		os.Exit(1)
	}
}

func parseFlags(fs *flag.FlagSet, cfg *config) error {
	fs.StringVar(&cfg.Host, "host", "192.168.2.1", "IP address or hostname of the router")
	fs.StringVar(&cfg.Username, "username", "admin", "Username to use for authentication")
	fs.StringVar(&cfg.AuthMethod, "auth-method", client.EncryptionMethodSHA512,
		"Authentication method to use (SHA512 or MD5)")
	fs.StringVar(&cfg.Password, "password", "", "Password to use for authentication")

	fs.StringVar(&cfg.Addr, "addr", "127.0.0.1:9780", "Address to listen on for web interface and telemetry.")

	fs.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	fs.DurationVar(&cfg.Refresh, "refresh", 1*time.Hour, "Session refresh interval")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	return nil
}

func run(ctx context.Context, cfg *config) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	logger := setupLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	closer, err := setupTracing(ctx, "sagemcom_fast_exporter")
	if err != nil {
		return fmt.Errorf("setupTracing: %w", err)
	}

	defer func() { _ = closer(ctx) }()

	rt := otelhttp.NewTransport(http.DefaultTransport)
	hc := &http.Client{
		Transport: rt,
	}

	scraper := client.New(cfg.Host, cfg.Username, cfg.Password, cfg.AuthMethod, hc, cfg.Refresh)

	srv := setupServer(ctx, scraper)

	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("net.Listen: %w", err)
	}

	logger.InfoContext(ctx, "listening", slog.String("addr", cfg.Addr))

	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			logger.ErrorContext(ctx, "instrumentation server terminated with error",
				slog.Any("err", err))
		}

		stop()
	}()

	<-ctx.Done()

	return nil
}

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level

	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	h := &traceLogHandler{slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
		// AddSource: true,
	})}
	l := slog.New(h)

	return l
}

func setupServer(ctx context.Context, scraper client.Scraper) *http.Server {
	router := http.NewServeMux()
	imh := promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer,
		promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		}),
	)

	router.Handle("/metrics", otelhttp.NewHandler(imh, "metrics"))
	router.Handle("/scrape", otelhttp.NewHandler(scrapeHandler(scraper), "scrape"))

	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		ReadHeaderTimeout: 1 * time.Second,
		ReadTimeout:       1 * time.Second,
		Handler:           router,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
		// ErrorLog:          errLogger,
	}

	return srv
}

func scrapeHandler(scraper client.Scraper) http.HandlerFunc {
	obs := newScrapeObserver()
	prometheus.MustRegister(obs)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "scrapeHandler")
		defer span.End()

		// logger := slog.Default().With("component", "scrapeHandler")

		slog.DebugContext(ctx, "starting scrape")

		start := time.Now()

		registry := prometheus.NewRegistry()
		collector := collector.New(ctx, scraper, obs)
		registry.MustRegister(collector)

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.InstrumentMetricHandler(
			// instrument with the default registry to report metrics on /metrics
			prometheus.DefaultRegisterer,
			promhttp.HandlerFor(registry, promhttp.HandlerOpts{
				EnableOpenMetrics: true,
			}),
		)
		h.ServeHTTP(w, r)

		duration := time.Since(start)
		// exporterDurationSummary.Observe(duration.Seconds())
		// exporterDuration.Observe(duration.Seconds())

		slog.DebugContext(ctx, "finished scrape", "duration", duration)
	}
}

type traceLogHandler struct {
	slog.Handler
}

var _ slog.Handler = (*traceLogHandler)(nil)

func (h *traceLogHandler) Handle(ctx context.Context, r slog.Record) error {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		var attrs []attribute.KeyValue

		r.Attrs(func(a slog.Attr) bool {
			attrs = append(attrs, attribute.String(a.Key, a.Value.String()))

			return true
		})

		r.Add(slog.String("traceID", span.SpanContext().TraceID().String()))

		span.AddEvent(r.Message, trace.WithAttributes(attrs...))
	}

	return h.Handler.Handle(ctx, r)
}

func (h *traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceLogHandler{h.Handler.WithAttrs(attrs)}
}

func (h *traceLogHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.Handler.Enabled(ctx, lvl)
}

func (h *traceLogHandler) WithGroup(name string) slog.Handler {
	return &traceLogHandler{h.Handler.WithGroup(name)}
}

func setupTracing(ctx context.Context, serviceName string) (closer func(context.Context) error, err error) {
	// we don't want to propagate cancellation to the trace provider, in order
	// to allow sending the last batch of spans
	ctx = context.WithoutCancel(ctx)

	logger := slog.Default().With("component", "tracing")

	var exporter sdktrace.SpanExporter

	exporter, err = autoexport.NewSpanExporter(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to init OTel exporter: %w", err)
	}

	res, err := traceResource(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// set the global tracer provider
	otel.SetTracerProvider(tp)

	// configure propagation for W3C Trace Context
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
	))

	otel.SetErrorHandler(otelErrHandler(func(err error) {
		logger.Error("OTel error", slog.Any("err", err))
	}))

	shutdown := func(ctx context.Context) error {
		// don't propagate cancellation while we shut down, but give it a 5s timeout
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		logger.Debug("trace provider shutting down")

		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown trace provider: %w", err)
		}

		logger.Debug("trace provider finished shutting down")

		return nil
	}

	return shutdown, nil
}

type otelErrHandler func(err error)

func (o otelErrHandler) Handle(err error) {
	o(err)
}

func traceResource(ctx context.Context, serviceName string) (*resource.Resource, error) {
	module := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		module = bi.Main.Path
	}

	return resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcessPID(),
		resource.WithProcessExecutableName(),
		resource.WithProcessExecutablePath(),
		resource.WithProcessOwner(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
		resource.WithProcessRuntimeDescription(),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithContainer(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version.Version),
			attribute.String("service.revision", version.Revision),
			attribute.String("module.path", module),
		),
	)
}

type instrumentedTransport struct {
	http.RoundTripper
	name string
}

var _ http.RoundTripper = (*instrumentedTransport)(nil)

func (t *instrumentedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.RoundTripper == nil {
		t.RoundTripper = http.DefaultTransport
	}

	ctx, span := tracer.Start(r.Context(), t.name, trace.WithAttributes())
	defer span.End()

	ctx = httptrace.WithClientTrace(ctx,
		otelhttptrace.NewClientTrace(ctx,
			// TODO: consider including subspans instead of events...
			otelhttptrace.WithoutSubSpans(),
		),
	)
	r = r.WithContext(ctx)

	resp, err := t.RoundTripper.RoundTrip(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	return resp, err
}
