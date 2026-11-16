// Package tracing provides optional OpenTelemetry (OTLP) distributed tracing
// for the mcpx gateway.
//
// When enabled it installs a global TracerProvider and a W3C trace-context
// propagator, so each request produces a root span (with child spans for policy
// evaluation and the backend call) that can join a caller's trace and continue
// into instrumented HTTP backends. When disabled — the default — the global
// provider stays a no-op and every span created here costs almost nothing, so
// the instrumentation can be left in the hot path unconditionally.
package tracing

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rohitgollarahalli/mcpx/internal/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName is the instrumentation scope reported on spans mcpx creates.
const ScopeName = "github.com/rohitgollarahalli/mcpx"

// defaultServiceName is used when tracing.service_name is unset.
const defaultServiceName = "mcpx"

// Tracer returns the mcpx tracer from the global provider. It is safe to call
// before Init: until Init installs a real provider it delegates to the no-op
// tracer, so the returned tracer's spans are cheap non-recording spans.
func Tracer() trace.Tracer {
	return otel.Tracer(ScopeName)
}

// Init configures the global OpenTelemetry TracerProvider and text-map
// propagator from cfg. It returns a shutdown function that flushes buffered
// spans; the caller must invoke it on graceful shutdown.
//
// When cfg is nil or disabled, Init is a no-op: it returns a shutdown that does
// nothing and leaves the default (no-op) provider and propagator in place.
func Init(cfg *config.TracingConfig, serviceVersion string) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if cfg == nil || !cfg.Enabled {
		return noop, nil
	}

	exp, err := newExporter(cfg)
	if err != nil {
		return noop, fmt.Errorf("tracing: building exporter: %w", err)
	}

	name := cfg.ServiceName
	if name == "" {
		name = defaultServiceName
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(name),
		semconv.ServiceVersion(serviceVersion),
	))
	if err != nil {
		return noop, fmt.Errorf("tracing: building resource: %w", err)
	}

	ratio := 1.0
	if cfg.SampleRatio != nil {
		ratio = *cfg.SampleRatio
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	// The propagator must be set explicitly: its default is a no-op, which
	// would make inbound Extract and outbound Inject silently do nothing.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

// newExporter builds the span exporter selected by cfg.Exporter. "otlp" (the
// default) exports over OTLP/HTTP — deliberately not gRPC, to keep the binary
// free of the grpc dependency.
func newExporter(cfg *config.TracingConfig) (sdktrace.SpanExporter, error) {
	switch cfg.Exporter {
	case "stdout":
		return stdouttrace.New(stdouttrace.WithPrettyPrint())
	case "", "otlp":
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
		insecure := true
		if cfg.Insecure != nil {
			insecure = *cfg.Insecure
		}
		if insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		return otlptracehttp.New(context.Background(), opts...)
	default:
		return nil, fmt.Errorf("unknown exporter %q", cfg.Exporter)
	}
}

// Middleware wraps next in a root server span per request. It extracts any
// inbound W3C trace context (so the gateway's spans join a caller's trace) and
// records the HTTP method, path, and response status. When tracing is disabled
// the span is a no-op and the overhead is negligible.
func Middleware(next http.Handler) http.Handler {
	tracer := Tracer()
	prop := otel.GetTextMapPropagator()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(ctx, "mcpx.request",
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
			),
		)
		defer span.End()

		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r.WithContext(ctx))

		span.SetAttributes(semconv.HTTPResponseStatusCode(rw.status))
		if rw.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(rw.status))
		}
	})
}

// Annotate records mcpx routing attributes (server, method, tool, client) on
// the request's root span. It is a no-op when the span is not recording, so it
// costs nothing when tracing is disabled.
func Annotate(ctx context.Context, server, method, tool, client string) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("mcpx.server", server)}
	if method != "" {
		attrs = append(attrs, attribute.String("mcpx.method", method))
	}
	if tool != "" {
		attrs = append(attrs, attribute.String("mcpx.tool", tool))
	}
	if client != "" {
		attrs = append(attrs, attribute.String("mcpx.client", client))
	}
	span.SetAttributes(attrs...)
}

// MarkDenied marks the span in ctx as a denied request: it sets
// mcpx.decision=deny and an error status carrying the policy reason.
func MarkDenied(ctx context.Context, reason string) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(attribute.String("mcpx.decision", "deny"))
	span.SetStatus(codes.Error, reason)
}

// MarkStreaming flags the span in ctx as serving a long-lived stream (SSE),
// adding a timestamped stream.start event. The span still ends when the stream
// closes, so export is delayed until then.
func MarkStreaming(ctx context.Context) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(attribute.Bool("mcpx.streaming", true))
	span.AddEvent("stream.start")
}

// InjectHeaders writes the trace context from ctx into h so a downstream HTTP
// backend can continue the trace. It is a no-op when tracing is disabled (the
// no-op propagator writes nothing).
func InjectHeaders(ctx context.Context, h http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(h))
}

// statusRecorder wraps an http.ResponseWriter to capture the response status
// for the span. It stays transparent to streaming and to
// http.ResponseController: Flush delegates so SSE events reach the client
// immediately, and Unwrap lets http.NewResponseController reach the underlying
// writer (mcpx lifts the write deadline for SSE through this chain — without
// Unwrap that call would silently fail and long streams would be cut off at the
// server write timeout). It mirrors the responseWriter in cmd/mcpx/main.go.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
