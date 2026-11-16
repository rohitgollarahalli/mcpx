package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/tracing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recordProvider installs a global TracerProvider backed by an in-memory span
// recorder so tests can inspect the spans Middleware produces.
func recordProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return sr
}

func findAttr(attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, a := range attrs {
		if string(a.Key) == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

func TestMiddlewareCreatesRootSpan(t *testing.T) {
	sr := recordProvider(t)

	handler := tracing.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The wrapper must support Unwrap (so http.NewResponseController can
		// reach the real writer to lift the SSE write deadline) and Flush.
		if _, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok {
			t.Error("tracing writer must implement Unwrap for http.ResponseController")
		}
		if _, ok := w.(http.Flusher); !ok {
			t.Error("tracing writer must implement Flush for streaming")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/demo", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]
	if span.Name() != "mcpx.request" {
		t.Errorf("span name = %q, want mcpx.request", span.Name())
	}
	if m, ok := findAttr(span.Attributes(), "http.request.method"); !ok || m.AsString() != http.MethodPost {
		t.Errorf("http.request.method attribute = %v (present=%v), want POST", m.AsString(), ok)
	}
	if c, ok := findAttr(span.Attributes(), "http.response.status_code"); !ok || c.AsInt64() != http.StatusOK {
		t.Errorf("http.response.status_code = %v (present=%v), want 200", c.AsInt64(), ok)
	}
	if span.Status().Code == codes.Error {
		t.Errorf("2xx response should not mark span as error")
	}
}

func TestMiddlewareMarksServerErrors(t *testing.T) {
	sr := recordProvider(t)

	handler := tracing.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp/demo", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("span status = %v, want Error for 500 response", got)
	}
}

func TestInitDisabledIsNoop(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.TracingConfig
	}{
		{"nil config", nil},
		{"disabled", &config.TracingConfig{Enabled: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shutdown, err := tracing.Init(tc.cfg, "test")
			if err != nil {
				t.Fatalf("Init returned error: %v", err)
			}
			if shutdown == nil {
				t.Fatal("Init must return a non-nil shutdown func")
			}
			if err := shutdown(context.Background()); err != nil {
				t.Errorf("no-op shutdown returned error: %v", err)
			}
		})
	}
}

func TestInitStdoutExporter(t *testing.T) {
	// The stdout exporter needs no network endpoint, so Init should succeed and
	// hand back a working shutdown.
	shutdown, err := tracing.Init(&config.TracingConfig{Enabled: true, Exporter: "stdout"}, "test")
	if err != nil {
		t.Fatalf("Init with stdout exporter failed: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}
}
