package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/audit"
	"github.com/rohitgollarahalli/mcpx/internal/breaker"
	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/integrity"
	"github.com/rohitgollarahalli/mcpx/internal/metrics"
	"github.com/rohitgollarahalli/mcpx/internal/policy"
	"github.com/rohitgollarahalli/mcpx/internal/proxy"
)

func breakerGateway(t *testing.T, url string, cfg breaker.Config) (*proxy.Gateway, *metrics.Collector) {
	t.Helper()
	c := &config.Config{Servers: []config.ServerConfig{{Name: "up", URL: url, Transport: "http"}}}
	al, _ := audit.New(config.AuditConfig{})
	mc := metrics.New()
	bm := breaker.NewManager(cfg, true)
	gw, err := proxy.New(c, policy.New(c.Servers, nil), al, integrity.NewStore(integrity.ModeOff), bm, nil, mc, nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return gw, mc
}

func callOnce(gw *proxy.Gateway) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

// TestGateway_BreakerOpensOn5xx: repeated 5xx responses open the breaker;
// the next request gets an instant 503 without touching the backend.
func TestGateway_BreakerOpensOn5xx(t *testing.T) {
	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(backend.Close)

	gw, mc := breakerGateway(t, backend.URL, breaker.Config{FailureThreshold: 3})

	for i := 0; i < 3; i++ {
		if rec := callOnce(gw); rec.Code != http.StatusInternalServerError {
			t.Fatalf("request %d: status = %d, want 500 passed through", i+1, rec.Code)
		}
	}
	if hits != 3 {
		t.Fatalf("backend hits = %d, want 3", hits)
	}

	// Breaker is now open: request must fail fast as a JSON-RPC error and
	// never reach the backend.
	rec := callOnce(gw)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 from open breaker", rec.Code)
	}
	if hits != 3 {
		t.Fatalf("backend hits = %d after breaker opened, want still 3", hits)
	}
	if body := rec.Body.String(); !strings.Contains(body, "circuit open") || !strings.Contains(body, "jsonrpc") {
		t.Errorf("expected JSON-RPC circuit-open error, got %s", body)
	}

	// Trip metric recorded.
	mrec := httptest.NewRecorder()
	mc.Handler()(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := mrec.Body.String()
	if !strings.Contains(out, "mcpx_breaker_trips_total 1") {
		t.Errorf("expected one breaker trip in metrics:\n%s", out)
	}
	if !strings.Contains(out, `mcpx_breaker_state{server="up"} 1`) {
		t.Errorf("expected open breaker state in metrics:\n%s", out)
	}
}

// TestGateway_BreakerCountsTransportErrors: a dead backend (connection
// refused) trips the breaker via the proxy ErrorHandler path.
func TestGateway_BreakerCountsTransportErrors(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close() // closed immediately: connections will be refused

	gw, _ := breakerGateway(t, dead.URL, breaker.Config{FailureThreshold: 2})

	for i := 0; i < 2; i++ {
		if rec := callOnce(gw); rec.Code != http.StatusBadGateway {
			t.Fatalf("request %d: status = %d, want 502", i+1, rec.Code)
		}
	}
	if rec := callOnce(gw); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 after transport errors tripped breaker", rec.Code)
	}
}

// TestGateway_BreakerRecoversOnSuccess: success resets the failure streak,
// so intermittent failures below the threshold never open the breaker.
func TestGateway_BreakerRecoversOnSuccess(t *testing.T) {
	var fail bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(backend.Close)

	gw, _ := breakerGateway(t, backend.URL, breaker.Config{FailureThreshold: 2})

	fail = true
	callOnce(gw) // one failure
	fail = false
	callOnce(gw) // success resets the streak
	fail = true
	callOnce(gw) // one failure again — still under threshold

	if rec := callOnce(gw); rec.Code == http.StatusServiceUnavailable {
		t.Fatal("breaker must not open on non-consecutive failures")
	}
}
