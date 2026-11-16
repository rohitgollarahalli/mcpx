package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/config"
)

// helper builds a Limiter from a config snippet.
func newTestLimiter(enabled bool, rps float64, burst int, perTool bool, toolRPS float64, toolBurst int) *Limiter {
	return New(config.RateLimitConfig{
		Enabled:   enabled,
		RPS:       rps,
		Burst:     burst,
		PerTool:   perTool,
		ToolRPS:   toolRPS,
		ToolBurst: toolBurst,
	})
}

// okHandler returns a simple 200 OK handler.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// toolCallBody builds a JSON-RPC tools/call request body.
func toolCallBody(tool string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`
}

func TestNewDisabledLimiter(t *testing.T) {
	l := newTestLimiter(false, 0, 0, false, 0, 0)
	if l.global != nil {
		t.Error("disabled limiter should have nil global limiter")
	}
}

func TestNewWithGlobalRPS(t *testing.T) {
	l := newTestLimiter(true, 10, 5, false, 0, 0)
	if l.global == nil {
		t.Fatal("expected global limiter to be created")
	}
}

func TestNewZeroRPSNoGlobal(t *testing.T) {
	l := newTestLimiter(true, 0, 0, false, 0, 0)
	if l.global != nil {
		t.Error("zero RPS should not create a global limiter")
	}
}

func TestNewBurstDefaultsToOne(t *testing.T) {
	l := newTestLimiter(true, 10, 0, false, 0, 0)
	if l.global == nil {
		t.Fatal("expected global limiter")
	}
	// burst=0 should default to 1, so first request must succeed
	if !l.global.Allow() {
		t.Error("first request should be allowed with burst defaulting to 1")
	}
}

func TestMiddlewareDisabledPassthrough(t *testing.T) {
	l := newTestLimiter(false, 10, 1, false, 0, 0)
	handler := l.Middleware()(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("disabled middleware should pass through; got %d", rec.Code)
	}
}

func TestMiddlewareGlobalRateLimitExceeded(t *testing.T) {
	// burst=1 means only one request gets through before limiting
	l := newTestLimiter(true, 1, 1, false, 0, 0)
	handler := l.Middleware()(okHandler())

	// first request: should succeed (consumes burst)
	req1 := httptest.NewRequest(http.MethodPost, "/", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request should succeed; got %d", rec1.Code)
	}

	// second request: should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429; got %d", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") != "1" {
		t.Error("expected Retry-After header")
	}
}

func TestMiddlewareGlobalAllowsBurst(t *testing.T) {
	l := newTestLimiter(true, 1, 3, false, 0, 0)
	handler := l.Middleware()(okHandler())

	// all 3 burst requests should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d should succeed within burst; got %d", i+1, rec.Code)
		}
	}

	// 4th request should be limited
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("request beyond burst should be limited; got %d", rec.Code)
	}
}

func TestMiddlewarePerToolRateLimit(t *testing.T) {
	// high global limit, low per-tool limit
	l := newTestLimiter(true, 1000, 100, true, 1, 1)
	handler := l.Middleware()(okHandler())

	body := toolCallBody("my_tool")

	// first tool call: should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first tool call should succeed; got %d", rec1.Code)
	}

	// second tool call: same tool, should be limited
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second tool call should be limited; got %d", rec2.Code)
	}
}

func TestMiddlewarePerToolDifferentToolsIndependent(t *testing.T) {
	l := newTestLimiter(true, 1000, 100, true, 1, 1)
	handler := l.Middleware()(okHandler())

	// call tool_a
	req1 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(toolCallBody("tool_a")))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("tool_a first call should succeed; got %d", rec1.Code)
	}

	// call tool_b: different tool, should also succeed
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(toolCallBody("tool_b")))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("tool_b first call should succeed independently; got %d", rec2.Code)
	}
}

func TestMiddlewarePerToolErrorResponse(t *testing.T) {
	l := newTestLimiter(true, 1000, 100, true, 1, 1)
	handler := l.Middleware()(okHandler())

	body := toolCallBody("limited_tool")

	// exhaust the tool's burst
	req1 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	// second call should return JSON-RPC error
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429; got %d", rec2.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec2.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object in response")
	}
	if code, _ := errObj["code"].(float64); code != -32000 {
		t.Errorf("expected error code -32000; got %v", code)
	}
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "limited_tool") {
		t.Errorf("error message should contain tool name; got %q", msg)
	}
}

func TestMiddlewareNonToolRequestPassesWithPerTool(t *testing.T) {
	l := newTestLimiter(true, 1000, 100, true, 1, 1)
	handler := l.Middleware()(okHandler())

	// non-tool JSON-RPC request (e.g. tools/list)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("non-tool-call request should pass; got %d", rec.Code)
	}
}

func TestGetToolLimiterUsesToolRPS(t *testing.T) {
	l := newTestLimiter(true, 100, 10, true, 5, 2)

	lim := l.getToolLimiter("test_tool")
	// first 2 should succeed (burst=2)
	if !lim.Allow() {
		t.Error("first request should be within burst")
	}
	if !lim.Allow() {
		t.Error("second request should be within burst")
	}
	// third should fail (burst exhausted)
	if lim.Allow() {
		t.Error("third request should exceed burst of 2")
	}
}

func TestGetToolLimiterFallsBackToGlobalRPS(t *testing.T) {
	// toolRPS=0 should fall back to global RPS
	l := newTestLimiter(true, 5, 2, true, 0, 0)

	lim := l.getToolLimiter("fallback_tool")
	// burst should default to max(cfg.Burst, 1) = 2
	if !lim.Allow() {
		t.Error("first should succeed")
	}
	if !lim.Allow() {
		t.Error("second should succeed within burst")
	}
	if lim.Allow() {
		t.Error("third should exceed fallback burst")
	}
}

func TestGetToolLimiterCachesInstance(t *testing.T) {
	l := newTestLimiter(true, 10, 5, true, 5, 2)

	lim1 := l.getToolLimiter("cached_tool")
	lim2 := l.getToolLimiter("cached_tool")

	if lim1 != lim2 {
		t.Error("same tool should return the same limiter instance")
	}
}

func TestBytesReaderRead(t *testing.T) {
	data := []byte("hello world")
	r := newBytesReader(data)

	buf := make([]byte, 5)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 || string(buf) != "hello" {
		t.Errorf("expected 'hello'; got %q", buf[:n])
	}

	buf2 := make([]byte, 20)
	n2, err2 := r.Read(buf2)
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if string(buf2[:n2]) != " world" {
		t.Errorf("expected ' world'; got %q", buf2[:n2])
	}
}

func TestBytesReaderEOF(t *testing.T) {
	r := newBytesReader([]byte("x"))
	buf := make([]byte, 10)
	r.Read(buf)

	_, err := r.Read(buf)
	if err.Error() != "EOF" {
		t.Errorf("expected EOF; got %v", err)
	}
}
