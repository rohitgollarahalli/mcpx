package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/audit"
	"github.com/rohitgollarahalli/mcpx/internal/auth"
	"github.com/rohitgollarahalli/mcpx/internal/cache"
	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/integrity"
	"github.com/rohitgollarahalli/mcpx/internal/metrics"
	"github.com/rohitgollarahalli/mcpx/internal/policy"
	"github.com/rohitgollarahalli/mcpx/internal/proxy"
	"github.com/rohitgollarahalli/mcpx/internal/stdio"
)

// countingUpstream is an MCP backend that counts the calls it receives and
// answers with the body handler returns for that call number.
type countingUpstream struct {
	*httptest.Server
	calls atomic.Int64
}

func newCountingUpstream(t *testing.T, reply func(call int64, req []byte) (contentType, body string)) *countingUpstream {
	t.Helper()
	up := &countingUpstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := up.calls.Add(1)
		buf := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			_, _ = r.Body.Read(buf)
		}
		ct, body := reply(n, buf)
		w.Header().Set("Content-Type", ct)
		w.Write([]byte(body))
	}))
	t.Cleanup(up.Close)
	return up
}

// okResult answers every call with the same successful tools/call result.
func okResult(text string) func(int64, []byte) (string, string) {
	return func(n int64, _ []byte) (string, string) {
		return "application/json", fmt.Sprintf(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}],"call":%d}}`, text, n)
	}
}

// cachingGateway builds a gateway whose "up" server caches the named tools,
// returning the gateway and the shared store so tests can inspect it.
func cachingGateway(t *testing.T, url string, cacheCfg cache.Config, tools map[string]config.CacheRule) (*proxy.Gateway, *cache.Store) {
	t.Helper()
	cfg := &config.Config{
		Servers: []config.ServerConfig{{
			Name: "up", URL: url, Transport: "http",
			Cache: &config.ServerCacheConfig{Tools: tools},
		}},
	}
	cs := cache.New(cacheCfg, true)
	al, err := audit.New(config.AuditConfig{})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	gw, err := proxy.New(cfg, policy.New(cfg.Servers, cfg.Clients), al,
		integrity.NewStore(integrity.ModeOff), nil, stdio.NewManager(), metrics.New(), cs)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return gw, cs
}

// callTool issues a tools/call through the gateway as the given client.
func callTool(t *testing.T, gw *proxy.Gateway, id, tool, args, client string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(body))
	if client != "" {
		req = req.WithContext(auth.WithClient(req.Context(), client))
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	return rec
}

func cacheStatus(rec *httptest.ResponseRecorder) string { return rec.Header().Get(proxy.CacheHeader) }

func TestGateway_ServesRepeatToolCallFromCache(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	gw, _ := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	first := callTool(t, gw, "1", "search", `{"q":"go"}`, "")
	if got := cacheStatus(first); got != "miss" {
		t.Fatalf("first call cache status = %q, want miss", got)
	}

	second := callTool(t, gw, "2", "search", `{"q":"go"}`, "")
	if got := cacheStatus(second); got != "hit" {
		t.Fatalf("second call cache status = %q, want hit", got)
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("upstream received %d calls, want 1", n)
	}

	// The cached body must answer the second request's id, not the first's.
	var resp struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode cached response: %v (%s)", err, second.Body.String())
	}
	if string(resp.ID) != "2" {
		t.Fatalf("cached response id = %s, want 2", resp.ID)
	}
	if !strings.Contains(string(resp.Result), `"call":1`) {
		t.Fatalf("expected the first upstream result to be replayed, got %s", resp.Result)
	}
}

func TestGateway_DoesNotCacheToolsThatAreNotOptedIn(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	gw, _ := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	for i := 0; i < 2; i++ {
		rec := callTool(t, gw, "1", "write_file", `{"path":"/tmp/x"}`, "")
		if got := cacheStatus(rec); got != "" {
			t.Fatalf("uncached tool carried cache status %q", got)
		}
	}
	if n := up.calls.Load(); n != 2 {
		t.Fatalf("upstream received %d calls, want 2 (tool is not cacheable)", n)
	}
}

func TestGateway_CacheKeySeparatesArgumentsAndClients(t *testing.T) {
	cases := []struct {
		name         string
		args, client string
	}{
		{"same call", `{"q":"go"}`, "alice"},
		{"different args", `{"q":"rust"}`, "alice"},
		{"different client", `{"q":"go"}`, "bob"},
	}
	up := newCountingUpstream(t, okResult("hello"))
	gw, _ := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	// Warm the cache for alice's "go" query, then check which calls reuse it.
	callTool(t, gw, "1", "search", `{"q":"go"}`, "alice")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := callTool(t, gw, "2", "search", tc.args, tc.client)
			want := "miss"
			if tc.name == "same call" {
				want = "hit"
			}
			if got := cacheStatus(rec); got != want {
				t.Fatalf("cache status = %q, want %q", got, want)
			}
		})
	}
	// One warm-up plus one backend call each for the two distinct calls.
	if n := up.calls.Load(); n != 3 {
		t.Fatalf("upstream received %d calls, want 3", n)
	}
}

func TestGateway_ArgumentOrderDoesNotChangeTheEntry(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	gw, _ := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	callTool(t, gw, "1", "search", `{"a":1,"b":2}`, "")
	rec := callTool(t, gw, "2", "search", `{"b":2,"a":1}`, "")

	if got := cacheStatus(rec); got != "hit" {
		t.Fatalf("reordered arguments missed the cache (status %q)", got)
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("upstream received %d calls, want 1", n)
	}
}

func TestGateway_DoesNotCacheFailures(t *testing.T) {
	cases := []struct {
		name  string
		first string
	}{
		{"jsonrpc error", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream blew up"}}`},
		{"tool reported isError", `{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newCountingUpstream(t, func(n int64, _ []byte) (string, string) {
				if n == 1 {
					return "application/json", tc.first
				}
				return "application/json", `{"jsonrpc":"2.0","id":1,"result":{"content":[],"call":2}}`
			})
			gw, _ := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

			callTool(t, gw, "1", "search", `{"q":"go"}`, "")
			second := callTool(t, gw, "2", "search", `{"q":"go"}`, "")

			if got := cacheStatus(second); got != "miss" {
				t.Fatalf("a failed call was cached (status %q)", got)
			}
			if n := up.calls.Load(); n != 2 {
				t.Fatalf("upstream received %d calls, want 2", n)
			}
			if !strings.Contains(second.Body.String(), `"call":2`) {
				t.Fatalf("retry did not reach the backend: %s", second.Body.String())
			}
		})
	}
}

func TestGateway_CacheEntryExpires(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	gw, _ := cachingGateway(t, up.URL, cache.Config{},
		map[string]config.CacheRule{"search": {TTL: config.Duration(40 * time.Millisecond)}})

	callTool(t, gw, "1", "search", `{"q":"go"}`, "")
	if got := cacheStatus(callTool(t, gw, "2", "search", `{"q":"go"}`, "")); got != "hit" {
		t.Fatalf("call within the TTL should hit, got %q", got)
	}

	time.Sleep(60 * time.Millisecond)

	if got := cacheStatus(callTool(t, gw, "3", "search", `{"q":"go"}`, "")); got != "miss" {
		t.Fatalf("call after the TTL should miss, got %q", got)
	}
	if n := up.calls.Load(); n != 2 {
		t.Fatalf("upstream received %d calls, want 2", n)
	}
}

func TestGateway_DoesNotCacheOversizedResponses(t *testing.T) {
	big := strings.Repeat("x", 4096)
	up := newCountingUpstream(t, okResult(big))
	gw, _ := cachingGateway(t, up.URL, cache.Config{MaxBodyBytes: 512}, map[string]config.CacheRule{"search": {}})

	first := callTool(t, gw, "1", "search", `{"q":"go"}`, "")
	if !strings.Contains(first.Body.String(), big) {
		t.Fatal("oversized response was truncated on its way to the client")
	}
	if got := cacheStatus(callTool(t, gw, "2", "search", `{"q":"go"}`, "")); got != "miss" {
		t.Fatalf("oversized response should not be cached, got %q", got)
	}
	if n := up.calls.Load(); n != 2 {
		t.Fatalf("upstream received %d calls, want 2", n)
	}
}

func TestGateway_DoesNotCacheStreamingResponses(t *testing.T) {
	up := newCountingUpstream(t, func(int64, []byte) (string, string) {
		return "text/event-stream", "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	})
	gw, _ := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	first := callTool(t, gw, "1", "search", `{"q":"go"}`, "")
	if !strings.Contains(first.Body.String(), "event: message") {
		t.Fatalf("stream did not reach the client intact: %q", first.Body.String())
	}
	if got := cacheStatus(callTool(t, gw, "2", "search", `{"q":"go"}`, "")); got != "miss" {
		t.Fatalf("a streamed response should not be cached, got %q", got)
	}
	if n := up.calls.Load(); n != 2 {
		t.Fatalf("upstream received %d calls, want 2", n)
	}
}

// TestGateway_SingleFlightSharesOneBackendCall drives the single-flight path
// deterministically: the test itself claims the key, so every concurrent
// request through the gateway is guaranteed to arrive as a follower.
func TestGateway_SingleFlightSharesOneBackendCall(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	gw, cs := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	key := cache.Key("up", "search", "", map[string]any{"q": "go"})
	if lead, _ := cs.Lead(context.Background(), key); !lead {
		t.Fatal("test should own the in-flight fetch")
	}

	const followers = 6
	var wg sync.WaitGroup
	statuses := make([]string, followers)
	sent := make(chan struct{}, followers)
	for i := 0; i < followers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sent <- struct{}{}
			statuses[i] = cacheStatus(callTool(t, gw, fmt.Sprint(i+10), "search", `{"q":"go"}`, ""))
		}(i)
	}
	for i := 0; i < followers; i++ {
		<-sent
	}
	// Every follower is on its way into the gateway; give them a moment to
	// park on the key before handing over the result.
	time.Sleep(50 * time.Millisecond)

	entry := cs.Put(key, []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[],"call":0}}`), "application/json", time.Minute)
	cs.Release(key, entry)
	wg.Wait()

	for i, got := range statuses {
		if got != "hit" {
			t.Errorf("follower %d saw cache status %q, want hit", i, got)
		}
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("upstream received %d calls; single-flight should have collapsed them all", n)
	}
}

// TestGateway_SingleFlightFollowersFallBackToTheBackend covers the other
// branch: the leader produced nothing cacheable, so waiters must each fetch.
func TestGateway_SingleFlightFollowersFallBackToTheBackend(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	gw, cs := cachingGateway(t, up.URL, cache.Config{}, map[string]config.CacheRule{"search": {}})

	key := cache.Key("up", "search", "", map[string]any{"q": "go"})
	if lead, _ := cs.Lead(context.Background(), key); !lead {
		t.Fatal("test should own the in-flight fetch")
	}

	const followers = 3
	var wg sync.WaitGroup
	sent := make(chan struct{}, followers)
	for i := 0; i < followers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sent <- struct{}{}
			callTool(t, gw, fmt.Sprint(i+10), "search", `{"q":"go"}`, "")
		}(i)
	}
	for i := 0; i < followers; i++ {
		<-sent
	}
	time.Sleep(50 * time.Millisecond)

	cs.Release(key, nil) // nothing cacheable came back
	wg.Wait()

	if n := up.calls.Load(); n != followers {
		t.Fatalf("upstream received %d calls, want %d (each follower fetches for itself)", n, followers)
	}
}

func TestGateway_CacheIsConsultedAfterPolicy(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	cfg := &config.Config{
		Servers: []config.ServerConfig{{
			Name: "up", URL: up.URL, Transport: "http",
			Policy: &config.Policy{DenyTools: []string{"search"}},
			Cache:  &config.ServerCacheConfig{Tools: map[string]config.CacheRule{"search": {}}},
		}},
	}
	al, _ := audit.New(config.AuditConfig{})
	gw, err := proxy.New(cfg, policy.New(cfg.Servers, cfg.Clients), al,
		integrity.NewStore(integrity.ModeOff), nil, stdio.NewManager(), metrics.New(), cache.New(cache.Config{}, true))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp/up/",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied tool returned %d, want 403", rec.Code)
	}
	if got := cacheStatus(rec); got != "" {
		t.Fatalf("denied request touched the cache (status %q)", got)
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("denied request reached the backend %d times", n)
	}
}

func TestGateway_DisabledCacheLeavesRequestsAlone(t *testing.T) {
	up := newCountingUpstream(t, okResult("hello"))
	cfg := &config.Config{
		Servers: []config.ServerConfig{{
			Name: "up", URL: up.URL, Transport: "http",
			Cache: &config.ServerCacheConfig{Tools: map[string]config.CacheRule{"search": {}}},
		}},
	}
	al, _ := audit.New(config.AuditConfig{})
	// A nil store is how the gateway is built when caching is off in config.
	gw, err := proxy.New(cfg, policy.New(cfg.Servers, cfg.Clients), al,
		integrity.NewStore(integrity.ModeOff), nil, stdio.NewManager(), metrics.New(), nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	for i := 0; i < 2; i++ {
		rec := callTool(t, gw, "1", "search", `{"q":"go"}`, "")
		if got := cacheStatus(rec); got != "" {
			t.Fatalf("cache header %q set while caching is disabled", got)
		}
	}
	if n := up.calls.Load(); n != 2 {
		t.Fatalf("upstream received %d calls, want 2", n)
	}
}

func TestGateway_StdioResponsesAreCached(t *testing.T) {
	gw := stdioCachingGateway(t, map[string]config.CacheRule{"read_file": {}})

	first := stdioCall(t, gw, `"req-1"`, "read_file")
	if got := first.Header().Get(proxy.CacheHeader); got != "miss" {
		t.Fatalf("first stdio call cache status = %q, want miss", got)
	}
	second := stdioCall(t, gw, `"req-2"`, "read_file")
	if got := second.Header().Get(proxy.CacheHeader); got != "hit" {
		t.Fatalf("second stdio call cache status = %q, want hit", got)
	}

	var resp struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode cached stdio response: %v (%s)", err, second.Body.String())
	}
	if string(resp.ID) != `"req-2"` {
		t.Fatalf("cached stdio response id = %s, want \"req-2\"", resp.ID)
	}
}

// stdioCachingGateway mirrors stdioGateway (stdio_test.go) with caching on.
func stdioCachingGateway(t *testing.T, tools map[string]config.CacheRule) *proxy.Gateway {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cfg := &config.Config{
		Servers: []config.ServerConfig{{
			Name:      "local",
			Transport: "stdio",
			Command:   exe,
			Env:       map[string]string{"MCPX_STDIO_HELPER": "1"},
			Cache:     &config.ServerCacheConfig{Tools: tools},
		}},
	}
	al, err := audit.New(config.AuditConfig{})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	sm := stdio.NewManager()
	t.Cleanup(sm.CloseAll)
	gw, err := proxy.New(cfg, policy.New(cfg.Servers, nil), al, integrity.NewStore(integrity.ModeOff),
		nil, sm, metrics.New(), cache.New(cache.Config{}, true))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return gw
}

func stdioCall(t *testing.T, gw *proxy.Gateway, id, tool string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":%q}}`, id, tool)
	req := httptest.NewRequest(http.MethodPost, "/mcp/local/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	return rec
}
