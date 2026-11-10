package proxy_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohitgs28/mcpx/internal/audit"
	"github.com/rohitgs28/mcpx/internal/breaker"
	"github.com/rohitgs28/mcpx/internal/cache"
	"github.com/rohitgs28/mcpx/internal/config"
	"github.com/rohitgs28/mcpx/internal/integrity"
	"github.com/rohitgs28/mcpx/internal/metrics"
	"github.com/rohitgs28/mcpx/internal/policy"
	"github.com/rohitgs28/mcpx/internal/proxy"
	"github.com/rohitgs28/mcpx/internal/stdio"
)

// paymentsSpec is a small REST API: a read, a write with a JSON body, and a
// destructive call. The write's body is an object, so its fields become
// top-level tool arguments that policy argument rules can constrain.
const paymentsSpec = `{
  "openapi": "3.1.0",
  "info": {"title": "Payments", "version": "2.0.0"},
  "paths": {
    "/accounts/{id}": {
      "get": {"operationId": "getAccount",
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}]}
    },
    "/payments": {
      "post": {"operationId": "createPayment",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {
          "type": "object", "required": ["amount", "currency"],
          "properties": {"amount": {"type": "number"}, "currency": {"type": "string"}, "to": {"type": "string"}}}}}}}
    },
    "/accounts/{id}/close": {
      "post": {"operationId": "closeAccount",
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}]}
    }
  }
}`

// restAPI is a fake REST backend counting the calls it receives.
type restAPI struct {
	srv      *httptest.Server
	calls    atomic.Int64
	status   atomic.Int64 // response status; 0 means 200
	lastAuth atomic.Value
	lastBody atomic.Value
}

func newRestAPI(t *testing.T) *restAPI {
	t.Helper()
	a := &restAPI{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls.Add(1)
		a.lastAuth.Store(r.Header.Get("Authorization"))
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		a.lastBody.Store(body)
		if s := a.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func writeSpec(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "payments.json")
	if err := os.WriteFile(p, []byte(paymentsSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// openapiServer is the server config under test; individual tests adjust it.
func openapiServer(t *testing.T, api *restAPI) config.ServerConfig {
	return config.ServerConfig{
		Name:      "up",
		Transport: "openapi",
		URL:       api.srv.URL,
		Headers:   map[string]string{"Authorization": "Bearer api-secret"},
		OpenAPI:   &config.OpenAPIConfig{Spec: writeSpec(t)},
	}
}

type gwOpts struct {
	insp    *config.InspectionConfig
	breaker *breaker.Manager
	cache   *cache.Store
}

func openapiGateway(t *testing.T, sc config.ServerConfig, o gwOpts) *proxy.Gateway {
	t.Helper()
	cfg := &config.Config{Servers: []config.ServerConfig{sc}, Inspection: o.insp}
	al, err := audit.New(config.AuditConfig{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := proxy.New(cfg, policy.New(cfg.Servers, cfg.Clients), al, integrity.NewStore(integrity.ModeEnforce),
		o.breaker, stdio.NewManager(), metrics.New(), o.cache)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return gw
}

func sortedTools(t *testing.T, gw *proxy.Gateway) []string {
	t.Helper()
	got := listTools(t, gw)
	sort.Strings(got)
	return got
}

func gwCall(gw *proxy.Gateway, tool string, args string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, args)
	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer client-token-must-not-leak")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

func toolResult(t *testing.T, rec *httptest.ResponseRecorder) (text string, isError bool) {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Result.Content) == 0 {
		t.Fatalf("not a tool result (%d): %s", rec.Code, rec.Body.String())
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

func TestOpenAPI_ToolsListedAndCalledThroughGateway(t *testing.T) {
	api := newRestAPI(t)
	gw := openapiGateway(t, openapiServer(t, api), gwOpts{})

	got := sortedTools(t, gw)
	if strings.Join(got, ",") != "closeAccount,createPayment,getAccount" {
		t.Fatalf("tools = %v", got)
	}

	rec := gwCall(gw, "getAccount", `{"id":"acc_1"}`)
	text, isErr := toolResult(t, rec)
	if rec.Code != 200 || isErr || text != `{"path":"/accounts/acc_1"}` {
		t.Fatalf("getAccount: %d %q %v", rec.Code, text, isErr)
	}
	// The API sees the gateway's injected credential, never the client's.
	if auth := api.lastAuth.Load(); auth != "Bearer api-secret" {
		t.Errorf("upstream Authorization = %v", auth)
	}
}

func TestOpenAPI_PolicyDenyBlocksAndHidesTool(t *testing.T) {
	api := newRestAPI(t)
	sc := openapiServer(t, api)
	sc.Policy = &config.Policy{DenyTools: []string{"closeAccount"}}
	gw := openapiGateway(t, sc, gwOpts{insp: &config.InspectionConfig{FilterToolsList: true}})

	if got := sortedTools(t, gw); strings.Join(got, ",") != "createPayment,getAccount" {
		t.Errorf("denied tool still listed: %v", got)
	}
	rec := gwCall(gw, "closeAccount", `{"id":"acc_1"}`)
	if rec.Code != http.StatusForbidden || api.calls.Load() != 0 {
		t.Errorf("denied call: status %d, upstream calls %d", rec.Code, api.calls.Load())
	}
}

// Argument rules apply to request-body fields because object bodies are
// flattened into top-level tool arguments.
func TestOpenAPI_ArgumentRulesConstrainBodyFields(t *testing.T) {
	api := newRestAPI(t)
	sc := openapiServer(t, api)
	sc.Policy = &config.Policy{ToolRules: map[string]config.ToolRule{
		"createPayment": {Args: map[string]config.ArgRule{
			"currency": {OneOf: []string{"CAD", "USD"}},
			"to":       {Required: true, Prefix: "acct_"},
		}},
	}}
	gw := openapiGateway(t, sc, gwOpts{})

	if rec := gwCall(gw, "createPayment", `{"amount":10,"currency":"EUR","to":"acct_9"}`); rec.Code != http.StatusForbidden {
		t.Errorf("disallowed currency: status %d", rec.Code)
	}
	if rec := gwCall(gw, "createPayment", `{"amount":10,"currency":"CAD","to":"evil"}`); rec.Code != http.StatusForbidden {
		t.Errorf("disallowed recipient: status %d", rec.Code)
	}
	if api.calls.Load() != 0 {
		t.Fatalf("denied payments reached the API: %d", api.calls.Load())
	}

	rec := gwCall(gw, "createPayment", `{"amount":10,"currency":"CAD","to":"acct_9"}`)
	if _, isErr := toolResult(t, rec); rec.Code != 200 || isErr {
		t.Fatalf("allowed payment failed: %d %s", rec.Code, rec.Body.String())
	}
	body, _ := api.lastBody.Load().(map[string]any)
	if body["amount"] != 10.0 || body["currency"] != "CAD" || body["to"] != "acct_9" {
		t.Errorf("upstream body = %v", body)
	}
}

func TestOpenAPI_ReadOnlyMethodsFilter(t *testing.T) {
	api := newRestAPI(t)
	sc := openapiServer(t, api)
	sc.OpenAPI.Methods = []string{"GET"}
	gw := openapiGateway(t, sc, gwOpts{})

	if got := sortedTools(t, gw); strings.Join(got, ",") != "getAccount" {
		t.Errorf("tools = %v", got)
	}
	var resp struct{ Error *struct{ Message string } }
	json.Unmarshal(gwCall(gw, "createPayment", `{"amount":1,"currency":"CAD"}`).Body.Bytes(), &resp)
	if resp.Error == nil || api.calls.Load() != 0 {
		t.Errorf("filtered-out operation must not be callable: %+v, calls %d", resp.Error, api.calls.Load())
	}
}

func TestOpenAPI_ResponseCache(t *testing.T) {
	api := newRestAPI(t)
	sc := openapiServer(t, api)
	sc.Cache = &config.ServerCacheConfig{Tools: map[string]config.CacheRule{"getAccount": {TTL: config.Duration(time.Minute)}}}
	cs := cache.New(cache.Config{}, true)
	gw := openapiGateway(t, sc, gwOpts{cache: cs})

	first := gwCall(gw, "getAccount", `{"id":"acc_1"}`)
	second := gwCall(gw, "getAccount", `{"id":"acc_1"}`)
	if cacheStatus(first) != "miss" || cacheStatus(second) != "hit" {
		t.Errorf("cache status = %q then %q", cacheStatus(first), cacheStatus(second))
	}
	if api.calls.Load() != 1 {
		t.Errorf("API called %d times, want 1", api.calls.Load())
	}
	if first.Body.String() != second.Body.String() {
		t.Errorf("cached body differs:\n%s\n%s", first.Body.String(), second.Body.String())
	}
}

// API outages (5xx) trip the circuit breaker; client errors (4xx) do not.
func TestOpenAPI_CircuitBreaker(t *testing.T) {
	api := newRestAPI(t)
	bm := breaker.NewManager(breaker.Config{FailureThreshold: 2, Cooldown: time.Minute}, true)
	gw := openapiGateway(t, openapiServer(t, api), gwOpts{breaker: bm})

	api.status.Store(http.StatusNotFound)
	for i := 0; i < 3; i++ {
		if _, isErr := toolResult(t, gwCall(gw, "getAccount", `{"id":"x"}`)); !isErr {
			t.Fatal("404 should be a tool error")
		}
	}
	api.status.Store(http.StatusServiceUnavailable)
	for i := 0; i < 2; i++ {
		if rec := gwCall(gw, "getAccount", `{"id":"x"}`); rec.Code != http.StatusBadGateway {
			t.Fatalf("503 upstream: gateway status %d", rec.Code)
		}
	}
	before := api.calls.Load()
	if rec := gwCall(gw, "getAccount", `{"id":"x"}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("breaker should be open: status %d", rec.Code)
	}
	if api.calls.Load() != before {
		t.Error("open breaker must not call the API")
	}
}

func TestOpenAPI_BadSpecFailsGatewayBuild(t *testing.T) {
	api := newRestAPI(t)
	sc := openapiServer(t, api)
	sc.OpenAPI.Spec = filepath.Join(t.TempDir(), "missing.json")
	cfg := &config.Config{Servers: []config.ServerConfig{sc}}
	al, _ := audit.New(config.AuditConfig{})
	if _, err := proxy.New(cfg, policy.New(cfg.Servers, nil), al, nil, nil, nil, metrics.New(), nil); err == nil {
		t.Error("expected an error for a missing spec")
	}
}
