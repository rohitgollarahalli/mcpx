package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rohitgs28/mcpx/internal/config"
)

// TestInjectedHeadersReplaceClientHeaders checks configured backend headers
// reach the upstream and win over a client-supplied header of the same name.
func TestInjectedHeadersReplaceClientHeaders(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(up.Close)

	cfg := &config.Config{Servers: []config.ServerConfig{{
		Name: "up", URL: up.URL, Transport: "http",
		Headers: map[string]string{"Authorization": "Bearer backend-key", "x-tenant": "acme"},
	}}}
	gw := newGatewayFromConfig(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mcp/up", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer client-forged")
	req.Header.Set("X-Other", "kept")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if v := got.Values("Authorization"); len(v) != 1 || v[0] != "Bearer backend-key" {
		t.Errorf("upstream Authorization = %q, want only the injected value", v)
	}
	if v := got.Get("X-Tenant"); v != "acme" {
		t.Errorf("upstream X-Tenant = %q", v)
	}
	if v := got.Get("X-Other"); v != "kept" {
		t.Errorf("unrelated client header dropped: X-Other = %q", v)
	}
}
