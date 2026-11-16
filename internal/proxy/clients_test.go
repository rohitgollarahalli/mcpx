package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/auth"
	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
	"github.com/rohitgollarahalli/mcpx/internal/proxy"
)

// listToolsAs issues a tools/list request carrying an authenticated client
// identity, the way the auth middleware would.
func listToolsAs(t *testing.T, gw *proxy.Gateway, client string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if client != "" {
		req = req.WithContext(auth.WithClient(req.Context(), client))
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	tl, err := mcp.ParseToolsListResult(resp.Result)
	if err != nil {
		t.Fatalf("parse tools/list result: %v", err)
	}
	names := make([]string, len(tl.Tools))
	for i, raw := range tl.Tools {
		names[i] = mcp.ToolName(raw)
	}
	return names
}

// TestGateway_PerClientToolsListFiltering: two clients receive differently
// filtered tools/list responses from the same backend.
func TestGateway_PerClientToolsListFiltering(t *testing.T) {
	body := toolsList("read_file", "write_file", "delete_file")
	up := upstream(t, &body)
	cfg := &config.Config{
		Servers:    []config.ServerConfig{{Name: "up", URL: up.URL, Transport: "http"}},
		Inspection: &config.InspectionConfig{FilterToolsList: true},
		Clients: map[string]config.ClientConfig{
			"reader": {Servers: map[string]*config.Policy{
				"up": {AllowTools: []string{"read_file"}},
			}},
			"editor": {Servers: map[string]*config.Policy{
				"up": {DenyTools: []string{"delete_file"}},
			}},
		},
	}
	gw := newGatewayFromConfig(t, cfg)

	if got := listToolsAs(t, gw, "reader"); !equalSet(got, []string{"read_file"}) {
		t.Errorf("reader should see only read_file, got %v", got)
	}
	if got := listToolsAs(t, gw, "editor"); !equalSet(got, []string{"read_file", "write_file"}) {
		t.Errorf("editor should see all but delete_file, got %v", got)
	}
	if got := listToolsAs(t, gw, ""); !equalSet(got, []string{"read_file", "write_file", "delete_file"}) {
		t.Errorf("anonymous client should see the server baseline, got %v", got)
	}
}

// TestGateway_PerClientCallDenied: a client-scoped policy blocks tools/call
// with a reason naming the client.
func TestGateway_PerClientCallDenied(t *testing.T) {
	body := toolsList("read_file", "write_file")
	up := upstream(t, &body)
	cfg := &config.Config{
		Servers: []config.ServerConfig{{Name: "up", URL: up.URL, Transport: "http"}},
		Clients: map[string]config.ClientConfig{
			"reader": {Servers: map[string]*config.Policy{
				"up": {AllowTools: []string{"read_file"}},
			}},
		},
	}
	gw := newGatewayFromConfig(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file"}}`))
	req = req.WithContext(auth.WithClient(req.Context(), "reader"))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `client \"reader\"`) && !strings.Contains(rec.Body.String(), "reader") {
		t.Errorf("denial should name the client, got %s", rec.Body.String())
	}
}
