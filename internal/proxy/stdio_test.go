package proxy_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/audit"
	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/integrity"
	"github.com/rohitgollarahalli/mcpx/internal/metrics"
	"github.com/rohitgollarahalli/mcpx/internal/policy"
	"github.com/rohitgollarahalli/mcpx/internal/proxy"
	"github.com/rohitgollarahalli/mcpx/internal/stdio"
)

// TestMain doubles as a fake MCP stdio server when the test binary is
// re-executed with MCPX_STDIO_HELPER set (same pattern as internal/stdio).
func TestMain(m *testing.M) {
	if os.Getenv("MCPX_STDIO_HELPER") == "1" {
		stdioHelperMain()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func stdioHelperMain() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			continue
		}
		switch msg.Method {
		case "tools/list":
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{
				"tools": []map[string]any{
					{"name": "read_file", "description": "read", "inputSchema": map[string]any{"type": "object"}},
					{"name": "delete_file", "description": "delete", "inputSchema": map[string]any{"type": "object"}},
				},
			}})
		case "tools/call":
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"called": json.RawMessage(msg.Params)}})
		default:
			if msg.ID != nil {
				out.Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{}})
			}
		}
	}
}

func stdioGateway(t *testing.T, pol *config.Policy, insp *config.InspectionConfig) *proxy.Gateway {
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
			Policy:    pol,
		}},
		Inspection: insp,
	}
	al, err := audit.New(config.AuditConfig{})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	sm := stdio.NewManager()
	t.Cleanup(sm.CloseAll)
	gw, err := proxy.New(cfg, policy.New(cfg.Servers, nil), al, integrity.NewStore(integrity.ModeOff), nil, sm, metrics.New(), nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return gw
}

func TestGateway_StdioCallRoundTrip(t *testing.T) {
	gw := stdioGateway(t, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp/local/",
		strings.NewReader(`{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"read_file"}}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID     string          `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if resp.ID != "req-1" {
		t.Errorf("response id = %q, want req-1", resp.ID)
	}
	if !strings.Contains(string(resp.Result), "read_file") {
		t.Errorf("result %s missing echoed call", resp.Result)
	}
}

func TestGateway_StdioPolicyDeny(t *testing.T) {
	gw := stdioGateway(t, &config.Policy{DenyTools: []string{"delete_file"}}, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp/local/",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_StdioNotificationAccepted(t *testing.T) {
	gw := stdioGateway(t, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp/local/",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_StdioGetRejected(t *testing.T) {
	gw := stdioGateway(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/mcp/local/", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_StdioFiltersDeniedToolsFromList(t *testing.T) {
	gw := stdioGateway(t,
		&config.Policy{DenyTools: []string{"delete_file"}},
		&config.InspectionConfig{FilterToolsList: true})
	req := httptest.NewRequest(http.MethodPost, "/mcp/local/",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "read_file") {
		t.Errorf("allowed tool missing from filtered list: %s", body)
	}
	if strings.Contains(body, "delete_file") {
		t.Errorf("denied tool leaked into filtered list: %s", body)
	}
}
