package mcp_test

import (
	"encoding/json"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

func TestParseRequest_ToolsCall(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}`
	req, err := mcp.ParseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != mcp.MethodToolsCall {
		t.Fatalf("expected tools/call, got %s", req.Method)
	}
	if req.ID != float64(1) {
		t.Fatalf("expected id 1, got %v", req.ID)
	}
}

func TestParseRequest_EmptyMethod(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1}`
	req, err := mcp.ParseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req != nil {
		t.Fatal("expected nil for request with empty method")
	}
}

func TestParseRequest_InvalidJSON(t *testing.T) {
	_, err := mcp.ParseRequest([]byte("{invalid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseRequest_AllMethods(t *testing.T) {
	methods := []string{
		mcp.MethodToolsCall, mcp.MethodToolsList, mcp.MethodInitialize,
		mcp.MethodPing, mcp.MethodResourceRead, mcp.MethodResourceList,
		mcp.MethodPromptGet, mcp.MethodPromptList,
	}
	for _, m := range methods {
		raw, _ := json.Marshal(mcp.Request{JSONRPC: "2.0", ID: 1, Method: m})
		req, err := mcp.ParseRequest(raw)
		if err != nil {
			t.Fatalf("error parsing %s: %v", m, err)
		}
		if req.Method != m {
			t.Fatalf("expected %s, got %s", m, req.Method)
		}
	}
}

func TestParseToolCall_ValidCall(t *testing.T) {
	params := mcp.ToolCallParams{Name: "read_file", Arguments: map[string]any{"path": "/tmp"}}
	data, _ := json.Marshal(params)
	req := &mcp.Request{JSONRPC: "2.0", ID: 1, Method: mcp.MethodToolsCall, Params: data}

	tc, err := mcp.ParseToolCall(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.Name != "read_file" {
		t.Fatalf("expected read_file, got %s", tc.Name)
	}
	if tc.Arguments["path"] != "/tmp" {
		t.Fatalf("expected /tmp argument, got %v", tc.Arguments["path"])
	}
}

func TestParseToolCall_NonToolsCallReturnsNil(t *testing.T) {
	req := &mcp.Request{JSONRPC: "2.0", ID: 1, Method: mcp.MethodToolsList}
	tc, err := mcp.ParseToolCall(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc != nil {
		t.Fatal("expected nil for non-tools/call method")
	}
}

func TestParseToolCall_NoArguments(t *testing.T) {
	params := mcp.ToolCallParams{Name: "list_files"}
	data, _ := json.Marshal(params)
	req := &mcp.Request{JSONRPC: "2.0", ID: 1, Method: mcp.MethodToolsCall, Params: data}

	tc, err := mcp.ParseToolCall(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.Name != "list_files" {
		t.Fatalf("expected list_files, got %s", tc.Name)
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp := mcp.NewErrorResponse(42, -32600, "access denied")

	if resp.JSONRPC != "2.0" {
		t.Fatalf("expected jsonrpc 2.0, got %s", resp.JSONRPC)
	}
	if resp.ID != 42 {
		t.Fatalf("expected id 42, got %v", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("expected error field to be set")
	}
	if resp.Error.Code != -32600 {
		t.Fatalf("expected code -32600, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "access denied" {
		t.Fatalf("expected 'access denied', got %s", resp.Error.Message)
	}
}

func TestNewErrorResponse_Serialization(t *testing.T) {
	resp := mcp.NewErrorResponse(1, -32601, "method not found")
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed mcp.Response
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.Error.Code != -32601 {
		t.Fatalf("round-trip failed: expected -32601, got %d", parsed.Error.Code)
	}
}

func TestParseRequest_Notification(t *testing.T) {
	// Notifications have no ID
	raw := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, err := mcp.ParseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request for notification")
	}
	if req.Method != "notifications/initialized" {
		t.Fatalf("expected notifications/initialized, got %s", req.Method)
	}
}
