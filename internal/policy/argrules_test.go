package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
	"github.com/rohitgollarahalli/mcpx/internal/policy"
)

func makeCallWithArgs(toolName string, args map[string]any) *mcp.Request {
	params := mcp.ToolCallParams{Name: toolName, Arguments: args}
	data, _ := json.Marshal(params)
	return &mcp.Request{JSONRPC: "2.0", ID: 1, Method: mcp.MethodToolsCall, Params: data}
}

func strPtr(s string) *string { return &s }

func argEngine(rules map[string]config.ToolRule) *policy.Engine {
	return policy.New([]config.ServerConfig{
		{Name: "srv", URL: "http://localhost:3000", Policy: &config.Policy{ToolRules: rules}},
	}, nil)
}

func TestEvaluate_ArgRules(t *testing.T) {
	rules := map[string]config.ToolRule{
		"read_file": {Args: map[string]config.ArgRule{
			"path": {Prefix: "/data/"},
		}},
		"write_file": {Args: map[string]config.ArgRule{
			"path": {Prefix: "/data/", Suffix: ".txt"},
			"mode": {OneOf: []string{"w", "a"}},
		}},
		"query": {Args: map[string]config.ArgRule{
			"sql":   {Regex: "^SELECT ", Required: true},
			"limit": {Equals: strPtr("100")},
		}},
		"flagged": {Args: map[string]config.ArgRule{
			"force":   {Equals: strPtr("false")},
			"retries": {Equals: strPtr("3")},
		}},
	}

	tests := []struct {
		name       string
		tool       string
		args       map[string]any
		wantAllow  bool
		wantReason string // substring of denial reason
	}{
		{"prefix match", "read_file", map[string]any{"path": "/data/a.txt"}, true, ""},
		{"prefix mismatch", "read_file", map[string]any{"path": "/etc/passwd"}, false, "prefix"},
		{"traversal passes literal prefix (documented v1 limit)", "read_file", map[string]any{"path": "/data/../etc/passwd"}, true, ""},
		{"unlisted arg ignored", "read_file", map[string]any{"path": "/data/a", "extra": "anything"}, true, ""},
		{"absent non-required arg passes", "read_file", nil, true, ""},
		{"multiple constraints AND - both pass", "write_file", map[string]any{"path": "/data/a.txt", "mode": "w"}, true, ""},
		{"multiple constraints AND - suffix fails", "write_file", map[string]any{"path": "/data/a.exe", "mode": "w"}, false, "suffix"},
		{"one_of mismatch", "write_file", map[string]any{"path": "/data/a.txt", "mode": "x"}, false, "one_of"},
		{"regex match", "query", map[string]any{"sql": "SELECT * FROM t"}, true, ""},
		{"regex mismatch", "query", map[string]any{"sql": "DROP TABLE t"}, false, "regex"},
		{"required missing", "query", nil, false, "required argument"},
		{"number normalized", "query", map[string]any{"sql": "SELECT 1", "limit": float64(100)}, true, ""},
		{"number mismatch", "query", map[string]any{"sql": "SELECT 1", "limit": float64(99)}, false, "equals"},
		{"bool normalized", "flagged", map[string]any{"force": false}, true, ""},
		{"bool mismatch", "flagged", map[string]any{"force": true}, false, "equals"},
		{"int-valued float normalized without decimal", "flagged", map[string]any{"retries": float64(3)}, true, ""},
		{"non-scalar value fails closed", "read_file", map[string]any{"path": []any{"/data/a"}}, false, "non-scalar"},
		{"tool without rules unaffected", "unruled_tool", map[string]any{"anything": "goes"}, true, ""},
	}
	e := argEngine(rules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := e.Evaluate("srv", "", makeCallWithArgs(tt.tool, tt.args))
			if res.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v (reason %q), want %v", res.Allowed, res.Reason, tt.wantAllow)
			}
			if !tt.wantAllow && !strings.Contains(res.Reason, tt.wantReason) {
				t.Errorf("reason %q does not mention %q", res.Reason, tt.wantReason)
			}
		})
	}
}

// TestEvaluate_ArgRulesAfterAllowList verifies argument rules compose with
// allow/deny lists: the tool must pass the name checks AND its arg rules.
func TestEvaluate_ArgRulesAfterAllowList(t *testing.T) {
	e := policy.New([]config.ServerConfig{
		{Name: "srv", URL: "http://localhost:3000", Policy: &config.Policy{
			AllowTools: []string{"read_file"},
			ToolRules: map[string]config.ToolRule{
				"read_file": {Args: map[string]config.ArgRule{"path": {Prefix: "/data/"}}},
			},
		}},
	}, nil)

	if res := e.Evaluate("srv", "", makeCallWithArgs("read_file", map[string]any{"path": "/data/x"})); !res.Allowed {
		t.Errorf("allow-listed tool with valid args should pass, got %q", res.Reason)
	}
	if res := e.Evaluate("srv", "", makeCallWithArgs("read_file", map[string]any{"path": "/tmp/x"})); res.Allowed {
		t.Error("allow-listed tool with violating args must still be denied")
	}
	if res := e.Evaluate("srv", "", makeCallWithArgs("other_tool", nil)); res.Allowed {
		t.Error("tool outside allow list must be denied regardless of rules")
	}
}

// Argument rules must not hide tools from tools/list: visibility is
// name-level only.
func TestToolAllowed_IgnoresArgRules(t *testing.T) {
	e := argEngine(map[string]config.ToolRule{
		"read_file": {Args: map[string]config.ArgRule{"path": {Prefix: "/data/", Required: true}}},
	})
	if !e.ToolAllowed("srv", "", "read_file") {
		t.Error("tool with arg rules must stay visible in tools/list")
	}
}
