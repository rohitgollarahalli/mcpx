package policy_test

import (
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
	"github.com/rohitgollarahalli/mcpx/internal/policy"
)

// clientEngine builds an engine with a server baseline policy and per-client
// overrides.
func clientEngine(server *config.Policy, clients map[string]config.ClientConfig) *policy.Engine {
	return policy.New([]config.ServerConfig{
		{Name: "fs", URL: "http://localhost:3001", Policy: server},
	}, clients)
}

// TestEvaluate_ClientIntersection: server policy AND client override must
// both allow a call.
func TestEvaluate_ClientIntersection(t *testing.T) {
	server := &config.Policy{DenyTools: []string{"delete_file"}}
	clients := map[string]config.ClientConfig{
		"ci-bot": {Servers: map[string]*config.Policy{
			"fs": {AllowTools: []string{"read_file"}},
		}},
		"auditor": {Servers: map[string]*config.Policy{
			"fs": {ReadOnly: true},
		}},
	}
	e := clientEngine(server, clients)

	tests := []struct {
		name      string
		client    string
		tool      string
		wantAllow bool
	}{
		{"server allows + client allows", "ci-bot", "read_file", true},
		{"server allows + client override denies", "ci-bot", "write_file", false},
		{"server denies + client would allow", "ci-bot", "delete_file", false},
		{"client read_only blocks everything", "auditor", "read_file", false},
		{"unknown client gets server baseline", "stranger", "write_file", true},
		{"unknown client still bound by server deny", "stranger", "delete_file", false},
		{"empty client gets server baseline", "", "write_file", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := e.Evaluate("fs", tt.client, makeRequest(mcp.MethodToolsCall, tt.tool))
			if res.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v (reason %q), want %v", res.Allowed, res.Reason, tt.wantAllow)
			}
		})
	}
}

// Client-denial reasons must name the client so audit logs are attributable.
func TestEvaluate_ClientDenialNamesClient(t *testing.T) {
	e := clientEngine(nil, map[string]config.ClientConfig{
		"ci-bot": {Servers: map[string]*config.Policy{
			"fs": {DenyTools: []string{"write_file"}},
		}},
	})
	res := e.Evaluate("fs", "ci-bot", makeRequest(mcp.MethodToolsCall, "write_file"))
	if res.Allowed {
		t.Fatal("expected client deny to block")
	}
	if !strings.Contains(res.Reason, `client "ci-bot"`) {
		t.Errorf("reason %q does not name the client", res.Reason)
	}
}

// Client overrides support argument rules too.
func TestEvaluate_ClientArgRules(t *testing.T) {
	e := clientEngine(nil, map[string]config.ClientConfig{
		"ci-bot": {Servers: map[string]*config.Policy{
			"fs": {ToolRules: map[string]config.ToolRule{
				"read_file": {Args: map[string]config.ArgRule{"path": {Prefix: "/ci/"}}},
			}},
		}},
	})

	if res := e.Evaluate("fs", "ci-bot", makeCallWithArgs("read_file", map[string]any{"path": "/ci/build.log"})); !res.Allowed {
		t.Errorf("expected client arg rule to pass, got %q", res.Reason)
	}
	if res := e.Evaluate("fs", "ci-bot", makeCallWithArgs("read_file", map[string]any{"path": "/etc/passwd"})); res.Allowed {
		t.Error("expected client arg rule to deny out-of-scope path")
	}
	if res := e.Evaluate("fs", "other", makeCallWithArgs("read_file", map[string]any{"path": "/etc/passwd"})); !res.Allowed {
		t.Errorf("other clients are not bound by ci-bot's rules, got %q", res.Reason)
	}
}

func TestToolAllowed_PerClient(t *testing.T) {
	server := &config.Policy{DenyTools: []string{"delete_file"}}
	e := clientEngine(server, map[string]config.ClientConfig{
		"ci-bot": {Servers: map[string]*config.Policy{
			"fs": {AllowTools: []string{"read_file"}},
		}},
	})

	tests := []struct {
		client string
		tool   string
		want   bool
	}{
		{"ci-bot", "read_file", true},
		{"ci-bot", "write_file", false},  // client allow-list excludes it
		{"ci-bot", "delete_file", false}, // server deny wins regardless
		{"stranger", "write_file", true}, // baseline only
		{"", "write_file", true},
	}
	for _, tt := range tests {
		if got := e.ToolAllowed("fs", tt.client, tt.tool); got != tt.want {
			t.Errorf("ToolAllowed(fs, %q, %q) = %v, want %v", tt.client, tt.tool, got, tt.want)
		}
	}
}
