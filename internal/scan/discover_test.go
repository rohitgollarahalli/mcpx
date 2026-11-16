package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseClientConfigShapes(t *testing.T) {
	cases := []struct {
		name string
		json string
		want map[string]string // server name -> transport
	}{
		{"claude desktop", `{"mcpServers":{"fs":{"command":"npx","args":["-y","x"]},"remote":{"url":"https://h/mcp"}}}`,
			map[string]string{"fs": "stdio", "remote": "http"}},
		{"vscode mcp.json", `{"servers":{"gh":{"type":"http","url":"https://api/mcp"}},"inputs":[]}`,
			map[string]string{"gh": "http"}},
		{"vscode settings", `{"editor.fontSize":12,"mcp":{"servers":{"py":{"command":"uvx","args":["srv"]}}}}`,
			map[string]string{"py": "stdio"}},
		{"windsurf", `{"mcpServers":{"w":{"serverUrl":"https://w/mcp"}}}`, map[string]string{"w": "http"}},
		{"gemini", `{"theme":"x","mcpServers":{"g":{"httpUrl":"https://g/mcp"}}}`, map[string]string{"g": "http"}},
		{"disabled skipped", `{"mcpServers":{"on":{"command":"a"},"off":{"command":"b","disabled":true}}}`,
			map[string]string{"on": "stdio"}},
		{"claude code projects", `{"mcpServers":{"g":{"command":"a"}},"projects":{"/home/u/app":{"mcpServers":{"db":{"command":"b"}}}}}`,
			map[string]string{"g": "stdio", "app/db": "stdio"}},
		{"no command or url", `{"mcpServers":{"bad":{}}}`, map[string]string{"bad": "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseClientConfig([]byte(tc.json), "f.json", "Test")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d servers, want %d: %+v", len(got), len(tc.want), got)
			}
			for _, s := range got {
				if tc.want[s.Name] != s.Transport {
					t.Errorf("%s: transport %q, want %q", s.Name, s.Transport, tc.want[s.Name])
				}
				if s.Source != "f.json" || s.Client != "Test" {
					t.Errorf("%s: source/client not set: %+v", s.Name, s)
				}
			}
		})
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{
  // line comment
  "url": "https://example.com/a//b", /* block
  comment */ "s": "has /* not a comment */ and \" quote",
  "list": [1, 2, ],
}`
	var v map[string]any
	if err := json.Unmarshal(stripJSONC([]byte(in)), &v); err != nil {
		t.Fatalf("decode: %v\n%s", err, stripJSONC([]byte(in)))
	}
	if v["url"] != "https://example.com/a//b" {
		t.Errorf("url mangled: %v", v["url"])
	}
	if v["s"] != `has /* not a comment */ and " quote` {
		t.Errorf("string mangled: %v", v["s"])
	}
	if l, _ := v["list"].([]any); len(l) != 2 {
		t.Errorf("list = %v", v["list"])
	}
}

func TestDiscoverExplicitPathsDedupes(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "claude_desktop_config.json")
	b := filepath.Join(dir, ".cursor", "mcp.json")
	os.MkdirAll(filepath.Dir(b), 0o755)
	os.WriteFile(a, []byte(`{"mcpServers":{"fs":{"command":"npx","args":["fs"]},"gh":{"command":"npx","args":["gh"]}}}`), 0o644)
	os.WriteFile(b, []byte(`{"mcpServers":{"fs":{"command":"npx","args":["fs"]},"gh":{"command":"npx","args":["gh-fork"]}}}`), 0o644)

	servers, files, err := Discover([]string{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("configs = %+v", files)
	}
	if files[0].Client != "Claude Desktop" || files[1].Client != "Cursor" {
		t.Errorf("clients = %s, %s", files[0].Client, files[1].Client)
	}
	// fs is identical in both and scanned once; the two different "gh"
	// servers are both kept.
	if len(servers) != 3 {
		t.Fatalf("servers = %+v", servers)
	}
	uniqueNames(servers)
	names := map[string]bool{}
	for _, s := range servers {
		if names[s.Name] {
			t.Fatalf("duplicate name %q after uniqueNames", s.Name)
		}
		names[s.Name] = true
	}
	if !names["gh (Claude Desktop)"] || !names["gh (Cursor)"] {
		t.Errorf("names = %v", names)
	}
}

func TestDiscoverExplicitErrors(t *testing.T) {
	if _, _, err := Discover([]string{filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("missing explicit config should fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{not json`), 0o644)
	if _, _, err := Discover([]string{bad}); err == nil {
		t.Error("invalid explicit config should fail")
	}
}

func TestDiscoverMCPXConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mcpx.yaml")
	os.WriteFile(p, []byte(`listen: ":8080"
servers:
  - name: local
    transport: stdio
    command: echo
  - name: remote
    url: http://localhost:3001
`), 0o644)
	servers, _, err := Discover([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 || servers[0].Transport != "stdio" || servers[1].URL != "http://localhost:3001" {
		t.Fatalf("servers = %+v", servers)
	}
}

func TestServerJSONOmitsSecrets(t *testing.T) {
	s := Server{Name: "x", Transport: "stdio", Command: "c", Env: map[string]string{"TOKEN": "s3cret"}, Headers: map[string]string{"Authorization": "Bearer s3cret"}}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "s3cret") {
		t.Fatalf("secret leaked: %s", b)
	}
}
