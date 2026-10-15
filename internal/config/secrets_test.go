package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandSecrets(t *testing.T) {
	t.Setenv("MCPX_TEST_TOKEN", "s3cret")
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("from-file\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"${env:MCPX_TEST_TOKEN}", "s3cret"},
		{"Bearer ${env:MCPX_TEST_TOKEN}", "Bearer s3cret"},
		{"${file:" + file + "}", "from-file"},
		{"${env:MCPX_TEST_TOKEN}:${file:" + file + "}", "s3cret:from-file"},
		{"$${env:MCPX_TEST_TOKEN}", "${env:MCPX_TEST_TOKEN}"},
		{"cost $5", "cost $5"},
	}
	for _, c := range cases {
		got, err := expandSecrets(c.in, "test")
		if err != nil {
			t.Errorf("expandSecrets(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("expandSecrets(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExpandSecrets_FailsClosed(t *testing.T) {
	t.Setenv("MCPX_TEST_EMPTY", "")
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"${env:MCPX_TEST_DEFINITELY_UNSET}": "not set",
		"${env:MCPX_TEST_EMPTY}":            "empty value",
		"${file:" + empty + "}":             "empty value",
		"${file:/nonexistent/mcpx/secret}":  "reading secret file",
		"${vault:kv/token}":                 "unknown secret provider",
		"${env:}":                           "invalid secret reference",
		"${MCPX_TEST_TOKEN}":                "invalid secret reference",
		"Bearer ${env:MCPX_TEST_TOKEN":      "unterminated",
	}
	for in, want := range cases {
		_, err := expandSecrets(in, "test")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expandSecrets(%q) error = %v, want containing %q", in, err, want)
		}
	}
}

func TestLoad_ResolvesSecrets(t *testing.T) {
	t.Setenv("MCPX_TEST_BACKEND", "backend-key")
	t.Setenv("MCPX_TEST_GATEWAY", "gateway-key")
	t.Setenv("MCPX_TEST_CHILD", "child-key")
	cfg := loadFromString(t, `
servers:
  - name: remote
    url: http://localhost:3001
    headers:
      Authorization: "Bearer ${env:MCPX_TEST_BACKEND}"
  - name: local
    transport: stdio
    command: some-mcp
    env:
      API_KEY: ${env:MCPX_TEST_CHILD}
auth:
  enabled: true
  type: bearer
  clients:
    - name: alice
      token: ${env:MCPX_TEST_GATEWAY}
`)
	if got := cfg.Servers[0].Headers["Authorization"]; got != "Bearer backend-key" {
		t.Errorf("header = %q", got)
	}
	if got := cfg.Servers[1].Env["API_KEY"]; got != "child-key" {
		t.Errorf("env = %q", got)
	}
	if got := cfg.Auth.Clients[0].Token; got != "gateway-key" {
		t.Errorf("client token = %q", got)
	}
}

func TestLoad_SecretErrorDoesNotLeakValue(t *testing.T) {
	t.Setenv("MCPX_TEST_MULTILINE", "line1\nline2-SECRET")
	_, err := loadFromStringErr(`
servers:
  - name: remote
    url: http://localhost:3001
    headers:
      X-Key: ${env:MCPX_TEST_MULTILINE}
`)
	if err == nil || !strings.Contains(err.Error(), "CR, LF, or NUL") {
		t.Fatalf("want CR/LF rejection, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error leaks the secret value: %v", err)
	}
}

func TestValidate_Headers(t *testing.T) {
	cases := map[string]string{
		"Host: evil":            "managed by the proxy",
		"content-length: \"1\"": "managed by the proxy",
		"\"Bad Header\": x":     "invalid header name",
		"X-A: a\n      x-a: b":  "duplicate header",
	}
	for hdr, want := range cases {
		_, err := loadFromStringErr("servers:\n  - name: s\n    url: http://localhost:1\n    headers:\n      " + hdr + "\n")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("headers {%s}: error = %v, want containing %q", hdr, err, want)
		}
	}
	_, err := loadFromStringErr(`
servers:
  - name: s
    transport: stdio
    command: x
    headers:
      X-Key: v
`)
	if err == nil || !strings.Contains(err.Error(), "only valid with transport") {
		t.Errorf("stdio headers: error = %v", err)
	}
}
