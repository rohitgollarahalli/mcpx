package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate_TLS(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEMPath := filepath.ToSlash(notPEM)
	cases := map[string]string{
		"url: http://localhost:1\n    tls:\n      ca_file: x":                                    "requires an https:// url",
		"url: https://localhost:1\n    tls:\n      cert_file: c.pem":                             "set together",
		"url: https://localhost:1\n    tls:\n      ca_file: /nonexistent/ca.pem":                 "reading ca_file",
		"url: https://localhost:1\n    tls:\n      ca_file: " + notPEMPath:                       "no PEM certificates",
		"url: https://localhost:1\n    tls:\n      min_version: \"1.1\"":                         "min_version",
		"url: https://localhost:1\n    tls:\n      insecure_skip_verify: true\n      ca_file: x": "set one or the other",
		"transport: stdio\n    command: x\n    tls:\n      min_version: \"1.3\"":                 "only valid with transport",
	}
	for body, want := range cases {
		_, err := loadFromStringErr("servers:\n  - name: s\n    " + body + "\n")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("server {%s}: error = %v, want containing %q", body, err, want)
		}
	}
	cfg := loadFromString(t, "servers:\n  - name: s\n    url: https://localhost:1\n    tls:\n      min_version: \"1.3\"\n")
	if cfg.Servers[0].TLS == nil || cfg.Servers[0].TLS.MinVersion != "1.3" {
		t.Errorf("tls not parsed: %+v", cfg.Servers[0].TLS)
	}
}
