package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseInterspersed(t *testing.T) {
	cases := []struct {
		args       []string
		wantPaths  []string
		wantFormat string
	}{
		{nil, nil, "text"},
		{[]string{"a.json"}, []string{"a.json"}, "text"},
		{[]string{"--format", "json", "a.json"}, []string{"a.json"}, "json"},
		{[]string{"a.json", "--format", "json", "b.json"}, []string{"a.json", "b.json"}, "json"},
		{[]string{"a.json", "--", "--format"}, []string{"a.json", "--format"}, "text"},
		// "--" as a flag's value is not a terminator.
		{[]string{"--format", "--", "a.json", "--format", "json"}, []string{"a.json"}, "json"},
		{[]string{"--verbose", "--", "--format"}, []string{"--format"}, "text"},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		format := fs.String("format", "text", "")
		fs.Bool("verbose", false, "")
		got, err := parseInterspersed(fs, c.args)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if !reflect.DeepEqual(got, c.wantPaths) || *format != c.wantFormat {
			t.Errorf("%v: paths=%v format=%q, want %v %q", c.args, got, *format, c.wantPaths, c.wantFormat)
		}
	}
}

func TestRunScanUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "xml"},
		{"--fail-on", "severe"},
		{"--min-severity", "nope"},
		{"--update-baseline"},
		{"--timeout", "0s"},
		{"--no-such-flag"},
		{"--emit-config", "--format", "sarif"},
	} {
		var out, errOut bytes.Buffer
		if code := runScan(args, &out, &errOut); code != scanExitError {
			t.Errorf("%v: exit %d, want %d (stderr: %s)", args, code, scanExitError, errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := runScan([]string{"-h"}, &out, &errOut); code != scanExitOK || !strings.Contains(errOut.String(), "Usage: mcpx scan") {
		t.Errorf("-h: exit %d, stderr %q", code, errOut.String())
	}
}

// TestRunScanPoisonedDemo scans the bundled malicious demo server end to end
// through the CLI: report formats, exit codes, and baseline creation.
func TestRunScanPoisonedDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the poisoned demo server")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "poisoned-mcp")
	build := exec.Command("go", "build", "-o", bin, "../../examples/poisoned-mcp")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building demo server: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "mcp.json")
	conf, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"utils": map[string]any{"command": bin},
	}})
	if err := os.WriteFile(cfg, conf, 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (int, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runScan(args, &out, &errOut)
		if code == scanExitError {
			t.Fatalf("%v: exit %d: %s", args, code, errOut.String())
		}
		return code, out.String()
	}

	code, text := run(cfg)
	if code != scanExitFindings || !strings.Contains(text, "hidden-unicode") {
		t.Errorf("text: exit %d, want %d with a hidden-unicode finding:\n%s", code, scanExitFindings, text)
	}

	if code, _ := run("--fail-on", "none", cfg); code != scanExitOK {
		t.Errorf("--fail-on none: exit %d, want 0", code)
	}

	_, js := run(cfg, "--format", "json") // flag after the path
	var rep struct {
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(js), &rep); err != nil || len(rep.Findings) == 0 {
		t.Errorf("json: err=%v findings=%d\n%s", err, len(rep.Findings), js)
	}

	_, sarif := run("--format", "sarif", cfg)
	if !strings.Contains(sarif, `"version": "2.1.0"`) {
		t.Errorf("sarif output missing version:\n%.300s", sarif)
	}

	_, yml := run("--emit-config", cfg)
	if !strings.Contains(yml, "servers:") {
		t.Errorf("emit-config output is not a gateway config:\n%s", yml)
	}

	bl := filepath.Join(dir, "baseline.json")
	run("--fail-on", "none", "--baseline", bl, cfg)
	if _, err := os.Stat(bl); err != nil {
		t.Errorf("baseline not written: %v", err)
	}
}

func TestRunScanUnscannedServerIsAnError(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "mcp.json")
	conf := `{"mcpServers": {"gone": {"command": "/nonexistent/mcp-server"}}}`
	if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runScan([]string{"--timeout", "5s", cfg}, &out, &errOut)
	if code != scanExitError || !strings.Contains(errOut.String(), "could not be scanned") {
		t.Errorf("exit %d, want %d; stderr: %s", code, scanExitError, errOut.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestErrWriterKeepsFirstError(t *testing.T) {
	w := &errWriter{w: failingWriter{}}
	_, _ = w.Write([]byte("a"))
	_, _ = w.Write([]byte("b"))
	if w.err != os.ErrClosed {
		t.Errorf("err = %v, want %v", w.err, os.ErrClosed)
	}
}

func TestRunScanNothingCheckedIsAnError(t *testing.T) {
	dir := t.TempDir()
	for name, conf := range map[string]string{
		"empty":   `{"mcpServers": {}}`,
		"skipped": `{"mcpServers": {"x": {}}}`, // no command or url: skipped
	} {
		cfg := filepath.Join(dir, name+".json")
		if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if code := runScan([]string{cfg}, &out, &errOut); code != scanExitError {
			t.Errorf("%s: exit %d, want %d; stderr: %s", name, code, scanExitError, errOut.String())
		}
	}
}
