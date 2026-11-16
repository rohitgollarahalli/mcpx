package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/config"
)

func TestNewDisabled(t *testing.T) {
	l, err := New(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not panic when logging while disabled
	l.Log(Entry{Server: "test", Method: "tools/call", Allowed: true})
	l.LogJSON(Entry{Server: "test", Method: "tools/call", Allowed: true})
}

func TestNewFileRequiresPath(t *testing.T) {
	_, err := New(config.AuditConfig{Enabled: true, Output: "file", Path: ""})
	if err == nil {
		t.Fatal("expected error when file output has no path")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error should mention path, got: %v", err)
	}
}

func TestNewFileInvalidPath(t *testing.T) {
	_, err := New(config.AuditConfig{
		Enabled: true,
		Output:  "file",
		Path:    "/nonexistent/deeply/nested/dir/audit.log",
	})
	if err == nil {
		t.Fatal("expected error for invalid file path")
	}
}

func TestNewFileValidTempPath(t *testing.T) {
	path := t.TempDir() + "/audit.log"
	l, err := New(config.AuditConfig{Enabled: true, Output: "file", Path: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close() // release the file handle before t.TempDir cleanup (required on Windows)
	if !l.enabled {
		t.Fatal("logger should be enabled")
	}
}

func TestNewStdoutDefault(t *testing.T) {
	l, err := New(config.AuditConfig{Enabled: true, Output: "stdout"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !l.enabled {
		t.Fatal("logger should be enabled")
	}
}

func TestNewDefaultOutputIsStdout(t *testing.T) {
	l, err := New(config.AuditConfig{Enabled: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !l.enabled {
		t.Fatal("logger should be enabled with default output")
	}
}

func TestLogDisabledNoOp(t *testing.T) {
	l := &Logger{enabled: false}
	// Should not panic on either log method
	l.Log(Entry{Server: "s", Method: "m"})
	l.LogJSON(Entry{Server: "s", Method: "m"})
}

func TestEntryJSONSerialization(t *testing.T) {
	entry := Entry{
		Server:     "backend-1",
		Method:     "tools/call",
		Tool:       "read_file",
		ClientIP:   "127.0.0.1",
		Allowed:    true,
		DurationMs: 42,
		StatusCode: 200,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal entry: %v", err)
	}

	var decoded Entry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal entry: %v", err)
	}

	if decoded.Server != "backend-1" {
		t.Errorf("server = %q, want %q", decoded.Server, "backend-1")
	}
	if decoded.Tool != "read_file" {
		t.Errorf("tool = %q, want %q", decoded.Tool, "read_file")
	}
	if !decoded.Allowed {
		t.Error("allowed should be true")
	}
	if decoded.DurationMs != 42 {
		t.Errorf("duration_ms = %d, want 42", decoded.DurationMs)
	}
	if decoded.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", decoded.StatusCode)
	}
}

func TestEntryOmitsEmptyFields(t *testing.T) {
	entry := Entry{
		Server:  "s1",
		Method:  "initialize",
		Allowed: true,
	}

	data, _ := json.Marshal(entry)
	s := string(data)

	if strings.Contains(s, `"tool"`) {
		t.Error("empty tool should be omitted from JSON")
	}
	if strings.Contains(s, `"client_ip"`) {
		t.Error("empty client_ip should be omitted from JSON")
	}
	if strings.Contains(s, `"reason"`) {
		t.Error("empty reason should be omitted from JSON")
	}
}

func TestEntryDeniedWithReason(t *testing.T) {
	entry := Entry{
		Server:  "backend-1",
		Method:  "tools/call",
		Tool:    "dangerous_tool",
		Allowed: false,
		Reason:  "tool blocked by deny list",
	}

	data, _ := json.Marshal(entry)
	s := string(data)

	if !strings.Contains(s, `"allowed":false`) {
		t.Error("should contain allowed:false")
	}
	if !strings.Contains(s, `"reason":"tool blocked by deny list"`) {
		t.Error("should contain denial reason")
	}
}

func TestEntryRoundTrip(t *testing.T) {
	original := Entry{
		Server:     "srv",
		Method:     "tools/call",
		Tool:       "exec",
		ClientIP:   "10.0.0.1",
		Allowed:    false,
		Reason:     "rate limited",
		DurationMs: 150,
		StatusCode: 429,
	}

	data, _ := json.Marshal(original)
	var decoded Entry
	json.Unmarshal(data, &decoded)

	if decoded.Server != original.Server ||
		decoded.Method != original.Method ||
		decoded.Tool != original.Tool ||
		decoded.ClientIP != original.ClientIP ||
		decoded.Allowed != original.Allowed ||
		decoded.Reason != original.Reason ||
		decoded.DurationMs != original.DurationMs ||
		decoded.StatusCode != original.StatusCode {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", decoded, original)
	}
}
