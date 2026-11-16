// Package audit provides structured audit logging for MCP gateway events.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/config"
)

type Logger struct {
	logger  *slog.Logger
	enabled bool
	closer  io.Closer // underlying file when output is "file"; nil otherwise
}

type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Server     string    `json:"server"`
	Method     string    `json:"method"`
	Tool       string    `json:"tool,omitempty"`
	Client     string    `json:"client,omitempty"` // authenticated client identity
	ClientIP   string    `json:"client_ip,omitempty"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason,omitempty"`
	Cache      string    `json:"cache,omitempty"` // response cache outcome: "hit" or "miss"
	DurationMs int64     `json:"duration_ms,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
}

func New(cfg config.AuditConfig) (*Logger, error) {
	if !cfg.Enabled {
		return &Logger{enabled: false}, nil
	}
	var w io.Writer
	var closer io.Closer
	switch cfg.Output {
	case "file":
		if cfg.Path == "" {
			return nil, fmt.Errorf("audit: file output requires a path")
		}
		f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("audit: opening log file: %w", err)
		}
		w = f
		closer = f
	default:
		w = os.Stdout
	}
	return &Logger{logger: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})), enabled: true, closer: closer}, nil
}

// Close releases the underlying log file, if any. It is safe to call on a
// disabled logger or one writing to stdout (both are no-ops).
func (l *Logger) Close() error {
	if l.closer == nil {
		return nil
	}
	return l.closer.Close()
}

func (l *Logger) Log(entry Entry) {
	if !l.enabled {
		return
	}
	a := []any{"server", entry.Server, "method", entry.Method, "allowed", entry.Allowed}
	if entry.Tool != "" {
		a = append(a, "tool", entry.Tool)
	}
	if entry.Client != "" {
		a = append(a, "client", entry.Client)
	}
	if entry.ClientIP != "" {
		a = append(a, "client_ip", entry.ClientIP)
	}
	if entry.Reason != "" {
		a = append(a, "reason", entry.Reason)
	}
	if entry.Cache != "" {
		a = append(a, "cache", entry.Cache)
	}
	if entry.DurationMs > 0 {
		a = append(a, "duration_ms", entry.DurationMs)
	}
	l.logger.Info("mcp.request", a...)
}

func (l *Logger) LogJSON(entry Entry) {
	if !l.enabled {
		return
	}
	entry.Timestamp = time.Now().UTC()
	data, _ := json.Marshal(entry)
	fmt.Println(string(data))
}
