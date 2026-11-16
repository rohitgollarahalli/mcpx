// Package integrity implements tool-schema pinning for the MCP gateway.
//
// On the first tools/list response from a backend, the gateway records a
// SHA-256 hash of each tool's full schema (name, description, and input
// schema). On subsequent responses, any tool whose schema differs from its
// pinned baseline is reported as a violation. This deterministically detects
// "rug-pull" tool mutation (CVE-2025-54136), cross-server shadowing, and
// full-schema poisoning — attacks where a server silently changes a tool the
// client already approved. See https://github.com/rohitgollarahalli/mcpx ROADMAP.
//
// Hashing the entire tool object (not just the description) is deliberate:
// poisoning payloads have been demonstrated in parameter names, enums, and
// defaults, so any change to the advertised contract is worth flagging.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

// Mode controls how the gateway reacts to a tool-schema change.
type Mode string

const (
	// ModeOff disables pinning entirely (no hashing, no overhead).
	ModeOff Mode = "off"
	// ModeWarn records baselines and reports violations but lets the
	// changed tool through unchanged.
	ModeWarn Mode = "warn"
	// ModeEnforce reports violations and drops the changed tool from the
	// advertised list so clients cannot invoke a mutated tool.
	ModeEnforce Mode = "enforce"
)

// ParseMode maps a config string to a Mode, defaulting to ModeOff for empty
// or unrecognized values.
func ParseMode(s string) Mode {
	switch Mode(s) {
	case ModeWarn:
		return ModeWarn
	case ModeEnforce:
		return ModeEnforce
	default:
		return ModeOff
	}
}

// Violation describes a tool whose schema changed since it was first pinned.
type Violation struct {
	Server  string
	Tool    string
	OldHash string
	NewHash string
}

// Store holds the pinned baseline hashes. It is safe for concurrent use and is
// intended to be created once and shared across config hot-reloads so the
// baseline survives reloads (mirroring the metrics collector).
type Store struct {
	mu   sync.Mutex
	pins map[string]string // key: server + "\x00" + tool -> schema hash
	mode Mode
}

// NewStore returns a Store operating in the given mode.
func NewStore(mode Mode) *Store {
	return &Store{pins: make(map[string]string), mode: mode}
}

// Mode reports the store's configured mode.
func (s *Store) Mode() Mode { return s.mode }

// Enabled reports whether pinning is active (warn or enforce).
func (s *Store) Enabled() bool { return s.mode == ModeWarn || s.mode == ModeEnforce }

func key(server, tool string) string { return server + "\x00" + tool }

// Check hashes each tool's full schema and compares it against the pinned
// baseline for the given server. Tools seen for the first time are recorded
// silently and are not violations. Tools whose schema differs from the
// baseline are returned as violations; the original baseline is retained so a
// persistent mutation keeps being reported rather than silently re-pinned.
func (s *Store) Check(server string, tools []json.RawMessage) []Violation {
	if !s.Enabled() {
		return nil
	}
	var violations []Violation
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range tools {
		name := mcp.ToolName(raw)
		h := canonicalHash(raw)
		k := key(server, name)
		old, ok := s.pins[k]
		if !ok {
			s.pins[k] = h
			continue
		}
		if old != h {
			violations = append(violations, Violation{Server: server, Tool: name, OldHash: old, NewHash: h})
		}
	}
	return violations
}

// Hash returns the canonical SHA-256 of a tool definition: the same value the
// gateway pins, independent of key order and whitespace. It lets other
// components (such as `mcpx scan` baselines) compare tools consistently.
func Hash(raw json.RawMessage) string { return canonicalHash(raw) }

// canonicalHash returns a stable SHA-256 over a tool's JSON, independent of
// key ordering or insignificant whitespace. json.Marshal sorts object keys, so
// decoding to any and re-encoding yields a canonical form. Invalid JSON hashes
// to the hash of the raw bytes (still deterministic, still change-detecting).
func canonicalHash(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err == nil {
		if b, err := json.Marshal(v); err == nil {
			sum := sha256.Sum256(b)
			return hex.EncodeToString(sum[:])
		}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
