package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rohitgollarahalli/mcpx/internal/config"
)

// Server is one MCP server found in a client or gateway config file.
type Server struct {
	Name      string            `json:"name"`
	Client    string            `json:"client"`    // e.g. "Claude Desktop", "Cursor", "mcpx"
	Source    string            `json:"source"`    // config file the server came from
	Transport string            `json:"transport"` // "stdio" or "http"
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"-"` // never serialized: often holds credentials
	Dir       string            `json:"-"`
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"-"` // never serialized: often holds credentials
	// Skip, when set, explains why the server cannot be scanned (an
	// unsupported transport, say). It is reported instead of connected to.
	Skip string `json:"skip,omitempty"`
}

// Target is a short human-readable description of what the server runs or
// connects to.
func (s Server) Target() string {
	if s.Transport == "stdio" {
		return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
	}
	return s.URL
}

// identity is used to de-duplicate a server that several clients configure
// identically: it is scanned once.
func (s Server) identity() string {
	if s.Transport == "stdio" {
		// Env is part of the identity: the same command with a different
		// environment (another account, another flag) may expose other tools.
		env := make([]string, 0, len(s.Env))
		for k, v := range s.Env {
			env = append(env, k+"="+v)
		}
		sort.Strings(env)
		return "stdio\x00" + s.Dir + "\x00" + s.Command + "\x00" + strings.Join(s.Args, "\x00") + "\x00\x00" + strings.Join(env, "\x00")
	}
	return "http\x00" + s.URL
}

// ConfigFile is a client config location that was checked during discovery.
type ConfigFile struct {
	Path    string `json:"path"`
	Client  string `json:"client"`
	Servers int    `json:"servers"`
}

type candidate struct {
	client string
	path   string
}

// knownConfigs lists the config files of popular MCP clients, relative to
// the user's home/config directories and the current working directory.
func knownConfigs() []candidate {
	var c []candidate
	home, _ := os.UserHomeDir()
	cfgDir, _ := os.UserConfigDir() // ~/.config, ~/Library/Application Support, or %AppData%
	cwd, _ := os.Getwd()
	add := func(client string, parts ...string) {
		for _, p := range parts {
			if p == "" {
				return
			}
		}
		c = append(c, candidate{client: client, path: filepath.Join(parts...)})
	}
	add("Claude Desktop", cfgDir, "Claude", "claude_desktop_config.json")
	add("Claude Code", home, ".claude.json")
	add("Claude Code", cwd, ".mcp.json")
	add("Cursor", home, ".cursor", "mcp.json")
	add("Cursor", cwd, ".cursor", "mcp.json")
	add("VS Code", cfgDir, "Code", "User", "mcp.json")
	add("VS Code", cwd, ".vscode", "mcp.json")
	add("Windsurf", home, ".codeium", "windsurf", "mcp_config.json")
	add("Gemini CLI", home, ".gemini", "settings.json")
	add("Cline", cfgDir, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
	add("mcpx", cwd, "mcpx.yaml")
	return c
}

// Discover loads servers from the given paths, or from every known MCP
// client config on this machine when paths is empty. Missing auto-discovered
// files are skipped silently; a missing or unparsable explicit path is an
// error. Servers configured identically in several places are returned once.
func Discover(paths []string) ([]Server, []ConfigFile, error) {
	explicit := len(paths) > 0
	var cands []candidate
	if explicit {
		for _, p := range paths {
			cands = append(cands, candidate{client: clientForPath(p), path: p})
		}
	} else {
		cands = knownConfigs()
	}

	var (
		servers []Server
		files   []ConfigFile
		seen    = map[string]bool{}
		seenCfg = map[string]bool{}
	)
	for _, cand := range cands {
		abs, err := filepath.Abs(cand.path)
		if err == nil {
			if seenCfg[abs] {
				continue
			}
			seenCfg[abs] = true
		}
		found, err := loadFile(cand.path, cand.client)
		if err != nil {
			if !explicit && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if explicit {
				return nil, nil, err
			}
			// A broken auto-discovered file should not abort the scan.
			files = append(files, ConfigFile{Path: cand.path, Client: cand.client, Servers: -1})
			continue
		}
		files = append(files, ConfigFile{Path: cand.path, Client: cand.client, Servers: len(found)})
		for _, s := range found {
			if seen[s.identity()] {
				continue
			}
			seen[s.identity()] = true
			servers = append(servers, s)
		}
	}
	return servers, files, nil
}

// clientForPath guesses which client an explicitly named config belongs to.
func clientForPath(p string) string {
	lp := strings.ToLower(filepath.ToSlash(p))
	switch {
	case strings.HasSuffix(lp, ".yaml"), strings.HasSuffix(lp, ".yml"):
		return "mcpx"
	case strings.Contains(lp, "claude_desktop"):
		return "Claude Desktop"
	case strings.Contains(lp, ".cursor/"):
		return "Cursor"
	case strings.Contains(lp, ".vscode/"), strings.Contains(lp, "/code/user/"):
		return "VS Code"
	case strings.Contains(lp, "windsurf"):
		return "Windsurf"
	case strings.Contains(lp, ".gemini/"):
		return "Gemini CLI"
	case strings.HasSuffix(lp, ".claude.json"), strings.HasSuffix(lp, ".mcp.json"):
		return "Claude Code"
	}
	return "config"
}

func loadFile(path, client string) ([]Server, error) {
	if client == "mcpx" {
		return loadMCPXConfig(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	servers, err := ParseClientConfig(data, path, client)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return servers, nil
}

// loadMCPXConfig scans the backends of an mcpx gateway config directly.
func loadMCPXConfig(path string) ([]Server, error) {
	cfg, err := config.LoadSkippingSpecURLs(path) // scan skips openapi backends anyway
	if err != nil {
		return nil, err
	}
	var out []Server
	for _, sc := range cfg.Servers {
		s := Server{Name: sc.Name, Client: "mcpx", Source: path}
		switch sc.Transport {
		case "stdio":
			s.Transport = "stdio"
			s.Command, s.Args, s.Env, s.Dir = sc.Command, sc.Args, sc.Env, sc.WorkDir
		case "openapi":
			s.Transport = "http"
			s.URL = sc.URL
			s.Skip = "openapi backends are generated by mcpx from a spec you control"
		default:
			s.Transport = "http"
			s.URL, s.Headers = sc.URL, sc.Headers
			if sc.TLS != nil {
				s.Skip = "backend TLS/mTLS settings are not supported by scan yet"
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// clientEntry is the union of the server shapes used by MCP clients.
type clientEntry struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	Cwd       string            `json:"cwd"`
	URL       string            `json:"url"`
	ServerURL string            `json:"serverUrl"` // Windsurf
	HTTPURL   string            `json:"httpUrl"`   // Gemini CLI
	Type      string            `json:"type"`
	Transport string            `json:"transport"`
	Headers   map[string]string `json:"headers"`
	Disabled  bool              `json:"disabled"`
}

// ParseClientConfig extracts MCP servers from a client's JSON (or JSONC)
// config. It understands the "mcpServers" map (Claude, Cursor, Windsurf,
// Gemini, Cline), the "servers" map (VS Code mcp.json), VS Code's
// "mcp.servers" settings key, and Claude Code's per-project servers in
// ~/.claude.json. Disabled servers are ignored.
func ParseClientConfig(data []byte, source, client string) ([]Server, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONC(data), &root); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	var out []Server
	addMap := func(raw json.RawMessage, prefix string) error {
		if len(raw) == 0 {
			return nil
		}
		var m map[string]clientEntry
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("parsing server map: %w", err)
		}
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			e := m[n]
			if e.Disabled {
				continue
			}
			out = append(out, entryToServer(prefix+n, e, source, client))
		}
		return nil
	}

	if err := addMap(root["mcpServers"], ""); err != nil {
		return nil, err
	}
	if err := addMap(root["servers"], ""); err != nil {
		return nil, err
	}
	if raw, ok := root["mcp"]; ok {
		var mcp struct {
			Servers json.RawMessage `json:"servers"`
		}
		if json.Unmarshal(raw, &mcp) == nil {
			if err := addMap(mcp.Servers, ""); err != nil {
				return nil, err
			}
		}
	}
	// Claude Code keeps per-project servers under projects.<path>.mcpServers.
	if raw, ok := root["projects"]; ok {
		var projects map[string]struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		if json.Unmarshal(raw, &projects) == nil {
			keys := make([]string, 0, len(projects))
			for k := range projects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := addMap(projects[k].MCPServers, filepath.Base(k)+"/"); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

func entryToServer(name string, e clientEntry, source, client string) Server {
	s := Server{Name: name, Client: client, Source: source}
	url := firstNonEmpty(e.URL, e.ServerURL, e.HTTPURL)
	switch {
	case e.Command != "":
		s.Transport = "stdio"
		s.Command, s.Args, s.Env, s.Dir = e.Command, e.Args, e.Env, e.Cwd
	case url != "":
		// Streamable HTTP. Servers on the deprecated HTTP+SSE transport
		// (type "sse") often answer it too; when they do not, the
		// connection error is reported for that server.
		s.Transport = "http"
		s.URL, s.Headers = url, e.Headers
	default:
		s.Transport = "unknown"
		s.Skip = "no command or url in config"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// stripJSONC removes // and /* */ comments and trailing commas so VS Code
// style JSONC files decode with encoding/json. String contents are preserved.
func stripJSONC(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	inStr, esc := false, false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if inStr {
			out.WriteByte(ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch {
		case ch == '"':
			inStr = true
			out.WriteByte(ch)
		case ch == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out.WriteByte('\n')
			}
		case ch == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && (data[i] != '*' || data[i+1] != '/') {
				i++
			}
			i++ // skip the closing '/'
		case ch == ',':
			// Drop the comma if the next significant byte closes a container.
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out.WriteByte(ch)
		default:
			out.WriteByte(ch)
		}
	}
	return out.Bytes()
}
