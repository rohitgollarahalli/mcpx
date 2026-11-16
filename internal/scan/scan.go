// Package scan implements `mcpx scan`: it finds the MCP servers configured
// in popular clients (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf,
// Gemini CLI, Cline) or in an mcpx.yaml, connects to each one, and inspects
// every tool definition for poisoning, prompt injection, hidden Unicode,
// exfiltration and shadowing attempts, and rug pulls against a baseline.
//
// The scanner only performs the MCP handshake and tools/list; it never
// calls a tool.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/integrity"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

// Options configures a scan.
type Options struct {
	// Paths are config files to scan. Empty means auto-discover.
	Paths []string
	// Timeout bounds each request to a server (default 45s, generous
	// enough for `npx -y` to download a server on first run).
	Timeout time.Duration
	// Concurrency is how many servers are scanned at once (default 4).
	Concurrency int
	// Baseline, when set, is a JSON file of tool hashes. Tools seen for the
	// first time are added to it; tools whose definition changed since are
	// reported as rug pulls.
	Baseline string
	// UpdateBaseline re-pins changed tools to their current definition.
	UpdateBaseline bool
	// Version is reported to servers as the client version.
	Version string
	// Progress, if set, is called as each server finishes.
	Progress func(r ServerResult)
}

// ServerResult is the outcome of scanning one server.
type ServerResult struct {
	Server
	ServerName   string            `json:"serverName,omitempty"`
	Version      string            `json:"serverVersion,omitempty"`
	Tools        []string          `json:"tools"`
	Error        string            `json:"error,omitempty"`
	Instructions string            `json:"-"`
	rawTools     []json.RawMessage // tool definitions as advertised
}

// Report is the full result of a scan.
type Report struct {
	Version         string         `json:"version"`
	Configs         []ConfigFile   `json:"configs"`
	Servers         []ServerResult `json:"servers"`
	Findings        []Finding      `json:"findings"`
	BaselineCreated bool           `json:"baselineCreated,omitempty"`
}

// Run discovers servers, fetches their tools, and analyzes them.
func Run(ctx context.Context, opts Options) (*Report, error) {
	servers, configs, err := Discover(opts.Paths)
	if err != nil {
		return nil, err
	}
	uniqueNames(servers)
	if opts.Timeout <= 0 {
		opts.Timeout = 45 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}

	results := make([]ServerResult, len(servers))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := ServerResult{Server: s, Tools: []string{}}
			if s.Skip != "" {
				r.Error = "skipped: " + s.Skip
			} else {
				inv, err := Fetch(ctx, s, opts.Timeout, opts.Version)
				if inv != nil {
					r.ServerName, r.Version, r.Instructions = inv.ServerName, inv.Version, inv.Instructions
					r.rawTools = inv.Tools
					for _, t := range inv.Tools {
						r.Tools = append(r.Tools, mcp.ToolName(t))
					}
				}
				if err != nil {
					r.Error = err.Error()
				}
			}
			results[i] = r
			if opts.Progress != nil {
				progressMu.Lock()
				opts.Progress(r)
				progressMu.Unlock()
			}
		}(i, s)
	}
	wg.Wait()

	rep := &Report{Version: opts.Version, Configs: configs, Servers: results}
	rep.Findings = Analyze(results)

	if opts.Baseline != "" {
		created, changed, err := applyBaseline(opts.Baseline, results, opts.UpdateBaseline)
		if err != nil {
			return nil, err
		}
		rep.BaselineCreated = created
		rep.Findings = append(rep.Findings, changed...)
	}
	sortFindings(rep.Findings)
	return rep, nil
}

// Analyze runs every rule over the scanned servers.
func Analyze(results []ServerResult) []Finding {
	var out []Finding
	tools := map[string][]string{}
	texts := map[string]map[string]string{}
	for _, r := range results {
		found := AnalyzeInstructions(r.Name, r.Instructions)
		texts[r.Name] = map[string]string{}
		for _, raw := range r.rawTools {
			found = append(found, AnalyzeTool(r.Name, raw)...)
			name := mcp.ToolName(raw)
			tools[r.Name] = append(tools[r.Name], name)
			var t struct {
				Description string `json:"description"`
			}
			_ = json.Unmarshal(raw, &t)
			texts[r.Name][name] = stripInvisible(t.Description)
		}
		for i := range found {
			found[i].Source = r.Source
		}
		out = append(out, found...)
	}
	cross := AnalyzeCrossServer(tools, texts)
	src := map[string]string{}
	for _, r := range results {
		src[r.Name] = r.Source
	}
	for i := range cross {
		cross[i].Source = src[cross[i].Server]
	}
	out = append(out, cross...)
	sortFindings(out)
	return out
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		return a.RuleID < b.RuleID
	})
}

// uniqueNames disambiguates servers that share a name across configs
// (e.g. two different "github" servers in Claude Desktop and Cursor).
func uniqueNames(servers []Server) {
	count := map[string]int{}
	for _, s := range servers {
		count[s.Name]++
	}
	used := map[string]bool{}
	for i := range servers {
		if count[servers[i].Name] < 2 {
			used[servers[i].Name] = true
			continue
		}
		base := servers[i].Name + " (" + servers[i].Client + ")"
		name := base
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s #%d", base, n)
		}
		used[name] = true
		servers[i].Name = name
	}
}

// --- baseline (rug-pull detection across scans) ------------------------------

type baselineFile struct {
	Version int                       `json:"version"`
	Servers map[string]baselineServer `json:"servers"`
}

type baselineServer struct {
	Target string            `json:"target"`
	Tools  map[string]string `json:"tools"` // tool name -> canonical SHA-256
}

// applyBaseline compares each scanned tool against the pinned hash. New
// servers and tools are pinned on first sight (trust on first use); changed
// tools become findings and keep their original pin unless update is set.
func applyBaseline(path string, results []ServerResult, update bool) (created bool, findings []Finding, err error) {
	bl := baselineFile{Version: 1, Servers: map[string]baselineServer{}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		created = true
	case err != nil:
		return false, nil, fmt.Errorf("reading baseline: %w", err)
	default:
		if err := json.Unmarshal(data, &bl); err != nil {
			return false, nil, fmt.Errorf("parsing baseline %s: %w", path, err)
		}
		if bl.Servers == nil {
			bl.Servers = map[string]baselineServer{}
		}
	}

	dirty := created
	for _, r := range results {
		if r.Error != "" && len(r.rawTools) == 0 {
			continue // do not forget pins for a server that is just down
		}
		bs, ok := bl.Servers[r.Name]
		if !ok {
			bs = baselineServer{Target: r.Target(), Tools: map[string]string{}}
			dirty = true
		}
		if bs.Tools == nil {
			bs.Tools = map[string]string{}
		}
		for _, raw := range r.rawTools {
			name := mcp.ToolName(raw)
			h := integrity.Hash(raw)
			old, seen := bs.Tools[name]
			switch {
			case !seen:
				bs.Tools[name] = h
				dirty = true
			case old != h:
				msg := "Definition changed since the baseline was recorded"
				if update {
					bs.Tools[name] = h
					dirty = true
					msg += " (baseline updated)"
				}
				f := newFinding(rule("tool-changed"), r.Name, name, "definition", msg,
					"was sha256:"+old[:12]+"…, now sha256:"+h[:12]+"…")
				f.Source = r.Source
				findings = append(findings, f)
			}
		}
		bl.Servers[r.Name] = bs
	}
	if dirty {
		out, err := json.MarshalIndent(bl, "", "  ")
		if err != nil {
			return created, findings, err
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			return created, findings, fmt.Errorf("writing baseline: %w", err)
		}
	}
	return created, findings, nil
}
