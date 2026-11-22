package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Counts tallies findings by severity.
func (r *Report) Counts() map[Severity]int {
	c := map[Severity]int{}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// Worst returns the highest severity found, or -1 when there are none.
func (r *Report) Worst() Severity {
	w := Severity(-1)
	for _, f := range r.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// ToolCount is the number of tools inspected across all servers.
func (r *Report) ToolCount() int {
	n := 0
	for _, s := range r.Servers {
		n += len(s.Tools)
	}
	return n
}

// --- text ---------------------------------------------------------------------

type palette struct{ on bool }

func (p palette) c(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p palette) bold(s string) string  { return p.c("1", s) }
func (p palette) dim(s string) string   { return p.c("2", s) }
func (p palette) green(s string) string { return p.c("32", s) }
func (p palette) red(s string) string   { return p.c("31", s) }

func (p palette) sev(s Severity) string {
	label := fmt.Sprintf("%-8s", strings.ToUpper(s.String()))
	switch s {
	case SevCritical:
		return p.c("1;97;41", label)
	case SevHigh:
		return p.c("1;31", label)
	case SevMedium:
		return p.c("33", label)
	case SevLow:
		return p.c("36", label)
	default:
		return p.c("2", label)
	}
}

// ColorEnabled reports whether ANSI colors should be used for w: only for a
// terminal, and never when NO_COLOR is set (https://no-color.org).
func ColorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// TextOptions controls the human-readable report.
type TextOptions struct {
	Color bool
	// MinSeverity hides findings below it (they still count in the summary).
	MinSeverity Severity
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer, o TextOptions) {
	p := palette{on: o.Color}
	fmt.Fprintf(w, "%s %s\n\n", p.bold("mcpx scan"), p.dim("· MCP tool poisoning & security scanner"))

	if len(r.Configs) == 0 {
		fmt.Fprintln(w, "No MCP client configs found. Pass one explicitly:")
		fmt.Fprintln(w, "  mcpx scan path/to/claude_desktop_config.json")
		return
	}
	fmt.Fprintln(w, p.bold("Configs"))
	for _, c := range r.Configs {
		switch c.Servers {
		case -1:
			fmt.Fprintf(w, "  %s  %s %s\n", p.red("✗"), tildify(c.Path), p.dim("("+c.Client+", unreadable)"))
		default:
			fmt.Fprintf(w, "  %s  %s %s\n", p.dim("•"), tildify(c.Path), p.dim(fmt.Sprintf("(%s, %s)", c.Client, plural(c.Servers, "server"))))
		}
	}
	fmt.Fprintln(w)

	byServer := map[string][]Finding{}
	for _, f := range r.Findings {
		byServer[f.Server] = append(byServer[f.Server], f)
	}
	hidden := 0
	fmt.Fprintln(w, p.bold("Servers"))
	for _, s := range r.Servers {
		fs := byServer[s.Name]
		var status string
		switch {
		case s.Error != "" && len(s.Tools) == 0:
			status = p.red("✗ " + s.Error)
		case countAtLeast(fs, SevLow) == 0:
			status = p.green("✓ no issues")
		default:
			status = p.red(plural(countAtLeast(fs, SevLow), "issue"))
		}
		fmt.Fprintf(w, "\n  %s  %s  %s\n", p.bold(s.Name), p.dim(s.Transport+" · "+clip(s.Target(), 60)), p.dim(plural(len(s.Tools), "tool")))
		fmt.Fprintf(w, "     %s\n", status)
		if s.Error != "" && len(s.Tools) > 0 {
			fmt.Fprintf(w, "     %s\n", p.red("! "+s.Error))
		}
		for _, f := range fs {
			if f.Severity < o.MinSeverity {
				hidden++
				continue
			}
			where := f.Location
			if f.Tool != "" {
				where = f.Tool + " › " + f.Location
			}
			fmt.Fprintf(w, "     %s %s  %s\n", p.sev(f.Severity), p.bold(f.Rule), p.dim(where))
			fmt.Fprintf(w, "              %s\n", f.Message)
			if f.Evidence != "" {
				fmt.Fprintf(w, "              %s\n", p.dim("“"+f.Evidence+"”"))
			}
		}
	}

	c := r.Counts()
	fmt.Fprintf(w, "\n%s  %s, %s inspected — ", p.bold("Summary"), plural(len(r.Servers), "server"), plural(r.ToolCount(), "tool"))
	var parts []string
	for s := SevCritical; s >= SevInfo; s-- {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	if len(parts) == 0 {
		fmt.Fprintln(w, p.green("no issues found"))
	} else {
		fmt.Fprintln(w, strings.Join(parts, ", "))
	}
	if hidden > 0 {
		fmt.Fprintln(w, p.dim(fmt.Sprintf("         %s hidden; show with --min-severity info", plural(hidden, "lower-severity finding"))))
	}
	if r.BaselineCreated {
		fmt.Fprintln(w, p.dim("         Baseline recorded. Re-run with the same --baseline to detect rug pulls."))
	}
	if r.Worst() >= SevMedium || c[SevInfo] > 0 {
		fmt.Fprintf(w, "\n%s Put mcpx in front of these servers to block flagged tools, pin tool\n", p.bold("Next:"))
		fmt.Fprintln(w, "      definitions, and audit every call:")
		fmt.Fprintln(w, "        mcpx scan --emit-config > mcpx.yaml && mcpx -c mcpx.yaml")
	}
}

func countAtLeast(fs []Finding, min Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity >= min {
			n++
		}
	}
	return n
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func tildify(p string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && strings.HasPrefix(p, home+string(filepath.Separator)) {
		return "~" + p[len(home):]
	}
	return p
}

// --- JSON -----------------------------------------------------------------------

// WriteJSON renders the report as JSON for scripts and CI.
func (r *Report) WriteJSON(w io.Writer) error {
	type summary struct {
		Servers  int            `json:"servers"`
		Tools    int            `json:"tools"`
		Findings map[string]int `json:"findings"`
	}
	c := r.Counts()
	sum := summary{Servers: len(r.Servers), Tools: r.ToolCount(), Findings: map[string]int{}}
	for s := SevInfo; s <= SevCritical; s++ {
		sum.Findings[s.String()] = c[s]
	}
	out := struct {
		*Report
		Summary summary `json:"summary"`
	}{r, sum}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- SARIF ------------------------------------------------------------------------

// WriteSARIF renders the report as SARIF 2.1.0 so findings show up in
// GitHub code scanning and other static-analysis dashboards.
func (r *Report) WriteSARIF(w io.Writer) error {
	level := func(s Severity) string {
		switch {
		case s >= SevHigh:
			return "error"
		case s == SevMedium:
			return "warning"
		default:
			return "note"
		}
	}
	type msg struct {
		Text string `json:"text"`
	}
	var rules []map[string]any
	for _, ru := range Rules {
		rules = append(rules, map[string]any{
			"id":                   ru.ID,
			"name":                 ru.Name,
			"shortDescription":     msg{ru.Summary},
			"defaultConfiguration": map[string]string{"level": level(ru.Severity)},
			"properties":           map[string]any{"tags": []string{"security", "mcp"}, "security-severity": securityScore(ru.Severity)},
		})
	}
	results := []map[string]any{}
	for _, f := range r.Findings {
		text := fmt.Sprintf("[%s] server %q", f.Rule, f.Server)
		if f.Tool != "" {
			text += fmt.Sprintf(", tool %q", f.Tool)
		}
		text += fmt.Sprintf(" (%s): %s", f.Location, f.Message)
		if f.Evidence != "" {
			text += " — " + f.Evidence
		}
		uri := filepath.ToSlash(f.Source)
		if uri == "" {
			uri = "mcp"
		}
		results = append(results, map[string]any{
			"ruleId":  f.RuleID,
			"level":   level(f.Severity),
			"message": msg{text},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": uri}},
				"logicalLocations": []map[string]string{{"name": f.Tool, "fullyQualifiedName": f.Server + "/" + f.Tool + "#" + f.Location, "kind": "function"}},
			}},
			"partialFingerprints": map[string]string{"mcpx/v1": f.RuleID + ":" + f.Server + ":" + f.Tool + ":" + f.Location},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": sarifDriver(r.Version, rules)},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// securityScore maps a severity onto GitHub's 0-10 security-severity scale.
func securityScore(s Severity) string {
	return [...]string{"1.0", "3.0", "5.5", "8.0", "9.5"}[s]
}

// --- gateway config ------------------------------------------------------------------

var nameSanitizer = regexp.MustCompile(`[^a-z0-9_-]+`)

// WriteGatewayConfig emits an mcpx.yaml that fronts every scanned server:
// tool integrity pinning in enforce mode, tools/list filtering, audit
// logging, and deny rules for every tool with a high or critical finding.
// Secret values from client configs are never copied; they become
// ${env:NAME} references instead.
func (r *Report) WriteGatewayConfig(w io.Writer) {
	deny := map[string]map[string]string{} // server -> tool -> reason
	for _, f := range r.Findings {
		if f.Tool == "" || f.Severity < SevHigh {
			continue
		}
		if deny[f.Server] == nil {
			deny[f.Server] = map[string]string{}
		}
		if _, ok := deny[f.Server][f.Tool]; !ok {
			deny[f.Server][f.Tool] = f.Severity.String() + ": " + f.Rule
		}
	}

	q := strconv.Quote
	fmt.Fprintf(w, "# mcpx gateway config generated by `mcpx scan --emit-config` on %s.\n", time.Now().Format("2006-01-02"))
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Start it with:   mcpx -c mcpx.yaml")
	fmt.Fprintln(w, "# Then point each MCP client at http://localhost:8080/mcp/<name> instead of")
	fmt.Fprintln(w, "# the server itself. Tools flagged high/critical by the scan are denied below.")
	fmt.Fprintln(w, "# Secret values were NOT copied: export the referenced environment variables.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, `listen: "127.0.0.1:8080"`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "inspection:")
	fmt.Fprintln(w, "  tool_integrity: enforce   # drop any tool whose definition changes (rug pulls)")
	fmt.Fprintln(w, "  filter_tools_list: true   # hide denied tools from clients")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "audit:")
	fmt.Fprintln(w, "  enabled: true")
	fmt.Fprintln(w, "  output: stdout")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "rate_limit:")
	fmt.Fprintln(w, "  enabled: true")
	fmt.Fprintln(w, "  rps: 20")
	fmt.Fprintln(w, "  burst: 40")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "servers:")

	used := map[string]bool{}
	wrote := 0
	for _, s := range r.Servers {
		if s.Transport != "stdio" && s.Transport != "http" {
			continue
		}
		name := strings.Trim(nameSanitizer.ReplaceAllString(strings.ToLower(s.Name), "-"), "-")
		if name == "" {
			name = "server"
		}
		base := name
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		used[name] = true
		wrote++

		fmt.Fprintf(w, "  - name: %s\n", q(name))
		fmt.Fprintf(w, "    # from %s (%s)\n", tildify(s.Source), s.Client)
		if s.Transport == "stdio" {
			fmt.Fprintln(w, "    transport: stdio")
			fmt.Fprintf(w, "    command: %s\n", q(s.Command))
			if len(s.Args) > 0 {
				fmt.Fprintln(w, "    args:")
				for _, a := range s.Args {
					fmt.Fprintf(w, "      - %s\n", q(a))
				}
			}
			if s.Dir != "" {
				fmt.Fprintf(w, "    workdir: %s\n", q(s.Dir))
			}
			writeSecretMap(w, "env", s.Env)
		} else {
			fmt.Fprintf(w, "    url: %s\n", q(s.URL))
			writeSecretMap(w, "headers", s.Headers)
		}
		if d := deny[s.Name]; len(d) > 0 {
			tools := make([]string, 0, len(d))
			for t := range d {
				tools = append(tools, t)
			}
			sort.Strings(tools)
			fmt.Fprintln(w, "    policy:")
			fmt.Fprintln(w, "      deny_tools:")
			for _, t := range tools {
				fmt.Fprintf(w, "        - %s   # %s\n", q(t), d[t])
			}
		}
	}
	if wrote == 0 {
		fmt.Fprintln(w, "  [] # no scannable servers were found")
	}
}

// writeSecretMap writes env/headers with every value replaced by an
// ${env:NAME} reference, so credentials never land in the generated file.
func writeSecretMap(w io.Writer, key string, m map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "    %s:\n", key)
	for _, k := range keys {
		envName := strings.ToUpper(nameSanitizer.ReplaceAllString(strings.ToLower(k), "_"))
		envName = strings.Trim(strings.ReplaceAll(envName, "-", "_"), "_")
		if envName == "" {
			envName = "MCPX_SECRET"
		}
		fmt.Fprintf(w, "      %s: %s\n", strconv.Quote(k), strconv.Quote("${env:"+envName+"}"))
	}
}

// sarifDriver builds the SARIF tool.driver object. SARIF 2.1.0
// requires semanticVersion to be a SemVer string, so it is only set when the
// version looks like one; the free-form version property is always set.
func sarifDriver(version string, rules any) map[string]any {
	d := map[string]any{
		"name":           "mcpx",
		"version":        version,
		"informationUri": "https://github.com/rohitgollarahalli/mcpx",
		"rules":          rules,
	}
	if version != "" && version[0] >= '0' && version[0] <= '9' {
		d["semanticVersion"] = version
	}
	return d
}
