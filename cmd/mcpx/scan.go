package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/scan"
)

// Exit codes for `mcpx scan`.
const (
	scanExitOK       = 0 // no finding at or above --fail-on
	scanExitFindings = 1 // at least one finding at or above --fail-on
	scanExitError    = 2 // bad usage, or the scan could not cover every server
	scanExitSignal   = 130
)

const scanUsage = `Usage: mcpx scan [flags] [config ...]

Find the MCP servers configured in Claude Desktop, Claude Code, Cursor,
VS Code, Windsurf, Gemini CLI, Cline (or in the given config files), list
their tools, and check every tool definition for poisoning, prompt
injection, hidden Unicode, exfiltration, shadowing, and rug pulls.

The scanner runs only the MCP handshake and tools/list; it never calls a
tool. stdio servers are started the way your client starts them.

Exit status: 0 clean, 1 a finding at or above --fail-on, 2 an error,
including no configs found or a server that could not be scanned (so a
broken setup never passes a CI gate as clean), 130 interrupted.

Flags:
`

// runScan implements the `mcpx scan` subcommand and returns the exit code.
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcpx scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json, or sarif")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding is at or above this severity (info, low, medium, high, critical, or none)")
	minSev := fs.String("min-severity", "info", "text output: hide findings below this severity (they still count in the summary)")
	baseline := fs.String("baseline", "", "baseline file of tool hashes; created on first run, later scans flag changed tools (rug pulls)")
	updateBaseline := fs.Bool("update-baseline", false, "with --baseline: re-pin changed tools to their current definition")
	emitConfig := fs.Bool("emit-config", false, "write an mcpx.yaml that fronts the scanned servers and denies high/critical tools, instead of a report")
	timeout := fs.Duration("timeout", 45*time.Second, "per-request timeout for each server")
	concurrency := fs.Int("concurrency", 4, "servers to scan at once")
	noColor := fs.Bool("no-color", false, "disable colored text output")
	fs.Usage = func() {
		fmt.Fprint(stderr, scanUsage)
		fs.PrintDefaults()
	}

	paths, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return scanExitOK
		}
		return scanExitError
	}

	*format = strings.ToLower(*format)
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "mcpx scan: unknown --format %q (want text, json, or sarif)\n", *format)
		return scanExitError
	}
	failThreshold, failNever := scan.Severity(0), strings.EqualFold(*failOn, "none")
	if !failNever {
		if failThreshold, err = scan.ParseSeverity(*failOn); err != nil {
			fmt.Fprintf(stderr, "mcpx scan: --fail-on: %v\n", err)
			return scanExitError
		}
	}
	minSeverity, err := scan.ParseSeverity(*minSev)
	if err != nil {
		fmt.Fprintf(stderr, "mcpx scan: --min-severity: %v\n", err)
		return scanExitError
	}
	if *updateBaseline && *baseline == "" {
		fmt.Fprintln(stderr, "mcpx scan: --update-baseline requires --baseline")
		return scanExitError
	}
	if *emitConfig && *format != "text" {
		fmt.Fprintln(stderr, "mcpx scan: --emit-config writes YAML and cannot be combined with --format")
		return scanExitError
	}
	if *timeout <= 0 || *concurrency <= 0 {
		fmt.Fprintln(stderr, "mcpx scan: --timeout and --concurrency must be positive")
		return scanExitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := scan.Options{
		Paths:          paths,
		Timeout:        *timeout,
		Concurrency:    *concurrency,
		Baseline:       *baseline,
		UpdateBaseline: *updateBaseline,
		Version:        version,
	}
	// Live progress only for a human watching a terminal; it goes to stderr
	// so it never mixes into piped JSON, SARIF, or YAML.
	if *format == "text" && !*emitConfig && isTerminal(stderr) {
		opts.Progress = func(r scan.ServerResult) {
			status := fmt.Sprintf("%d tools", len(r.Tools))
			if r.Error != "" {
				status = r.Error
			}
			fmt.Fprintf(stderr, "  scanned %s: %s\n", r.Name, status)
		}
	}

	rep, err := scan.Run(ctx, opts)
	if ctx.Err() != nil {
		// Servers cut off mid-scan report no findings; never pass that off
		// as a clean (or partial) result.
		fmt.Fprintln(stderr, "mcpx scan: interrupted")
		return scanExitSignal
	}
	if err != nil {
		fmt.Fprintf(stderr, "mcpx scan: %v\n", err)
		return scanExitError
	}

	// WriteText and WriteGatewayConfig do not return errors; record the
	// first write failure so a truncated config or report is not exit 0.
	out := &errWriter{w: stdout}
	switch {
	case *emitConfig:
		rep.WriteGatewayConfig(out)
	case *format == "json":
		err = rep.WriteJSON(out)
	case *format == "sarif":
		err = rep.WriteSARIF(out)
	default:
		rep.WriteText(out, scan.TextOptions{
			Color:       !*noColor && scan.ColorEnabled(stdout),
			MinSeverity: minSeverity,
		})
	}
	if err == nil {
		err = out.err
	}
	if err != nil {
		fmt.Fprintf(stderr, "mcpx scan: writing output: %v\n", err)
		return scanExitError
	}

	if !failNever && rep.Worst() >= failThreshold { // Worst is -1 with no findings
		return scanExitFindings
	}
	if len(rep.Configs) == 0 {
		fmt.Fprintln(stderr, "mcpx scan: no MCP client configs found")
		return scanExitError
	}
	if failed := unscanned(rep); failed > 0 {
		fmt.Fprintf(stderr, "mcpx scan: %d server(s) could not be scanned; their tools were not checked\n", failed)
		return scanExitError
	}
	return scanExitOK
}

// unscanned counts servers that failed to connect or list tools. Servers
// the scanner deliberately skipped (see scan.Server.Skip) do not count.
func unscanned(rep *scan.Report) int {
	n := 0
	for _, r := range rep.Servers {
		if r.Error != "" && r.Skip == "" {
			n++
		}
	}
	return n
}

// errWriter remembers the first write error and drops later writes.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// isTerminal reports whether w is a character device (an interactive
// terminal), independent of color preferences like NO_COLOR.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// parseInterspersed parses flags that may appear before, between, or after
// positional arguments ("mcpx scan .mcp.json --format json"), which the
// standard flag package alone stops at. A "--" ends flag parsing.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if endedOnTerminator(fs, args[:len(args)-len(rest)]) {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// endedOnTerminator reports whether fs.Parse stopped because it consumed a
// "--" terminator as the last of the consumed args, as opposed to "--"
// being the value of a preceding flag ("--baseline --").
func endedOnTerminator(fs *flag.FlagSet, consumed []string) bool {
	n := len(consumed)
	if n == 0 || consumed[n-1] != "--" {
		return false
	}
	if n == 1 {
		return true
	}
	prev := consumed[n-2]
	if !strings.HasPrefix(prev, "-") || prev == "--" || strings.Contains(prev, "=") {
		return true
	}
	f := fs.Lookup(strings.TrimLeft(prev, "-"))
	if f == nil {
		return true
	}
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return true
	}
	return false // "--" was this flag's value
}
