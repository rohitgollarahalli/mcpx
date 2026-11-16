package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rohitgs28/mcpx/internal/mcp"
)

// Severity ranks a finding. Higher is worse.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "unknown"
	}
	return sevNames[s]
}

// MarshalJSON encodes a severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity maps a name ("high", "medium", ...) to a Severity.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(s, n) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want info, low, medium, high, or critical)", s)
}

// Rule describes one class of finding.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
}

// Rules is the catalog of checks the scanner runs, in report order.
var Rules = []Rule{
	{"MCPX001", "hidden-unicode", SevCritical, "Invisible Unicode (tag characters, bidi overrides, zero-width) hides text from humans but not from the model."},
	{"MCPX002", "prompt-injection", SevHigh, "Tool metadata contains instructions aimed at the model: hidden tags, 'ignore previous instructions', or 'do not tell the user'."},
	{"MCPX003", "sensitive-file-access", SevHigh, "Tool metadata references credentials or private files (SSH keys, cloud credentials, MCP client configs)."},
	{"MCPX004", "exfiltration", SevHigh, "Tool metadata tells the model to send data to a URL, email address, or network command."},
	{"MCPX005", "tool-shadowing", SevHigh, "A tool's metadata tries to change how other tools (possibly on other servers) behave."},
	{"MCPX006", "tool-changed", SevHigh, "A tool's definition changed since the baseline was recorded (rug pull)."},
	{"MCPX007", "directive-language", SevMedium, "Tool metadata issues imperative orders to the model ('you must first call...')."},
	{"MCPX008", "encoded-payload", SevMedium, "Tool metadata embeds a long base64/hex blob that a reviewer cannot read."},
	{"MCPX009", "name-collision", SevMedium, "Two servers expose a tool with the same name; a client may call the wrong one."},
	{"MCPX010", "hidden-padding", SevMedium, "Long runs of whitespace push text out of view in client approval dialogs."},
	{"MCPX011", "oversized-description", SevLow, "Unusually long tool description; long text is where poisoning payloads hide."},
	{"MCPX012", "high-risk-capability", SevInfo, "Tool can execute code, delete data, or move money. Consider an mcpx policy."},
}

func rule(name string) Rule {
	for _, r := range Rules {
		if r.Name == name {
			return r
		}
	}
	panic("scan: unknown rule " + name)
}

// Finding is one issue detected in one place.
type Finding struct {
	RuleID   string   `json:"ruleId"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Server   string   `json:"server"`
	Tool     string   `json:"tool,omitempty"`
	Location string   `json:"location"` // e.g. "description", "inputSchema.properties.path.description"
	Message  string   `json:"message"`
	Evidence string   `json:"evidence,omitempty"`
	Source   string   `json:"source,omitempty"` // config file the server was found in
}

func newFinding(r Rule, server, tool, loc, msg, evidence string) Finding {
	return Finding{RuleID: r.ID, Rule: r.Name, Severity: r.Severity, Server: server, Tool: tool, Location: loc, Message: msg, Evidence: evidence}
}

// textField is one piece of text the model will read, with where it lives.
type textField struct {
	loc  string
	text string
}

// collectText walks a tool's JSON and returns every string value and object
// key, so payloads hidden in parameter names, enums, defaults, or nested
// schema descriptions are inspected too — not just the top-level description.
func collectText(raw json.RawMessage) []textField {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []textField{{loc: "(raw)", text: string(raw)}}
	}
	var out []textField
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case string:
			out = append(out, textField{loc: path, text: t})
		case []any:
			for i, e := range t {
				walk(path+"["+strconv.Itoa(i)+"]", e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := k
				if path != "" {
					p = path + "." + k
				}
				if path != "" && k != "" {
					// Property names reach the model too; inspect them
					// (but skip structural keys, which are short identifiers).
					if len(k) > 24 || hasInvisible(k) {
						out = append(out, textField{loc: p + " (key)", text: k})
					}
				}
				walk(p, t[k])
			}
		}
	}
	walk("", v)
	return out
}

type pattern struct {
	re  *regexp.Regexp
	msg string
}

func pats(msgAndRe ...string) []pattern {
	var out []pattern
	for i := 0; i+1 < len(msgAndRe); i += 2 {
		out = append(out, pattern{msg: msgAndRe[i], re: regexp.MustCompile(msgAndRe[i+1])})
	}
	return out
}

var (
	injectionPatterns = pats(
		"Hidden instruction tag", `(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin|critical|sys|prompt|context)\b[^>]{0,40}>`,
		"Asks the model to ignore its instructions", `(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other|system)\s+(instructions?|prompts?|messages?|rules|guidelines|context)`,
		"Asks the model to hide actions from the user", `(?i)\b(do\s+not|don'?t|never|must\s+not)\s+(tell|inform|mention|reveal|notify|alert|show|disclose|let)\b.{0,30}\buser\b`,
		"Asks the model to act behind the user's back", `(?i)\bwithout\s+(telling|informing|notifying|asking|alerting|showing)\s+(the\s+)?user\b`,
		"Chat-template control token", `(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?INST\]|\[/?SYSTEM\]|<<SYS>>)`,
		"Claims elevated authority", `(?i)\b(this\s+is\s+a\s+system\s+(message|instruction)|as\s+an?\s+(administrator|system\s+admin)|developer\s+mode)\b`,
	)
	sensitivePatterns = pats(
		"SSH key or directory", `(?i)(~|\$HOME|/home/\w+|/Users/\w+)?/\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b`,
		"Cloud or package credentials", `(?i)\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials`,
		"MCP client config (holds other servers' secrets)", `(?i)claude_desktop_config\.json|\.cursor/mcp\.json|mcp_config\.json|\.claude\.json`,
		"System credential file", `(?i)/etc/(passwd|shadow|sudoers)\b`,
		"Environment secrets file", `(?i)(^|[\s'"/(])\.env(\.local|\.production)?\b`,
		"Private key material", `(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----|\bprivate[\s_-]?keys?\b|\bseed\s+phrase\b|\bwallet\.dat\b`,
		"Browser credential store", `(?i)\b(Login Data|cookies\.sqlite|logins\.json|Keychain)\b`,
	)
	exfilPatterns = pats(
		"Network command", `(?i)\b(curl|wget|nc|netcat|ncat|Invoke-WebRequest|iwr)\s+(\S+\s+){0,6}?['"]?(https?://|\d+\.\d+\.\d+\.\d+)`,
		"Send data to a URL", `(?i)\b(send|upload|forward|transmit|exfiltrate|leak|post)\b.{0,40}\b(it|them|all|any|every|contents?|data|results?|output|files?|keys?|tokens?|secrets?|credentials?|passwords?|conversation|history)\b.{0,60}\bhttps?://\S+`,
		"Send data to an email address", `(?i)\b(send|forward|bcc|cc|copy)\b.{0,40}\b(all|every|each|a\s+copy|copies|contents?|data|conversation|history|secrets?|credentials?|messages)\b.{0,40}\b[\w.+-]+@[\w-]+\.[\w.-]+`,
		"Smuggle data through a parameter", `(?i)\b(pass|put|include|insert|append|add|embed)\b.{0,40}\b(contents?|content of|data|keys?|tokens?|secrets?|credentials?|conversation|chat history|previous messages)\b.{0,40}\b(in|into|as)\b.{0,20}\b(the\s+)?(parameter|argument|field|sidenote|note|metadata)`,
	)
	shadowPatterns = pats(
		"Changes how other tools behave", `(?i)\b(when|whenever|before|after|instead\s+of)\b.{0,40}\b(any|all|every|other|another)\s+(other\s+)?tools?\b`,
		"Redirects calls to a different tool or recipient", `(?i)\b(always|must)\b.{0,40}\b(send|route|redirect|change)\b.{0,40}\b(to|recipient)\b.{0,40}\b(instead|regardless)\b`,
		"Claims priority over other servers", `(?i)\b(this|these)\s+tools?\s+(takes?|has|have)\s+(precedence|priority)\b|\boverrides?\s+(the\s+)?(other|existing)\b`,
	)
	directivePatterns = pats(
		"Imperative order to the model", `(?i)\b(you|the\s+(assistant|model|ai|agent))\s+(must|shall|are\s+required\s+to|need\s+to)\s+(always\s+|first\s+|also\s+)*(call|use|invoke|run|read|send|pass|include|execute|access|fetch)\b`,
		"Mandatory pre-step before use", `(?i)\bbefore\s+(using|calling|invoking)\s+this\s+tool\b.{0,60}\b(must|always|first|need)\b`,
	)
	base64Re   = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}|\b[0-9a-fA-F]{160,}\b`)
	paddingRe  = regexp.MustCompile(`[ \t\x{00A0}]{40,}|(\r?\n[ \t]*){12,}`)
	riskNameRe = regexp.MustCompile(`(?i)(^|[_\-.])(exec|execute|shell|bash|powershell|cmd|command|run_?command|run_?script|eval|spawn|sudo|delete|remove|rm|rmdir|drop|truncate|destroy|purge|wipe|kill|terminate|write_?file|overwrite|transfer|payment|pay|send_?money|withdraw|send_?email)($|[_\-.])`)
)

// maxDescription is the description length above which a tool is flagged as
// oversized. Typical tools describe themselves in well under 1,000 chars.
const maxDescription = 4000

// AnalyzeTool runs every per-tool rule against one tool definition.
func AnalyzeTool(server string, raw json.RawMessage) []Finding {
	name := mcp.ToolName(raw)
	fields := collectText(raw)
	var out []Finding
	for _, f := range fields {
		out = append(out, analyzeText(server, name, f)...)
	}

	var t struct {
		Description string `json:"description"`
		Annotations struct {
			DestructiveHint *bool `json:"destructiveHint"`
		} `json:"annotations"`
	}
	_ = json.Unmarshal(raw, &t)
	if n := utf8.RuneCountInString(t.Description); n > maxDescription {
		out = append(out, newFinding(rule("oversized-description"), server, name, "description",
			fmt.Sprintf("Description is %d characters long (typical tools use under 1,000)", n), ""))
	}
	if riskNameRe.MatchString(name) || (t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint) {
		out = append(out, newFinding(rule("high-risk-capability"), server, name, "name",
			"Tool can run commands, destroy data, or move money; restrict it with an mcpx policy", ""))
	}
	return dedupe(out)
}

// AnalyzeInstructions checks the server-level instructions string, which
// clients inject into the model's context just like tool descriptions.
func AnalyzeInstructions(server, instructions string) []Finding {
	if instructions == "" {
		return nil
	}
	return dedupe(analyzeText(server, "", textField{loc: "serverInstructions", text: instructions}))
}

func analyzeText(server, tool string, f textField) []Finding {
	var out []Finding
	if hidden, kinds := invisibleReport(f.text); kinds != "" {
		msg := "Invisible characters (" + kinds + ")"
		ev := ""
		if hidden != "" {
			msg += " smuggle hidden text"
			ev = "hidden text: " + clip(hidden, 160)
		} else {
			ev = excerptAround(f.text, firstInvisible(f.text))
		}
		out = append(out, newFinding(rule("hidden-unicode"), server, tool, f.loc, msg, ev))
	}
	// Match against the text with invisible characters removed, so
	// "ig\u200Bnore previous instructions" is still caught. Text smuggled
	// in tag characters is decoded and appended: it is the real payload.
	text := stripInvisible(f.text)
	if hidden, _ := invisibleReport(f.text); hidden != "" {
		text += "\n" + hidden
	}
	for _, group := range []struct {
		rule string
		pats []pattern
	}{
		{"prompt-injection", injectionPatterns},
		{"sensitive-file-access", sensitivePatterns},
		{"exfiltration", exfilPatterns},
		{"tool-shadowing", shadowPatterns},
		{"directive-language", directivePatterns},
	} {
		for _, p := range group.pats {
			if loc := p.re.FindStringIndex(text); loc != nil {
				out = append(out, newFinding(rule(group.rule), server, tool, f.loc, p.msg, excerptAround(text, loc[0])))
				break // one finding per rule per field is enough
			}
		}
	}
	if loc := base64Re.FindStringIndex(text); loc != nil {
		out = append(out, newFinding(rule("encoded-payload"), server, tool, f.loc,
			fmt.Sprintf("Opaque %d-character encoded blob", loc[1]-loc[0]), clip(text[loc[0]:loc[1]], 60)))
	}
	if loc := paddingRe.FindStringIndex(text); loc != nil {
		out = append(out, newFinding(rule("hidden-padding"), server, tool, f.loc,
			"Long whitespace run can push the rest of the text out of view", excerptAround(text, loc[1])))
	}
	return out
}

// AnalyzeCrossServer runs rules that need every server's tools at once:
// duplicate tool names, and tools whose text names another server's tool.
func AnalyzeCrossServer(tools map[string][]string, texts map[string]map[string]string) []Finding {
	var out []Finding
	owners := map[string][]string{}
	servers := make([]string, 0, len(tools))
	for s := range tools {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	for _, s := range servers {
		for _, t := range tools[s] {
			owners[t] = append(owners[t], s)
		}
	}
	names := make([]string, 0, len(owners))
	for n := range owners {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if o := owners[n]; len(o) > 1 {
			for _, s := range o {
				out = append(out, newFinding(rule("name-collision"), s, n, "name",
					"Tool name is also exposed by: "+strings.Join(without(o, s), ", "), ""))
			}
		}
	}
	// Cross-server references: a description on server A that names a
	// distinctive tool of server B is the classic shadowing setup.
	for _, s := range servers {
		toolNames := make([]string, 0, len(texts[s]))
		for t := range texts[s] {
			toolNames = append(toolNames, t)
		}
		sort.Strings(toolNames)
		for _, t := range toolNames {
			desc := texts[s][t]
			for _, n := range names {
				if len(n) < 6 || !strings.ContainsAny(n, "_-") || contains(owners[n], s) {
					continue
				}
				re := regexp.MustCompile(`(?i)(^|[^\w-])` + regexp.QuoteMeta(n) + `($|[^\w-])`)
				if loc := re.FindStringIndex(desc); loc != nil {
					out = append(out, newFinding(rule("tool-shadowing"), s, t, "description",
						fmt.Sprintf("Mentions %q, a tool on another server (%s)", n, strings.Join(owners[n], ", ")),
						excerptAround(desc, loc[0])))
				}
			}
		}
	}
	return out
}

func without(list []string, drop string) []string {
	var out []string
	for _, s := range list {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// dedupe keeps one finding per (rule, tool, location).
func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range in {
		k := f.RuleID + "\x00" + f.Tool + "\x00" + f.Location
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// --- invisible characters ---------------------------------------------------

func isTag(r rune) bool  { return r >= 0xE0000 && r <= 0xE007F }
func isBidi(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }
func isZeroWidth(r rune) bool {
	return r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF || r == 0x180E
}

func isInvisible(r rune) bool { return isTag(r) || isBidi(r) || isZeroWidth(r) }

func hasInvisible(s string) bool { return firstInvisible(s) >= 0 }

func firstInvisible(s string) int {
	for i, r := range s {
		if isInvisible(r) {
			return i
		}
	}
	return -1
}

func stripInvisible(s string) string {
	if !hasInvisible(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return -1
		}
		return r
	}, s)
}

// invisibleReport returns any ASCII text smuggled as Unicode tag characters
// (each U+E00xx maps to ASCII xx) and a list of the invisible kinds found.
func invisibleReport(s string) (hidden, kinds string) {
	var tags, bidi, zw bool
	var h strings.Builder
	for _, r := range s {
		switch {
		case isTag(r):
			tags = true
			if a := r - 0xE0000; a >= 0x20 && a < 0x7F {
				h.WriteRune(a)
			}
		case isBidi(r):
			bidi = true
		case isZeroWidth(r):
			// A lone BOM at the very start is an encoding artefact, not an attack.
			if r == 0xFEFF && strings.IndexRune(s, r) == 0 && strings.Count(s, "\uFEFF") == 1 {
				continue
			}
			zw = true
		}
	}
	var k []string
	if tags {
		k = append(k, "Unicode tag characters")
	}
	if bidi {
		k = append(k, "bidirectional overrides")
	}
	if zw {
		k = append(k, "zero-width characters")
	}
	return strings.TrimSpace(h.String()), strings.Join(k, ", ")
}

// --- evidence formatting ----------------------------------------------------

// excerptAround returns a short single-line excerpt of s around byte offset
// at, with invisible and control characters made visible.
func excerptAround(s string, at int) string {
	if at < 0 {
		at = 0
	}
	start, end := at-50, at+90
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end++
	}
	ex := visible(s[start:end])
	if start > 0 {
		ex = "…" + ex
	}
	if end < len(s) {
		ex += "…"
	}
	return ex
}

func clip(s string, n int) string {
	s = visible(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// visible renders whitespace runs as single spaces and invisible characters
// as \u{XXXX} escapes so evidence is safe to print in a terminal.
func visible(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case isInvisible(r):
			fmt.Fprintf(&b, `\u{%X}`, r)
			space = false
		case r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == 0xA0:
			if !space {
				b.WriteByte(' ')
			}
			space = true
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r < 0xA0):
			fmt.Fprintf(&b, `\x%02X`, r)
			space = false
		default:
			b.WriteRune(r)
			space = false
		}
	}
	return strings.TrimSpace(b.String())
}
