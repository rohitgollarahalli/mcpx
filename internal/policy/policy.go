// Package policy enforces tool-level access control on MCP requests.
// It evaluates allow/deny lists, read-only modes, and per-tool argument
// rules per backend server.
package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

type Engine struct {
	policies map[string]*compiledPolicy
	// clients maps client name -> server name -> override policy. The
	// effective decision intersects server policy and override: both must
	// allow. A client without an entry gets the server baseline.
	clients map[string]map[string]*compiledPolicy
}

// compiledPolicy pairs a config policy with its pre-compiled argument rules
// (tool -> arg -> rule) so regexes compile once at load, not per request.
type compiledPolicy struct {
	cfg   *config.Policy
	rules map[string]map[string]compiledArgRule
}

type compiledArgRule struct {
	config.ArgRule
	re *regexp.Regexp
}

func New(servers []config.ServerConfig, clients map[string]config.ClientConfig) *Engine {
	policies := make(map[string]*compiledPolicy)
	for _, s := range servers {
		policies[s.Name] = compile(s.Policy)
	}
	var cc map[string]map[string]*compiledPolicy
	if len(clients) > 0 {
		cc = make(map[string]map[string]*compiledPolicy, len(clients))
		for name, c := range clients {
			m := make(map[string]*compiledPolicy, len(c.Servers))
			for srv, p := range c.Servers {
				m[srv] = compile(p)
			}
			cc[name] = m
		}
	}
	return &Engine{policies: policies, clients: cc}
}

// compile pre-compiles a policy's argument rules. Invalid regexes cannot
// occur post config.Validate; defensively, a rule whose regex fails to
// compile keeps re == nil and the regex constraint then fails closed.
func compile(p *config.Policy) *compiledPolicy {
	if p == nil {
		return nil
	}
	cp := &compiledPolicy{cfg: p}
	if len(p.ToolRules) > 0 {
		cp.rules = make(map[string]map[string]compiledArgRule, len(p.ToolRules))
		for tool, tr := range p.ToolRules {
			args := make(map[string]compiledArgRule, len(tr.Args))
			for arg, ar := range tr.Args {
				car := compiledArgRule{ArgRule: ar}
				if ar.Regex != "" {
					car.re, _ = regexp.Compile(ar.Regex)
				}
				args[arg] = car
			}
			cp.rules[tool] = args
		}
	}
	return cp
}

type Result struct {
	Allowed bool
	Reason  string
}

// Evaluate decides whether a request from the named client (may be "" when
// auth provides no identity) is allowed on a server. The server policy and
// the client's override must BOTH allow it.
func (e *Engine) Evaluate(serverName, client string, req *mcp.Request) Result {
	if cp := e.policies[serverName]; cp != nil {
		if res := evalPolicy(cp, serverName, req); !res.Allowed {
			return res
		}
	}
	if cp := e.clientPolicy(client, serverName); cp != nil {
		if res := evalPolicy(cp, serverName, req); !res.Allowed {
			res.Reason = fmt.Sprintf("client %q: %s", client, res.Reason)
			return res
		}
	}
	return Result{Allowed: true}
}

// clientPolicy returns the client's override for a server, or nil.
func (e *Engine) clientPolicy(client, serverName string) *compiledPolicy {
	if client == "" {
		return nil
	}
	return e.clients[client][serverName]
}

// evalPolicy applies one policy to a request: read-only mode, deny list,
// allow list, then per-tool argument rules.
func evalPolicy(cp *compiledPolicy, serverName string, req *mcp.Request) Result {
	policy := cp.cfg
	if policy.ReadOnly && req.Method == mcp.MethodToolsCall {
		return Result{Allowed: false, Reason: fmt.Sprintf("server %q is in read-only mode: tools/call is blocked", serverName)}
	}
	if req.Method != mcp.MethodToolsCall {
		return Result{Allowed: true}
	}
	tc, err := mcp.ParseToolCall(req)
	if err != nil || tc == nil {
		return Result{Allowed: true}
	}
	for _, d := range policy.DenyTools {
		if d == tc.Name {
			return Result{Allowed: false, Reason: fmt.Sprintf("tool %q is denied on server %q", tc.Name, serverName)}
		}
	}
	if len(policy.AllowTools) > 0 {
		allowed := false
		for _, a := range policy.AllowTools {
			if a == tc.Name {
				allowed = true
				break
			}
		}
		if !allowed {
			return Result{Allowed: false, Reason: fmt.Sprintf("tool %q not in allow list for %q", tc.Name, serverName)}
		}
	}
	return evalArgRules(cp.rules[tc.Name], serverName, tc)
}

// evalArgRules checks a tool call's arguments against the tool's compiled
// rules. Values are normalized to strings deterministically; a rule that
// targets a non-scalar value fails closed.
func evalArgRules(rules map[string]compiledArgRule, serverName string, tc *mcp.ToolCallParams) Result {
	for arg, rule := range rules {
		val, present := tc.Arguments[arg]
		if !present {
			if rule.Required {
				return Result{Allowed: false, Reason: fmt.Sprintf("tool %q on server %q: required argument %q is missing", tc.Name, serverName, arg)}
			}
			continue
		}
		s, scalar := normalize(val)
		if !scalar {
			return Result{Allowed: false, Reason: fmt.Sprintf("tool %q argument %q has a non-scalar value, which rules cannot evaluate", tc.Name, arg)}
		}
		if violated := checkArg(rule, s); violated != "" {
			return Result{Allowed: false, Reason: fmt.Sprintf("tool %q argument %q violates %s rule", tc.Name, arg, violated)}
		}
	}
	return Result{Allowed: true}
}

// checkArg returns the name of the first violated constraint, or "".
func checkArg(rule compiledArgRule, s string) string {
	if rule.Equals != nil && s != *rule.Equals {
		return "equals"
	}
	if len(rule.OneOf) > 0 {
		found := false
		for _, v := range rule.OneOf {
			if v == s {
				found = true
				break
			}
		}
		if !found {
			return "one_of"
		}
	}
	if rule.Prefix != "" && !strings.HasPrefix(s, rule.Prefix) {
		return "prefix"
	}
	if rule.Suffix != "" && !strings.HasSuffix(s, rule.Suffix) {
		return "suffix"
	}
	if rule.Regex != "" && (rule.re == nil || !rule.re.MatchString(s)) {
		return "regex"
	}
	return ""
}

// normalize converts a decoded JSON argument value to its string form for
// comparison. Returns ok=false for non-scalar values (objects, arrays, null).
func normalize(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	default:
		return "", false
	}
}

// ToolAllowed reports whether a named tool may be called on a server by the
// named client. It mirrors the tool-level decision in Evaluate and is used
// to filter tools/list responses so clients never see tools they cannot call.
// A read-only server hides all tools, since every tools/call on it is blocked.
// Argument rules do not affect visibility: a tool that is callable with the
// right arguments stays listed.
func (e *Engine) ToolAllowed(serverName, client, tool string) bool {
	if !toolAllowedBy(e.policies[serverName], tool) {
		return false
	}
	return toolAllowedBy(e.clientPolicy(client, serverName), tool)
}

func toolAllowedBy(cp *compiledPolicy, tool string) bool {
	if cp == nil {
		return true
	}
	policy := cp.cfg
	if policy.ReadOnly {
		return false
	}
	for _, d := range policy.DenyTools {
		if d == tool {
			return false
		}
	}
	if len(policy.AllowTools) > 0 {
		for _, a := range policy.AllowTools {
			if a == tool {
				return true
			}
		}
		return false
	}
	return true
}
