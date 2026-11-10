// Package openapi turns an OpenAPI 3.x description of a REST API into an MCP
// server: every operation becomes an MCP tool whose input schema is derived
// from the operation's parameters and JSON request body, and a tools/call is
// executed as the corresponding HTTP request against the API.
//
// The gateway mounts the resulting Server as an in-process backend, so the
// generated tools get the same auth, policy, argument rules, rate limiting,
// caching, circuit breaking, audit logging, and metrics as any other MCP
// server behind mcpx. The package depends on the standard library only.
package openapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Spec is a parsed OpenAPI document reduced to what tool generation needs.
type Spec struct {
	Title   string
	Version string
	// ServerURL is the first entry of the document's servers list, or "" when
	// the document has none. Relative entries are returned unresolved.
	ServerURL  string
	operations []*operation
	root       map[string]any // full document, for $ref resolution
}

// operation is one HTTP method on one path.
type operation struct {
	method      string // upper-case HTTP method
	path        string // templated path, e.g. /pets/{petId}
	operationID string
	summary     string
	description string
	tags        []string
	params      []param
	body        *requestBody
	deprecated  bool
}

type param struct {
	name        string
	in          string // path, query, header
	required    bool
	description string
	schema      map[string]any // resolved JSON Schema (never nil)
	explode     bool           // query arrays: repeat the key (true) or comma-join (false)
}

type requestBody struct {
	required    bool
	description string
	contentType string         // the JSON media type the body is sent as
	schema      map[string]any // resolved JSON Schema (never nil)
}

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Parse parses an OpenAPI 3.0 or 3.1 document in JSON form. YAML documents
// must be converted to JSON first (the gateway's config loader does this).
func Parse(data []byte) (*Spec, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("openapi: invalid JSON: %w", err)
	}
	ver, _ := root["openapi"].(string)
	if ver == "" {
		if _, ok := root["swagger"]; ok {
			return nil, fmt.Errorf("openapi: Swagger 2.0 documents are not supported; convert to OpenAPI 3 first")
		}
		return nil, fmt.Errorf("openapi: missing \"openapi\" version field")
	}
	if !strings.HasPrefix(ver, "3.") {
		return nil, fmt.Errorf("openapi: unsupported version %q (want 3.x)", ver)
	}

	s := &Spec{root: root}
	if info, ok := root["info"].(map[string]any); ok {
		s.Title, _ = info["title"].(string)
		s.Version, _ = info["version"].(string)
	}
	if servers, ok := root["servers"].([]any); ok && len(servers) > 0 {
		if srv, ok := servers[0].(map[string]any); ok {
			s.ServerURL = expandServerVars(srv)
		}
	}

	paths, _ := root["paths"].(map[string]any)
	pathKeys := make([]string, 0, len(paths))
	for p := range paths {
		pathKeys = append(pathKeys, p)
	}
	sort.Strings(pathKeys)

	for _, p := range pathKeys {
		item, ok := s.deref(paths[p]).(map[string]any)
		if !ok {
			continue
		}
		shared, err := s.parseParams(item["parameters"])
		if err != nil {
			return nil, fmt.Errorf("openapi: %s: %w", p, err)
		}
		for _, m := range httpMethods {
			raw, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			op, err := s.parseOperation(strings.ToUpper(m), p, raw, shared)
			if err != nil {
				return nil, fmt.Errorf("openapi: %s %s: %w", strings.ToUpper(m), p, err)
			}
			s.operations = append(s.operations, op)
		}
	}
	if len(s.operations) == 0 {
		return nil, fmt.Errorf("openapi: document defines no operations")
	}
	return s, nil
}

// expandServerVars substitutes a server object's variables with their
// defaults, e.g. https://{region}.api.example.com with region default "eu".
func expandServerVars(srv map[string]any) string {
	u, _ := srv["url"].(string)
	vars, _ := srv["variables"].(map[string]any)
	for name, v := range vars {
		if vm, ok := v.(map[string]any); ok {
			if def, ok := vm["default"].(string); ok {
				u = strings.ReplaceAll(u, "{"+name+"}", def)
			}
		}
	}
	return u
}

func (s *Spec) parseOperation(method, p string, raw map[string]any, shared []param) (*operation, error) {
	op := &operation{method: method, path: p}
	op.operationID, _ = raw["operationId"].(string)
	op.summary, _ = raw["summary"].(string)
	op.description, _ = raw["description"].(string)
	op.deprecated, _ = raw["deprecated"].(bool)
	if tags, ok := raw["tags"].([]any); ok {
		for _, t := range tags {
			if ts, ok := t.(string); ok {
				op.tags = append(op.tags, ts)
			}
		}
	}

	own, err := s.parseParams(raw["parameters"])
	if err != nil {
		return nil, err
	}
	// Operation-level parameters override path-level ones with the same
	// name and location.
	merged := make([]param, 0, len(shared)+len(own))
	for _, sp := range shared {
		overridden := false
		for _, o := range own {
			if o.name == sp.name && o.in == sp.in {
				overridden = true
				break
			}
		}
		if !overridden {
			merged = append(merged, sp)
		}
	}
	op.params = append(merged, own...)

	if rb, ok := s.deref(raw["requestBody"]).(map[string]any); ok {
		op.body = s.parseBody(rb)
	}
	return op, nil
}

func (s *Spec) parseParams(v any) ([]param, error) {
	list, _ := v.([]any)
	var out []param
	for _, item := range list {
		pm, ok := s.deref(item).(map[string]any)
		if !ok {
			continue
		}
		name, _ := pm["name"].(string)
		in, _ := pm["in"].(string)
		if name == "" {
			return nil, fmt.Errorf("parameter without a name")
		}
		switch in {
		case "path", "query", "header":
		case "cookie":
			continue // not supported; cookies are left to injected headers
		default:
			return nil, fmt.Errorf("parameter %q: unknown location %q", name, in)
		}
		// Per the OpenAPI spec these header parameters are ignored: the
		// HTTP layer owns them.
		if in == "header" {
			switch strings.ToLower(name) {
			case "accept", "content-type", "authorization":
				continue
			}
		}
		p := param{name: name, in: in, explode: true}
		p.required, _ = pm["required"].(bool)
		if in == "path" {
			p.required = true
		}
		p.description, _ = pm["description"].(string)
		if ex, ok := pm["explode"].(bool); ok {
			p.explode = ex
		}
		if style, ok := pm["style"].(string); ok && style != "form" && in == "query" {
			p.explode = false
		}
		p.schema = s.schemaOf(pm["schema"])
		if p.schema == nil {
			// OpenAPI also allows a "content" map instead of "schema".
			if content, ok := pm["content"].(map[string]any); ok {
				for _, mt := range content {
					if m, ok := mt.(map[string]any); ok {
						p.schema = s.schemaOf(m["schema"])
						break
					}
				}
			}
		}
		if p.schema == nil {
			p.schema = map[string]any{"type": "string"}
		}
		out = append(out, p)
	}
	return out, nil
}

// parseBody picks the JSON media type of a request body. Bodies with no JSON
// representation (multipart, octet-stream, form) are not exposed: the
// operation is still a tool, but without a body argument.
func (s *Spec) parseBody(rb map[string]any) *requestBody {
	content, _ := rb["content"].(map[string]any)
	ct := ""
	for mt := range content {
		base := strings.ToLower(strings.TrimSpace(strings.SplitN(mt, ";", 2)[0]))
		if base == "application/json" {
			ct = mt
			break
		}
		if strings.HasSuffix(base, "+json") && ct == "" {
			ct = mt
		}
	}
	if ct == "" {
		return nil
	}
	b := &requestBody{contentType: ct}
	b.required, _ = rb["required"].(bool)
	b.description, _ = rb["description"].(string)
	if m, ok := content[ct].(map[string]any); ok {
		b.schema = s.schemaOf(m["schema"])
	}
	if b.schema == nil {
		b.schema = map[string]any{}
	}
	return b
}

// deref follows a single local $ref ("#/components/...") if v is a reference
// object. Non-local references resolve to nil.
func (s *Spec) deref(v any) any {
	for i := 0; i < 32; i++ {
		m, ok := v.(map[string]any)
		if !ok {
			return v
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return v
		}
		v = s.lookup(ref)
	}
	return nil
}

// lookup resolves a JSON pointer of the form #/a/b/c within the document.
func (s *Spec) lookup(ref string) any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = s.root
	for _, tok := range strings.Split(ref[2:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		if t, err := url.PathUnescape(tok); err == nil {
			tok = t
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[tok]
	}
	return cur
}

// maxSchemaDepth bounds $ref inlining. Recursive schemas (a tree node that
// contains nodes) are cut off below this depth and replaced with an
// unconstrained schema, which clients accept and the API still validates.
const maxSchemaDepth = 12

// schemaOf returns a self-contained JSON Schema for an OpenAPI schema
// object: local $refs are inlined, OpenAPI-only keywords are dropped, and
// 3.0's "nullable" is rewritten to the JSON Schema equivalent.
func (s *Spec) schemaOf(v any) map[string]any {
	if v == nil {
		return nil
	}
	out, _ := s.convert(v, 0, map[string]bool{}).(map[string]any)
	return out
}

// droppedKeywords are OpenAPI schema extensions that are not JSON Schema.
var droppedKeywords = map[string]bool{
	"nullable": true, "discriminator": true, "xml": true, "externalDocs": true,
	"example": true, // rewritten to JSON Schema "examples" below
}

func (s *Spec) convert(v any, depth int, seen map[string]bool) any {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			if seen[ref] || depth >= maxSchemaDepth {
				return map[string]any{}
			}
			target := s.lookup(ref)
			if target == nil {
				return map[string]any{}
			}
			seen[ref] = true
			out := s.convert(target, depth+1, seen)
			delete(seen, ref)
			return out
		}
		out := make(map[string]any, len(x))
		for k, val := range x {
			if droppedKeywords[k] || strings.HasPrefix(k, "x-") {
				continue
			}
			// Under "properties" the keys are property names, not keywords.
			if k == "properties" {
				if props, ok := val.(map[string]any); ok {
					cp := make(map[string]any, len(props))
					for pn, ps := range props {
						cp[pn] = s.convert(ps, depth+1, seen)
					}
					out[k] = cp
					continue
				}
			}
			out[k] = s.convert(val, depth+1, seen)
		}
		if n, _ := x["nullable"].(bool); n {
			if t, ok := out["type"].(string); ok {
				out["type"] = []any{t, "null"}
			}
		}
		if ex, ok := x["example"]; ok {
			if _, has := out["examples"]; !has {
				out["examples"] = []any{ex}
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = s.convert(val, depth+1, seen)
		}
		return out
	default:
		return v
	}
}

// --- tool generation ---------------------------------------------------------

// Filter selects which operations become tools. Patterns use path.Match glob
// syntax ("list*", "admin_*") and match the generated tool name or the
// operationId. Empty lists select everything.
type Filter struct {
	IncludeOperations []string
	ExcludeOperations []string
	IncludeTags       []string
	ExcludeTags       []string
	// Methods limits tools to these HTTP methods (e.g. ["GET"] exposes a
	// read-only view of the API). Case-insensitive.
	Methods []string
}

// Tool is a generated MCP tool and the operation it calls.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Annotations map[string]any
	op          *operation
	// bodyMode says how the request body is built from the arguments:
	// "" (no body), "arg" (the "body" argument), or "flat" (the body
	// object's properties are top-level arguments).
	bodyMode  string
	bodyProps map[string]bool // flat mode: which arguments belong to the body
}

// Method and Path report the HTTP operation a tool invokes.
func (t *Tool) Method() string { return t.op.method }
func (t *Tool) Path() string   { return t.op.path }

var invalidNameChars = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// maxToolName keeps names within the limit common MCP clients enforce.
const maxToolName = 64

// toolName derives a stable, client-safe tool name: the operationId when
// present, otherwise method_path ("get_pets_petId").
func toolName(op *operation) string {
	base := op.operationID
	if base == "" {
		trimmed := strings.Trim(op.path, "/")
		base = strings.ToLower(op.method) + "_" + strings.NewReplacer("{", "", "}", "").Replace(trimmed)
	}
	name := strings.Trim(invalidNameChars.ReplaceAllString(base, "_"), "_")
	if name == "" {
		name = strings.ToLower(op.method)
	}
	if len(name) > maxToolName {
		name = name[:maxToolName]
	}
	return name
}

// maxDescription keeps tool descriptions compact; long API prose costs
// context window on every tools/list.
const maxDescription = 1024

// BuildTools generates the tool set for the operations the filter selects.
func (s *Spec) BuildTools(f Filter) ([]*Tool, error) {
	var tools []*Tool
	used := map[string]bool{}
	for _, op := range s.operations {
		name := toolName(op)
		if !f.selects(op, name) {
			continue
		}
		// Disambiguate collisions deterministically (operations are sorted).
		if used[name] {
			for i := 2; ; i++ {
				suffix := fmt.Sprintf("_%d", i)
				cand := name
				if len(cand)+len(suffix) > maxToolName {
					cand = cand[:maxToolName-len(suffix)]
				}
				cand += suffix
				if !used[cand] {
					name = cand
					break
				}
			}
		}
		used[name] = true
		t, err := buildTool(name, op)
		if err != nil {
			return nil, fmt.Errorf("openapi: %s %s: %w", op.method, op.path, err)
		}
		tools = append(tools, t)
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("openapi: no operations left after filtering")
	}
	return tools, nil
}

func (f Filter) selects(op *operation, name string) bool {
	if len(f.Methods) > 0 {
		ok := false
		for _, m := range f.Methods {
			if strings.EqualFold(m, op.method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	matchOp := func(patterns []string) bool {
		for _, p := range patterns {
			if m, _ := path.Match(p, name); m {
				return true
			}
			if op.operationID != "" {
				if m, _ := path.Match(p, op.operationID); m {
					return true
				}
			}
		}
		return false
	}
	matchTag := func(tags []string) bool {
		for _, want := range tags {
			for _, t := range op.tags {
				if strings.EqualFold(want, t) {
					return true
				}
			}
		}
		return false
	}
	if len(f.IncludeOperations) > 0 && !matchOp(f.IncludeOperations) {
		return false
	}
	if len(f.IncludeTags) > 0 && !matchTag(f.IncludeTags) {
		return false
	}
	if matchOp(f.ExcludeOperations) || matchTag(f.ExcludeTags) {
		return false
	}
	return true
}

func buildTool(name string, op *operation) (*Tool, error) {
	props := map[string]any{}
	var required []string
	for _, p := range op.params {
		if _, dup := props[p.name]; dup {
			return nil, fmt.Errorf("parameter %q is defined in more than one location", p.name)
		}
		sch := copySchema(p.schema)
		if p.description != "" {
			if _, has := sch["description"]; !has {
				sch["description"] = p.description
			}
		}
		props[p.name] = sch
		if p.required {
			required = append(required, p.name)
		}
	}

	t := &Tool{Name: name, op: op}
	if op.body != nil {
		bodyProps, _ := op.body.schema["properties"].(map[string]any)
		collides := false
		for pn := range bodyProps {
			if _, ok := props[pn]; ok {
				collides = true
				break
			}
		}
		// Flatten an object body into top-level arguments when that is
		// unambiguous. Besides being easier for models to fill in, this lets
		// policy argument rules (which inspect top-level scalars) constrain
		// body fields such as an amount or a recipient.
		if len(bodyProps) > 0 && !collides && isObjectSchema(op.body.schema) {
			t.bodyMode = "flat"
			t.bodyProps = map[string]bool{}
			reqSet := map[string]bool{}
			if rl, ok := op.body.schema["required"].([]any); ok {
				for _, r := range rl {
					if rs, ok := r.(string); ok {
						reqSet[rs] = true
					}
				}
			}
			for pn, ps := range bodyProps {
				props[pn] = ps
				t.bodyProps[pn] = true
				if reqSet[pn] && op.body.required {
					required = append(required, pn)
				}
			}
		} else {
			if _, ok := props["body"]; ok {
				return nil, fmt.Errorf("a parameter named \"body\" collides with the request body argument")
			}
			t.bodyMode = "arg"
			sch := copySchema(op.body.schema)
			if op.body.description != "" {
				if _, has := sch["description"]; !has {
					sch["description"] = op.body.description
				}
			}
			props["body"] = sch
			if op.body.required {
				required = append(required, "body")
			}
		}
	}
	sort.Strings(required)
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	t.InputSchema = schema
	t.Description = describe(op)
	t.Annotations = annotate(op)
	return t, nil
}

func isObjectSchema(s map[string]any) bool {
	switch t := s["type"].(type) {
	case nil:
		return true // properties without a type: an object in practice
	case string:
		return t == "object"
	case []any:
		for _, v := range t {
			if v == "object" {
				return true
			}
		}
	}
	return false
}

func copySchema(s map[string]any) map[string]any {
	out := make(map[string]any, len(s)+1)
	for k, v := range s {
		out[k] = v
	}
	return out
}

func describe(op *operation) string {
	var parts []string
	if op.summary != "" {
		parts = append(parts, op.summary)
	}
	if op.description != "" && op.description != op.summary {
		parts = append(parts, op.description)
	}
	parts = append(parts, fmt.Sprintf("(%s %s)", op.method, op.path))
	if op.deprecated {
		parts = append(parts, "Deprecated.")
	}
	d := strings.Join(parts, "\n\n")
	if len(d) > maxDescription {
		d = d[:maxDescription-3] + "..."
	}
	return d
}

// annotate sets MCP tool annotations from HTTP semantics, so clients can
// tell a safe lookup from a destructive call before invoking it.
func annotate(op *operation) map[string]any {
	a := map[string]any{"openWorldHint": true}
	if op.summary != "" {
		a["title"] = op.summary
	}
	switch op.method {
	case "GET", "HEAD", "OPTIONS":
		a["readOnlyHint"] = true
	case "DELETE":
		a["readOnlyHint"] = false
		a["destructiveHint"] = true
		a["idempotentHint"] = true
	case "PUT":
		a["readOnlyHint"] = false
		a["destructiveHint"] = true
		a["idempotentHint"] = true
	default: // POST, PATCH, TRACE
		a["readOnlyHint"] = false
		a["destructiveHint"] = op.method == "PATCH"
	}
	return a
}
