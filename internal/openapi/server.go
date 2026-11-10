package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Options configures a Server.
type Options struct {
	// Name identifies the backend (the gateway's server name); it appears in
	// the MCP serverInfo.
	Name string
	// BaseURL is the API root every operation path is appended to, e.g.
	// https://api.example.com/v1. Required.
	BaseURL string
	// Headers are set on every upstream API request (credentials). They
	// replace any same-named header parameter a tool call supplies.
	Headers map[string]string
	// Filter selects which operations are exposed as tools.
	Filter Filter
	// Timeout bounds each upstream request (default 30s).
	Timeout time.Duration
	// MaxResponseBytes caps how much of an upstream response is returned to
	// the client (default 1 MiB); longer bodies are truncated with a note.
	MaxResponseBytes int64
	// Transport is the HTTP transport for upstream requests (TLS settings);
	// nil uses http.DefaultTransport.
	Transport http.RoundTripper
	// Version is reported in serverInfo.
	Version string
}

// Server is an MCP server (Streamable HTTP, JSON responses) backed by a REST
// API. It is safe for concurrent use.
type Server struct {
	name     string
	version  string
	base     *url.URL
	headers  map[string]string
	client   *http.Client
	maxBytes int64
	tools    []*Tool
	byName   map[string]*Tool
	toolList json.RawMessage // pre-rendered tools/list result
}

const (
	defaultTimeout          = 30 * time.Second
	defaultMaxResponseBytes = 1 << 20
	// latestProtocol is answered when a client asks for a version this
	// server does not know.
	latestProtocol = "2025-06-18"
)

var supportedProtocols = map[string]bool{
	"2024-11-05": true, "2025-03-26": true, "2025-06-18": true,
}

// New builds a Server for the operations in spec selected by opts.Filter.
func New(spec *Spec, opts Options) (*Server, error) {
	if spec == nil {
		return nil, errors.New("openapi: nil spec")
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("openapi: base url %q must be an absolute http(s) URL", opts.BaseURL)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("openapi: base url %q must use http or https", opts.BaseURL)
	}
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawQuery, base.Fragment = "", ""

	tools, err := spec.BuildTools(opts.Filter)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	maxBytes := opts.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	s := &Server{
		name:     opts.Name,
		version:  opts.Version,
		base:     base,
		headers:  opts.Headers,
		maxBytes: maxBytes,
		tools:    tools,
		byName:   make(map[string]*Tool, len(tools)),
	}
	s.client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Injected credentials must never follow a redirect to another
		// host (the stdlib strips Authorization cross-host, but not custom
		// API-key headers). Same-host redirects are followed as usual.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Host != s.base.Host || req.URL.Scheme != s.base.Scheme {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	list := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		s.byName[t.Name] = t
		list = append(list, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
			"annotations": t.Annotations,
		})
	}
	s.toolList, err = json.Marshal(map[string]any{"tools": list})
	if err != nil {
		return nil, fmt.Errorf("openapi: rendering tool list: %w", err)
	}
	return s, nil
}

// Tools returns the generated tools in tools/list order.
func (s *Server) Tools() []*Tool { return s.tools }

// --- JSON-RPC over HTTP --------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// errUpstream marks failures of the API itself (unreachable, timeout, 5xx).
// They are answered with HTTP 502 so the gateway's circuit breaker counts
// them; client mistakes (4xx) come back as tool results with isError set,
// which lets the model correct its arguments and retry.
type errUpstream struct{ msg string }

func (e *errUpstream) Error() string { return e.msg }

// ServeHTTP implements the MCP Streamable HTTP transport for a server that
// always answers with a single JSON response (no SSE streams, no sessions).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeRPC(w, http.StatusMethodNotAllowed, nil, nil, &rpcError{Code: -32600, Message: "openapi backends accept POST only"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeRPC(w, http.StatusBadRequest, nil, nil, &rpcError{Code: -32700, Message: "failed to read request body"})
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		writeRPC(w, http.StatusBadRequest, nil, nil, &rpcError{Code: -32600, Message: "JSON-RPC batches are not supported"})
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil || req.Method == "" {
		writeRPC(w, http.StatusBadRequest, nil, nil, &rpcError{Code: -32700, Message: "invalid JSON-RPC request"})
		return
	}
	// Notifications (no id) and client responses expect no reply.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		writeRPC(w, http.StatusOK, req.ID, s.initialize(req.Params), nil)
	case "ping":
		writeRPC(w, http.StatusOK, req.ID, json.RawMessage(`{}`), nil)
	case "tools/list":
		writeRPC(w, http.StatusOK, req.ID, s.toolList, nil)
	case "tools/call":
		result, err := s.call(r.Context(), req.Params)
		var up *errUpstream
		switch {
		case errors.As(err, &up):
			writeRPC(w, http.StatusBadGateway, req.ID, nil, &rpcError{Code: -32000, Message: up.msg})
		case err != nil:
			writeRPC(w, http.StatusOK, req.ID, nil, &rpcError{Code: -32602, Message: err.Error()})
		default:
			writeRPC(w, http.StatusOK, req.ID, result, nil)
		}
	case "resources/list", "resources/templates/list", "prompts/list":
		// Not offered (capabilities say so), but answering empty keeps
		// clients that probe anyway from logging errors.
		key := map[string]string{"resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}[req.Method]
		writeRPC(w, http.StatusOK, req.ID, map[string]any{key: []any{}}, nil)
	default:
		writeRPC(w, http.StatusOK, req.ID, nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
	}
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := latestProtocol
	if supportedProtocols[p.ProtocolVersion] {
		version = p.ProtocolVersion
	}
	name := "mcpx-openapi"
	if s.name != "" {
		name += "/" + s.name
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": name, "version": s.version},
		"instructions":    "Each tool calls one REST API operation. Path, query and header parameters, and request-body fields, are tool arguments.",
	}
}

func writeRPC(w http.ResponseWriter, status int, id json.RawMessage, result any, rerr *rpcError) {
	resp := map[string]any{"jsonrpc": "2.0"}
	if len(id) > 0 {
		resp["id"] = id
	} else {
		resp["id"] = nil
	}
	if rerr != nil {
		resp["error"] = rerr
	} else {
		resp["result"] = result
	}
	b, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	w.Write(b)
}

// --- tool execution ------------------------------------------------------------

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

func (s *Server) call(ctx context.Context, raw json.RawMessage) (*callResult, error) {
	var p callParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %v", err)
	}
	t, ok := s.byName[p.Name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", p.Name)
	}
	req, err := s.buildRequest(ctx, t, p.Arguments)
	if err != nil {
		// Argument problems are the model's to fix: report as a tool error.
		return &callResult{Content: []content{{Type: "text", Text: err.Error()}}, IsError: true}, nil
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &errUpstream{msg: "upstream API request failed: " + scrubURLError(err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes+1))
	if err != nil {
		return nil, &errUpstream{msg: "reading upstream API response: " + err.Error()}
	}
	truncated := int64(len(data)) > s.maxBytes
	if truncated {
		data = data[:s.maxBytes]
	}
	if resp.StatusCode >= 500 {
		return nil, &errUpstream{msg: fmt.Sprintf("upstream API returned HTTP %d: %s", resp.StatusCode, snippet(data))}
	}
	text := string(data)
	if text == "" {
		text = fmt.Sprintf("HTTP %d %s (empty body)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if resp.StatusCode >= 300 {
		text = fmt.Sprintf("HTTP %d %s\n\n%s", resp.StatusCode, http.StatusText(resp.StatusCode), text)
	}
	if truncated {
		text += fmt.Sprintf("\n\n[mcpx: response truncated to %d bytes]", s.maxBytes)
	}
	return &callResult{Content: []content{{Type: "text", Text: text}}, IsError: resp.StatusCode >= 300}, nil
}

// scrubURLError drops the request URL from client errors: query parameters
// can carry user data that does not belong in error messages and logs.
func scrubURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

// buildRequest maps tool arguments onto the operation's path, query, header
// and body. Unknown arguments are rejected rather than silently dropped, so
// a model that misnames a field finds out.
func (s *Server) buildRequest(ctx context.Context, t *Tool, args map[string]any) (*http.Request, error) {
	op := t.op
	known := map[string]bool{}
	path := op.path
	query := url.Values{}
	headers := http.Header{}

	for _, p := range op.params {
		known[p.name] = true
		v, present := args[p.name]
		if !present || v == nil {
			if p.required {
				return nil, fmt.Errorf("missing required argument %q", p.name)
			}
			continue
		}
		switch p.in {
		case "path":
			sv, err := scalarString(v)
			if err != nil {
				return nil, fmt.Errorf("argument %q: %v", p.name, err)
			}
			// A path parameter fills exactly one segment: escape slashes and
			// refuse dot segments so a value cannot walk to another endpoint.
			if sv == "" || sv == "." || sv == ".." {
				return nil, fmt.Errorf("argument %q: invalid path segment %q", p.name, sv)
			}
			path = strings.ReplaceAll(path, "{"+p.name+"}", url.PathEscape(sv))
		case "query":
			if err := addQuery(query, p, v); err != nil {
				return nil, err
			}
		case "header":
			sv, err := scalarString(v)
			if err != nil {
				return nil, fmt.Errorf("argument %q: %v", p.name, err)
			}
			if strings.ContainsAny(sv, "\r\n\x00") {
				return nil, fmt.Errorf("argument %q: header values must not contain CR, LF or NUL", p.name)
			}
			headers.Set(p.name, sv)
		}
	}

	var body io.Reader
	switch t.bodyMode {
	case "arg":
		known["body"] = true
		if v, ok := args["body"]; ok && v != nil {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("argument \"body\": %v", err)
			}
			body = bytes.NewReader(b)
		} else if op.body.required {
			return nil, fmt.Errorf("missing required argument \"body\"")
		}
	case "flat":
		obj := map[string]any{}
		for name := range t.bodyProps {
			known[name] = true
			if v, ok := args[name]; ok {
				obj[name] = v
			}
		}
		if len(obj) > 0 || op.body.required {
			b, err := json.Marshal(obj)
			if err != nil {
				return nil, fmt.Errorf("request body: %v", err)
			}
			body = bytes.NewReader(b)
		}
	}

	var unknown []string
	for k := range args {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown argument(s): %s", strings.Join(unknown, ", "))
	}

	// Keep the encoded form exactly as built: decoding and re-encoding
	// would turn an escaped slash inside an id back into a path separator.
	escaped := s.base.EscapedPath() + escapeTemplate(path)
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return nil, fmt.Errorf("building request path: %v", err)
	}
	u := *s.base
	u.Path, u.RawPath = decoded, escaped
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, op.method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("building request: %v", err)
	}
	for k, vs := range headers {
		req.Header[k] = vs
	}
	if body != nil {
		req.Header.Set("Content-Type", op.body.contentType)
	}
	req.Header.Set("Accept", "application/json, */*;q=0.5")
	req.Header.Set("User-Agent", "mcpx-openapi")
	// Injected credentials go last so a tool argument can never replace them.
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// escapeTemplate returns path with its literal parts escaped but already
// percent-encoded parameter values left alone. Values were inserted with
// url.PathEscape, so the only '%' characters present start escape sequences
// that must survive verbatim (a slash inside an id stays %2F).
func escapeTemplate(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '%' && i+2 < len(p) {
			b.WriteString(p[i : i+3])
			i += 2
			continue
		}
		if c == '/' {
			b.WriteByte('/')
			continue
		}
		b.WriteString(url.PathEscape(string(c)))
	}
	return b.String()
}

func addQuery(q url.Values, p param, v any) error {
	switch x := v.(type) {
	case []any:
		vals := make([]string, 0, len(x))
		for _, item := range x {
			sv, err := scalarString(item)
			if err != nil {
				return fmt.Errorf("argument %q: %v", p.name, err)
			}
			vals = append(vals, sv)
		}
		if p.explode {
			for _, sv := range vals {
				q.Add(p.name, sv)
			}
		} else {
			q.Set(p.name, strings.Join(vals, ","))
		}
	case map[string]any:
		// Deep-object styles vary between APIs; send the object as JSON,
		// which is unambiguous and widely accepted.
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Errorf("argument %q: %v", p.name, err)
		}
		q.Set(p.name, string(b))
	default:
		sv, err := scalarString(v)
		if err != nil {
			return fmt.Errorf("argument %q: %v", p.name, err)
		}
		q.Set(p.name, sv)
	}
	return nil
}

// scalarString renders a JSON scalar the way it appears in a URL: numbers in
// their shortest form, booleans as true/false.
func scalarString(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case json.Number:
		return x.String(), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	default:
		return "", fmt.Errorf("expected a string, number or boolean, got %T", v)
	}
}

// Probe reports whether the upstream API is reachable: any HTTP response to
// a GET on the base URL counts, except a 5xx. Used by the gateway's /health.
func (s *Server) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base.String(), nil)
	if err != nil {
		return err
	}
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("unreachable: " + scrubURLError(err))
	}
	// Drain a little so the connection can be reused; a read error here
	// says nothing about the API's health.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}
	return nil
}
