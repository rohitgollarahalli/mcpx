// Package proxy implements the core MCP reverse proxy.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rohitgs28/mcpx/internal/audit"
	"github.com/rohitgs28/mcpx/internal/auth"
	"github.com/rohitgs28/mcpx/internal/breaker"
	"github.com/rohitgs28/mcpx/internal/cache"
	"github.com/rohitgs28/mcpx/internal/config"
	"github.com/rohitgs28/mcpx/internal/httperr"
	"github.com/rohitgs28/mcpx/internal/integrity"
	"github.com/rohitgs28/mcpx/internal/mcp"
	"github.com/rohitgs28/mcpx/internal/metrics"
	"github.com/rohitgs28/mcpx/internal/policy"
	"github.com/rohitgs28/mcpx/internal/stdio"
	"github.com/rohitgs28/mcpx/internal/tracing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Gateway struct {
	servers  map[string]*Backend
	policy   *policy.Engine
	audit    *audit.Logger
	tools    *integrity.Store
	metrics  *metrics.Collector
	breakers *breaker.Manager // may be nil/disabled: Get returns nil breakers
	cache    *cache.Store     // may be nil/disabled: every method is a no-op
	rules    cacheRules       // per-server, per-tool cache TTLs (empty when caching is off)
	filter   bool             // remove policy-denied tools from tools/list responses
	inspect  bool             // true when integrity or filtering needs response interception
	mux      *http.ServeMux
}

type Backend struct {
	Name   string
	URL    string
	Proxy  *httputil.ReverseProxy // http/sse transports
	Stdio  *stdio.Client          // stdio transport
	Config config.ServerConfig
}

// ctxKey is the private type for request-scoped values the gateway threads
// through the reverse proxy into ModifyResponse.
type ctxKey int

const ctxKeyReqInfo ctxKey = iota

// reqInfo carries the parsed MCP routing details from handleMCP into the
// ModifyResponse hook (which only receives the outbound *http.Response).
type reqInfo struct {
	server string
	method string
	client string
}

// New builds a gateway. The policy engine and audit logger enforce/record
// per-request decisions; the integrity store (may be nil) pins tool schemas;
// the breaker manager (may be nil) fails fast on repeatedly-failing backends;
// the stdio manager (required only when a stdio server is configured) owns
// local child processes; the response cache (may be nil) serves repeat calls
// to idempotent tools. Tool-list filtering is enabled via
// cfg.Inspection.FilterToolsList.
func New(cfg *config.Config, pe *policy.Engine, al *audit.Logger, ts *integrity.Store, bm *breaker.Manager, sm *stdio.Manager, mc *metrics.Collector, cs *cache.Store) (*Gateway, error) {
	g := &Gateway{
		servers:  make(map[string]*Backend),
		policy:   pe,
		audit:    al,
		tools:    ts,
		metrics:  mc,
		breakers: bm,
		cache:    cs,
		mux:      http.NewServeMux(),
	}
	if cfg.Inspection != nil {
		g.filter = cfg.Inspection.FilterToolsList
	}
	if cs.Enabled() {
		g.rules = buildCacheRules(cfg.Servers, cs.DefaultTTL())
	}
	g.inspect = g.filter || (ts != nil && ts.Enabled())

	for _, sc := range cfg.Servers {
		switch sc.Transport {
		case "http", "sse":
			target, err := url.Parse(sc.URL)
			if err != nil {
				return nil, fmt.Errorf("parsing URL for server %q: %w", sc.Name, err)
			}
			p := httputil.NewSingleHostReverseProxy(target)
			transport, err := BackendTransport(sc)
			if err != nil {
				return nil, fmt.Errorf("server %q: tls: %w", sc.Name, err)
			}
			if transport != nil {
				p.Transport = transport
			}
			// The stdlib flushes text/event-stream bodies immediately; the
			// interval covers other streaming content types (e.g. ndjson).
			p.FlushInterval = 100 * time.Millisecond
			serverName := sc.Name
			p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				g.recordBackendFailure(serverName)
				httperr.Write(w, http.StatusBadGateway, httperr.CodeUpstreamError, "upstream error: "+err.Error())
			}
			// Wrap the director unconditionally so trace context is injected
			// into every outbound request (instrumented backends continue the
			// trace). When inspection is on we also force identity encoding so
			// ModifyResponse sees plain JSON and pin tools/list to a JSON
			// response: a Streamable HTTP backend may otherwise answer over
			// SSE, which would bypass integrity pinning and list filtering.
			// Injected headers (backend credentials) are set after the stock
			// director and replace any same-named client header, so a client
			// can neither see nor override them.
			orig := p.Director
			inject := sc.Headers
			p.Director = func(req *http.Request) {
				orig(req)
				for k, v := range inject {
					req.Header.Set(k, v)
				}
				tracing.InjectHeaders(req.Context(), req.Header)
				if g.inspect {
					req.Header.Del("Accept-Encoding")
					if info, _ := req.Context().Value(ctxKeyReqInfo).(*reqInfo); info != nil && info.method == mcp.MethodToolsList {
						req.Header.Set("Accept", "application/json")
					}
				}
			}
			// ModifyResponse also feeds the circuit breaker (5xx = failure),
			// so it is installed whenever inspection or breaking is on.
			if g.inspect || g.breakers.Enabled() {
				p.ModifyResponse = g.modifyResponse
			}
			g.servers[sc.Name] = &Backend{Name: sc.Name, URL: sc.URL, Proxy: p, Config: sc}
		case "stdio":
			if sm == nil {
				return nil, fmt.Errorf("server %q: stdio transport requires a stdio manager", sc.Name)
			}
			client := sm.Ensure(sc.Name, stdio.FromServerConfig(sc))
			g.servers[sc.Name] = &Backend{Name: sc.Name, URL: "stdio:" + sc.Command, Stdio: client, Config: sc}
		}
	}
	g.mux.HandleFunc("/mcp/", g.handleMCP)
	g.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "servers": len(g.servers)})
	})
	g.mux.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		type info struct {
			Name, URL, Transport string
			ReadOnly             bool
		}
		var s []info
		for _, b := range g.servers {
			readOnly := b.Config.Policy != nil && b.Config.Policy.ReadOnly
			s = append(s, info{b.Name, b.URL, b.Config.Transport, readOnly})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s)
	})
	return g, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.mux.ServeHTTP(w, r) }

// recordToolCall records a tools/call policy decision. It is a no-op for
// non-tool requests (empty tool) and when no metrics collector is configured.
func (g *Gateway) recordToolCall(server, tool, decision, client string) {
	if g.metrics == nil || tool == "" {
		return
	}
	g.metrics.RecordToolCall(server, tool, decision, client)
}

// recordBackendFailure feeds a backend failure to its circuit breaker,
// logging and counting the transition when this failure trips it open.
func (g *Gateway) recordBackendFailure(server string) {
	br := g.breakers.Get(server)
	if br == nil {
		return
	}
	if br.RecordFailure() {
		slog.Warn("circuit breaker opened", "server", server)
		if g.metrics != nil {
			g.metrics.RecordBreakerTrip()
		}
	}
	g.setBreakerMetric(server, br)
}

func (g *Gateway) setBreakerMetric(server string, br *breaker.Breaker) {
	if g.metrics != nil {
		g.metrics.SetBreakerState(server, int64(br.State()))
	}
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := strings.TrimPrefix(r.URL.Path, "/mcp/")
	parts := strings.SplitN(path, "/", 2)
	sn := parts[0]
	b, ok := g.servers[sn]
	if !ok {
		httperr.Write(w, http.StatusNotFound, httperr.CodeUnknownServer, "unknown server: "+sn)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httperr.Write(w, http.StatusBadRequest, httperr.CodeBadRequest, "failed to read request body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	mreq, _ := mcp.ParseRequest(body)
	client := auth.ClientFrom(r.Context())
	entry := audit.Entry{Timestamp: time.Now().UTC(), Server: sn, Client: client, ClientIP: r.RemoteAddr}
	var toolCall *mcp.ToolCallParams
	if mreq != nil {
		entry.Method = mreq.Method
		if tc, _ := mcp.ParseToolCall(mreq); tc != nil {
			toolCall = tc
			entry.Tool = tc.Name
		}
		tracing.Annotate(r.Context(), sn, entry.Method, entry.Tool, client)
		_, polSpan := tracing.Tracer().Start(r.Context(), "mcpx.policy")
		result := g.policy.Evaluate(sn, client, mreq)
		polSpan.End()
		if !result.Allowed {
			tracing.MarkDenied(r.Context(), result.Reason)
			entry.Allowed = false
			entry.Reason = result.Reason
			entry.StatusCode = http.StatusForbidden
			entry.DurationMs = time.Since(start).Milliseconds()
			g.audit.Log(entry)
			g.recordToolCall(sn, entry.Tool, "deny", client)
			httperr.WriteRPC(w, http.StatusForbidden, mreq.ID, -32600, result.Reason)
			return
		}
		g.recordToolCall(sn, entry.Tool, "allow", client)
	}
	// Response cache. Consulted after policy (so a denied call is never
	// answered from a warm entry) but before the circuit breaker: a hit costs
	// the backend nothing, so it is worth serving even while the circuit is
	// open. A miss returns an op the backend call below fills in.
	hit, cop := g.beginCache(r.Context(), sn, client, mreq, toolCall)
	if hit != nil {
		entry.Allowed = true
		entry.Cache = "hit"
		entry.StatusCode = g.serveCacheHit(w, hit, body)
		entry.DurationMs = time.Since(start).Milliseconds()
		g.audit.Log(entry)
		return
	}
	if cop != nil {
		entry.Cache = "miss"
		if cop.lead {
			// Release exactly once, whatever happens below: a follower blocked
			// on this key must never be stranded by an early return or panic.
			defer func() { g.cache.Release(cop.key, cop.stored) }()
		}
	}
	// Fail fast while the backend's circuit is open instead of queueing
	// requests against a dead upstream.
	if br := g.breakers.Get(sn); br != nil && !br.Allow() {
		entry.Allowed = false
		entry.Reason = "circuit breaker open"
		entry.StatusCode = http.StatusServiceUnavailable
		entry.DurationMs = time.Since(start).Milliseconds()
		g.audit.Log(entry)
		msg := fmt.Sprintf("server %q temporarily unavailable (circuit open)", sn)
		if mreq != nil {
			httperr.WriteRPC(w, http.StatusServiceUnavailable, mreq.ID, -32000, msg)
		} else {
			httperr.Write(w, http.StatusServiceUnavailable, httperr.CodeUpstreamUnavailable, msg)
		}
		return
	}
	// Stdio backends bypass the reverse proxy entirely: the request is
	// bridged onto the child process and the reply written directly.
	if b.Stdio != nil {
		g.serveStdio(w, r, b, mreq, body, entry, start, cop)
		return
	}
	// Thread routing details to ModifyResponse: tools/list inspection needs
	// server/method/client, the circuit breaker needs the server name.
	if g.inspect || g.breakers.Enabled() {
		method := ""
		if mreq != nil {
			method = mreq.Method
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyReqInfo, &reqInfo{server: sn, method: method, client: client}))
	}
	entry.Allowed = true
	r.URL.Path = "/"
	if len(parts) > 1 {
		r.URL.Path = "/" + parts[1]
	}
	// Span the backend call; its context is threaded into the outbound request
	// so the injected trace context (and any instrumented backend's span)
	// parents on mcpx.proxy rather than the root request span.
	ctx, proxySpan := tracing.Tracer().Start(r.Context(), "mcpx.proxy",
		trace.WithAttributes(attribute.String("mcpx.transport", b.Config.Transport)))
	r = r.WithContext(ctx)
	// Clients that accept SSE may receive a long-lived stream, which must
	// outlive the server's global WriteTimeout.
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		tracing.MarkStreaming(ctx)
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	}
	// For a cacheable tool the leader buffers the response so it can be stored;
	// captureWriter falls back to streaming the moment the response turns out
	// not to be a bounded JSON reply.
	if cop != nil {
		w.Header().Set(CacheHeader, "miss")
	}
	if cop != nil && cop.lead {
		cw := newCaptureWriter(w, g.cache.MaxBodyBytes())
		b.Proxy.ServeHTTP(cw, r)
		cop.stored = g.storeCacheable(cop, cw.status, cw.Header().Get("Content-Type"), cw.body())
		cw.finish()
	} else {
		b.Proxy.ServeHTTP(w, r)
	}
	proxySpan.End()
	entry.DurationMs = time.Since(start).Milliseconds()
	entry.StatusCode = http.StatusOK
	g.audit.Log(entry)
}

// serveStdio bridges one HTTP request onto a stdio backend. Auth, rate
// limiting, policy, and the circuit breaker have already run by the time we
// get here; this handles transport translation, feeds the breaker, and
// applies the same tools/list inspection the reverse proxy path gets.
func (g *Gateway) serveStdio(w http.ResponseWriter, r *http.Request, b *Backend, mreq *mcp.Request, body []byte, entry audit.Entry, start time.Time, cop *cacheOp) {
	finish := func(status int) {
		entry.StatusCode = status
		entry.DurationMs = time.Since(start).Milliseconds()
		g.audit.Log(entry)
	}
	if r.Method != http.MethodPost {
		finish(http.StatusMethodNotAllowed)
		httperr.Write(w, http.StatusMethodNotAllowed, httperr.CodeBadRequest, "stdio backends accept POST only")
		return
	}
	if mreq == nil {
		finish(http.StatusBadRequest)
		httperr.Write(w, http.StatusBadRequest, httperr.CodeBadRequest, "stdio backends require a JSON-RPC request body")
		return
	}
	// Notifications expect no reply; 202 mirrors the Streamable HTTP spec.
	if mreq.ID == nil {
		if err := b.Stdio.Notify(body); err != nil {
			g.recordBackendFailure(b.Name)
			finish(http.StatusBadGateway)
			httperr.Write(w, http.StatusBadGateway, httperr.CodeUpstreamError, "upstream error: "+err.Error())
			return
		}
		finish(http.StatusAccepted)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	_, proxySpan := tracing.Tracer().Start(r.Context(), "mcpx.proxy",
		trace.WithAttributes(attribute.String("mcpx.transport", "stdio")))
	respBody, err := b.Stdio.Call(r.Context(), body)
	proxySpan.End()
	if err != nil {
		g.recordBackendFailure(b.Name)
		finish(http.StatusBadGateway)
		httperr.WriteRPC(w, http.StatusBadGateway, mreq.ID, -32000, "upstream error: "+err.Error())
		return
	}
	if br := g.breakers.Get(b.Name); br != nil {
		br.RecordSuccess()
		g.setBreakerMetric(b.Name, br)
	}
	if g.inspect && mreq.Method == mcp.MethodToolsList {
		if newBody, changed := g.processToolsList(b.Name, entry.Client, respBody); changed {
			respBody = newBody
		}
	}
	if cop != nil {
		w.Header().Set(CacheHeader, "miss")
		if cop.lead {
			cop.stored = g.storeCacheable(cop, http.StatusOK, "application/json", respBody)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	finish(http.StatusOK)
	w.Write(respBody)
}

// modifyResponse inspects tools/list responses, applying schema-integrity
// pinning and policy-based tool filtering before the body reaches the client.
// All other responses pass through untouched.
func (g *Gateway) modifyResponse(resp *http.Response) error {
	info, _ := resp.Request.Context().Value(ctxKeyReqInfo).(*reqInfo)
	// Feed the circuit breaker: a 5xx counts as a backend failure, anything
	// else proves the backend alive.
	if info != nil {
		if br := g.breakers.Get(info.server); br != nil {
			if resp.StatusCode >= http.StatusInternalServerError {
				g.recordBackendFailure(info.server)
			} else {
				br.RecordSuccess()
				g.setBreakerMetric(info.server, br)
			}
		}
	}
	// Streaming responses (MCP Streamable HTTP / SSE) pass through untouched:
	// reading the body here would buffer the stream and stall the client.
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil
	}
	if !g.inspect || info == nil || info.method != mcp.MethodToolsList || resp.StatusCode != http.StatusOK {
		return nil
	}
	// We forced identity encoding upstream; if a server compressed anyway,
	// leave the body alone rather than risk corrupting it.
	if resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	newBody, changed := g.processToolsList(info.server, info.client, body)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	return nil
}

// processToolsList returns a (possibly rewritten) tools/list response body and
// whether it changed. It drops tools whose schema mutated (enforce mode) and
// tools the policy forbids (when filtering is enabled), logging integrity
// violations to the audit trail.
func (g *Gateway) processToolsList(server, client string, body []byte) ([]byte, bool) {
	var rpc mcp.Response
	if err := json.Unmarshal(body, &rpc); err != nil || rpc.Error != nil || len(rpc.Result) == 0 {
		return body, false
	}
	tl, err := mcp.ParseToolsListResult(rpc.Result)
	if err != nil {
		return body, false
	}

	// Schema-integrity pinning: detect mutated tools.
	drop := make(map[string]bool)
	if g.tools != nil && g.tools.Enabled() {
		enforce := g.tools.Mode() == integrity.ModeEnforce
		for _, v := range g.tools.Check(server, tl.Tools) {
			reason := "tool schema changed since pinned baseline (possible rug-pull/mutation)"
			g.audit.Log(audit.Entry{
				Timestamp: time.Now().UTC(),
				Server:    server,
				Method:    mcp.MethodToolsList,
				Tool:      v.Tool,
				Allowed:   !enforce,
				Reason:    reason,
			})
			if enforce {
				drop[v.Tool] = true
			}
		}
	}

	changed := false
	kept := make([]json.RawMessage, 0, len(tl.Tools))
	for _, raw := range tl.Tools {
		name := mcp.ToolName(raw)
		if drop[name] {
			changed = true
			continue
		}
		if g.filter && !g.policy.ToolAllowed(server, client, name) {
			changed = true
			continue
		}
		kept = append(kept, raw)
	}
	if !changed {
		return body, false
	}

	tl.Tools = kept
	newResult, err := json.Marshal(tl)
	if err != nil {
		return body, false
	}
	rpc.Result = newResult
	newBody, err := json.Marshal(rpc)
	if err != nil {
		return body, false
	}
	return newBody, true
}
