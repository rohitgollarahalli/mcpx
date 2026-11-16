package proxy

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/cache"
	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

// CacheHeader tells a client whether its response came from the gateway's
// response cache ("hit") or from the backend ("miss").
const CacheHeader = "X-Mcpx-Cache"

// cacheRules indexes the per-server, per-tool cache TTLs from config:
// server -> tool -> ttl. A tool absent from the map is never cached.
type cacheRules map[string]map[string]time.Duration

// buildCacheRules flattens servers[].cache.tools into a lookup table. A tool
// with no explicit ttl gets defaultTTL.
func buildCacheRules(servers []config.ServerConfig, defaultTTL time.Duration) cacheRules {
	var rules cacheRules
	for _, sc := range servers {
		if sc.Cache == nil || len(sc.Cache.Tools) == 0 {
			continue
		}
		tools := make(map[string]time.Duration, len(sc.Cache.Tools))
		for name, rule := range sc.Cache.Tools {
			ttl := time.Duration(rule.TTL)
			if ttl <= 0 {
				ttl = defaultTTL
			}
			tools[name] = ttl
		}
		if rules == nil {
			rules = make(cacheRules)
		}
		rules[sc.Name] = tools
	}
	return rules
}

// ttlFor returns the cache TTL for a tool and whether it is cacheable at all.
func (r cacheRules) ttlFor(server, tool string) (time.Duration, bool) {
	tools, ok := r[server]
	if !ok {
		return 0, false
	}
	ttl, ok := tools[tool]
	return ttl, ok
}

// cacheOp is the per-request cache state threaded through a cacheable call.
// It exists only for tools/call requests naming a tool the config opted in.
type cacheOp struct {
	key string
	ttl time.Duration
	// lead is true when this request owns the in-flight backend fetch for key
	// and must Release it (single-flight). Followers wait for the leader and
	// either reuse its entry or, if it produced nothing cacheable, call the
	// backend themselves without caching.
	lead bool
	// stored is the entry handed to single-flight waiters on Release; nil
	// means "nothing cacheable came back, go fetch it yourself".
	stored *cache.Entry
}

// beginCache decides whether a request may be served from (or stored in) the
// response cache. It returns a live entry on a hit, and otherwise an op the
// caller must carry through the backend call.
//
// Callers must invoke this only after the policy engine has allowed the
// request: the cache is consulted downstream of policy so that a tool a client
// is no longer permitted to call can never be answered from a warm entry.
func (g *Gateway) beginCache(ctx context.Context, server, client string, mreq *mcp.Request, tc *mcp.ToolCallParams) (*cache.Entry, *cacheOp) {
	if !g.cache.Enabled() || mreq == nil || tc == nil || tc.Name == "" || mreq.Method != mcp.MethodToolsCall {
		return nil, nil
	}
	ttl, ok := g.rules.ttlFor(server, tc.Name)
	if !ok {
		return nil, nil
	}
	key := cache.Key(server, tc.Name, client, tc.Arguments)
	if e := g.cache.Get(key); e != nil {
		g.recordCacheLookup(server, tc.Name, "hit")
		return e, nil
	}
	op := &cacheOp{key: key, ttl: ttl}
	// Single-flight: only the leader calls the backend. A follower that gets a
	// shared entry is a hit for every purpose except that it waited.
	lead, shared := g.cache.Lead(ctx, key)
	if !lead && shared != nil {
		g.recordCacheLookup(server, tc.Name, "hit")
		return shared, nil
	}
	op.lead = lead
	g.recordCacheLookup(server, tc.Name, "miss")
	return nil, op
}

// recordCacheLookup counts a cache lookup and refreshes the occupancy gauges.
func (g *Gateway) recordCacheLookup(server, tool, result string) {
	if g.metrics == nil {
		return
	}
	g.metrics.RecordCacheLookup(server, tool, result)
	g.metrics.SetCacheStats(int64(g.cache.Stats().Entries), g.cache.Evictions())
}

// serveCacheHit writes a cached response to the client, re-pointing it at the
// current request's JSON-RPC id so the client can match it to what it asked.
func (g *Gateway) serveCacheHit(w http.ResponseWriter, e *cache.Entry, reqBody []byte) int {
	body := cache.RetargetID(e.Body, mcp.RawID(reqBody))
	ct := e.ContentType
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set(CacheHeader, "hit")
	// Age lets a client (or a human reading a capture) see how stale the
	// answer is, mirroring the HTTP header of the same name.
	w.Header().Set("Age", strconv.Itoa(int(e.Age(time.Now()).Seconds())))
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return http.StatusOK
}

// storeCacheable stores a backend response under op's key when it qualifies,
// returning the stored entry (nil when nothing was cached). Anything other
// than a bounded, non-streaming, successful JSON-RPC result is skipped — see
// cache.Cacheable for why failures in particular are never stored.
func (g *Gateway) storeCacheable(op *cacheOp, status int, contentType string, body []byte) *cache.Entry {
	if op == nil || status != http.StatusOK || len(body) == 0 {
		return nil
	}
	if ct := contentType; ct != "" && !strings.HasPrefix(ct, "application/json") {
		return nil
	}
	if !cache.Cacheable(body) {
		return nil
	}
	return g.cache.Put(op.key, body, contentType, op.ttl)
}

// captureWriter buffers a response so the gateway can cache it, while staying
// transparent to anything that must not be buffered.
//
// It gives up buffering (and caching) the moment the response proves to be a
// stream — a non-200 status, an event-stream content type, an explicit Flush,
// or a body past max — and from then on writes straight through. Because the
// switch happens before any bytes reach the client, the client sees a normal
// response either way; it just may not be cached.
type captureWriter struct {
	http.ResponseWriter
	max int

	status      int
	wroteHeader bool // the handler has declared a status
	sent        bool // the status has been forwarded to the real writer
	passthrough bool // no longer buffering; writes go straight out
	buf         bytes.Buffer
}

func newCaptureWriter(w http.ResponseWriter, max int) *captureWriter {
	return &captureWriter{ResponseWriter: w, max: max, status: http.StatusOK}
}

func (c *captureWriter) WriteHeader(code int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	c.status = code
	// Only a plain 200 is worth buffering; a stream must reach the client as
	// it is produced.
	if code != http.StatusOK || strings.HasPrefix(c.Header().Get("Content-Type"), "text/event-stream") {
		c.stopBuffering()
	}
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if c.passthrough {
		return c.ResponseWriter.Write(p)
	}
	if c.buf.Len()+len(p) > c.max {
		// Too large to cache: flush what we hold and stream the rest.
		c.stopBuffering()
		return c.ResponseWriter.Write(p)
	}
	return c.buf.Write(p)
}

// Flush signals that the caller wants bytes on the wire now, which is
// incompatible with buffering: stop and delegate.
func (c *captureWriter) Flush() {
	c.stopBuffering()
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer (the gateway
// lifts write deadlines for SSE through this chain).
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// stopBuffering commits everything buffered so far to the real writer and
// switches to pass-through. Safe to call repeatedly.
func (c *captureWriter) stopBuffering() {
	if c.passthrough {
		return
	}
	c.passthrough = true
	c.sendHeader()
	if c.buf.Len() > 0 {
		c.ResponseWriter.Write(c.buf.Bytes())
		c.buf.Reset()
	}
}

func (c *captureWriter) sendHeader() {
	if c.sent {
		return
	}
	c.sent = true
	c.ResponseWriter.WriteHeader(c.status)
}

// finish releases the buffered response to the client. It is a no-op once the
// writer has switched to pass-through, which has already sent everything.
func (c *captureWriter) finish() {
	if c.passthrough {
		return
	}
	c.sendHeader()
	if c.buf.Len() > 0 {
		c.ResponseWriter.Write(c.buf.Bytes())
	}
}

// body returns the buffered response, or nil once buffering was abandoned.
func (c *captureWriter) body() []byte {
	if c.passthrough {
		return nil
	}
	return c.buf.Bytes()
}
