// Package ratelimit provides request rate limiting for the MCP gateway.
// Supports global rate limits and per-tool rate limits.
package ratelimit

import (
	"io"
	"net/http"
	"sync"

	"golang.org/x/time/rate"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/httperr"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

type Limiter struct {
	cfg     config.RateLimitConfig
	global  *rate.Limiter
	tools   map[string]*rate.Limiter
	toolsMu sync.RWMutex
}

func New(cfg config.RateLimitConfig) *Limiter {
	l := &Limiter{cfg: cfg, tools: make(map[string]*rate.Limiter)}
	if cfg.RPS > 0 {
		l.global = rate.NewLimiter(rate.Limit(cfg.RPS), max(cfg.Burst, 1))
	}
	return l
}

func (l *Limiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !l.cfg.Enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l.global != nil && !l.global.Allow() {
				w.Header().Set("Retry-After", "1")
				httperr.Write(w, http.StatusTooManyRequests, httperr.CodeRateLimited, "rate limit exceeded")
				return
			}
			if l.cfg.PerTool && r.Body != nil {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					httperr.Write(w, http.StatusBadRequest, httperr.CodeBadRequest, "failed to read request")
					return
				}
				r.Body = io.NopCloser(newBytesReader(body))
				req, _ := mcp.ParseRequest(body)
				if req != nil && req.Method == mcp.MethodToolsCall {
					tc, _ := mcp.ParseToolCall(req)
					if tc != nil && !l.getToolLimiter(tc.Name).Allow() {
						w.Header().Set("Retry-After", "1")
						httperr.WriteRPC(w, http.StatusTooManyRequests, req.ID, -32000, "rate limit exceeded for tool: "+tc.Name)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (l *Limiter) getToolLimiter(tool string) *rate.Limiter {
	l.toolsMu.RLock()
	lim, ok := l.tools[tool]
	l.toolsMu.RUnlock()
	if ok {
		return lim
	}
	l.toolsMu.Lock()
	defer l.toolsMu.Unlock()
	if lim, ok = l.tools[tool]; ok {
		return lim
	}
	rps := l.cfg.ToolRPS
	if rps <= 0 {
		rps = l.cfg.RPS
	}
	burst := l.cfg.ToolBurst
	if burst <= 0 {
		burst = max(l.cfg.Burst, 1)
	}
	lim = rate.NewLimiter(rate.Limit(rps), burst)
	l.tools[tool] = lim
	return lim
}

type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader { return &bytesReader{data: data} }
func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
