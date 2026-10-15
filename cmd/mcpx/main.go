// mcpx - Lightweight MCP gateway proxy
//
// Sits between MCP clients and MCP servers, adding auth, rate limiting,
// tool-level access control, audit logging, and Prometheus metrics.
//
// Usage:
//
//	mcpx -c mcpx.yaml
//	mcpx -c mcpx.yaml -watch          # hot-reload on file change
//	mcpx -c mcpx.yaml -watch-interval 5s
//	mcpx --version
//
// Send SIGHUP to the running process to force a reload at any time.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rohitgs28/mcpx/internal/audit"
	"github.com/rohitgs28/mcpx/internal/auth"
	"github.com/rohitgs28/mcpx/internal/breaker"
	"github.com/rohitgs28/mcpx/internal/cache"
	"github.com/rohitgs28/mcpx/internal/config"
	"github.com/rohitgs28/mcpx/internal/cors"
	"github.com/rohitgs28/mcpx/internal/health"
	"github.com/rohitgs28/mcpx/internal/httperr"
	"github.com/rohitgs28/mcpx/internal/integrity"
	"github.com/rohitgs28/mcpx/internal/metrics"
	"github.com/rohitgs28/mcpx/internal/middleware"
	"github.com/rohitgs28/mcpx/internal/policy"
	"github.com/rohitgs28/mcpx/internal/proxy"
	"github.com/rohitgs28/mcpx/internal/ratelimit"
	"github.com/rohitgs28/mcpx/internal/stdio"
	"github.com/rohitgs28/mcpx/internal/tracing"
)

const version = "0.1.0"

func main() {
	// CLI flags
	configPath := flag.String("c", "mcpx.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(showVersion, "v", false, "print version and exit (shorthand)")
	watchFlag := flag.Bool("watch", false, "watch config file and hot-reload on change")
	watchInterval := flag.Duration("watch-interval", 2*time.Second, "config file poll interval when -watch is set")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mcpx v%s\n", version)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}

	// Tracing is configured once at startup (the exporter connection persists
	// across reloads). On error we log and continue without tracing rather than
	// fail the gateway over telemetry; Init returns a no-op shutdown in that case.
	traceShutdown, err := tracing.Init(cfg.Tracing, version)
	if err != nil {
		slog.Error("failed to initialize tracing, continuing without it", "error", err)
	}
	initialTracing := cfg.Tracing != nil && cfg.Tracing.Enabled

	// Metrics collector persists across reloads so counters are not reset.
	mc := metrics.New()

	// Tool-schema pin store persists across reloads so the integrity baseline
	// (and thus rug-pull detection) survives config changes. The mode is read
	// once at startup.
	integMode := integrity.ModeOff
	if cfg.Inspection != nil {
		integMode = integrity.ParseMode(cfg.Inspection.ToolIntegrity)
	}
	ts := integrity.NewStore(integMode)

	// Circuit-breaker state also persists across reloads (an open breaker
	// must not reset on SIGHUP); its settings are read once at startup.
	var bm *breaker.Manager
	if cb := cfg.CircuitBreaker; cb != nil && cb.Enabled {
		bm = breaker.NewManager(breaker.Config{
			FailureThreshold: cb.FailureThreshold,
			Cooldown:         time.Duration(cb.Cooldown),
			HalfOpenMax:      cb.HalfOpenMax,
		}, true)
	}

	// The response cache persists across reloads too, so a reload does not
	// throw away a warm cache. Its sizing is read once at startup; which tools
	// are cacheable comes from the per-server config and does reload. Set
	// cache.purge_on_reload to empty it on every reload instead.
	var cs *cache.Store
	if cc := cfg.Cache; cc != nil && cc.Enabled {
		cs = cache.New(cache.Config{
			MaxEntries:   cc.MaxEntries,
			DefaultTTL:   time.Duration(cc.DefaultTTL),
			MaxBodyBytes: cc.MaxBodyBytes,
		}, true)
	}

	// Stdio child processes also persist across reloads: a SIGHUP that
	// leaves a server's spawn config untouched keeps its process (and the
	// MCP sessions on it) running.
	sm := stdio.NewManager()

	// Build the initial handler and wrap it in a reloadable shell.
	// On reload, we atomically swap the inner handler — new requests see
	// the new config, in-flight requests finish against the old one.
	initialHandler, initialAudit := buildHandler(cfg, mc, ts, bm, sm, cs)
	reloadable := newReloadableHandler(initialHandler)

	// currentAudit tracks the live audit logger so its file handle can be
	// closed when retired. Guarded by auditMu: reload runs on the SIGHUP
	// and watch goroutines, the final Close on the main goroutine.
	var auditMu sync.Mutex
	currentAudit := initialAudit

	// Build HTTP server against the reloadable wrapper. The listen address
	// is captured from the initial config; changing it requires a restart.
	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      reloadable,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	initialListen := cfg.Listen

	// reload applies a freshly loaded config by rebuilding the handler
	// chain and atomically swapping it. It never mutates srv.Addr.
	reload := func(newCfg *config.Config) {
		if newCfg.Listen != initialListen {
			slog.Warn("listen address change requires restart; ignoring",
				"current", initialListen, "new", newCfg.Listen)
		}
		if newTracing := newCfg.Tracing != nil && newCfg.Tracing.Enabled; newTracing != initialTracing {
			slog.Warn("tracing enable/disable requires restart; ignoring",
				"current", initialTracing, "new", newTracing)
		}
		if newCache := newCfg.Cache != nil && newCfg.Cache.Enabled; newCache != cs.Enabled() {
			slog.Warn("cache enable/disable requires restart; ignoring",
				"current", cs.Enabled(), "new", newCache)
		}
		if newCfg.Cache != nil && newCfg.Cache.PurgeOnReload {
			cs.Purge()
		}
		h, newAudit := buildHandler(newCfg, mc, ts, bm, sm, cs)
		reloadable.swap(h)
		// Stop child processes for stdio servers dropped from the config.
		active := make(map[string]bool)
		for _, s := range newCfg.Servers {
			if s.Transport == "stdio" {
				active[s.Name] = true
			}
		}
		sm.Prune(active)
		// Close the retired audit logger's file handle. In-flight requests
		// on the old handler may lose their audit lines — acceptable, and
		// strictly better than leaking a handle on every reload.
		auditMu.Lock()
		if currentAudit != nil {
			if err := currentAudit.Close(); err != nil {
				slog.Warn("failed to close retired audit logger", "error", err)
			}
		}
		currentAudit = newAudit
		auditMu.Unlock()
		slog.Info("config reloaded",
			"servers", len(newCfg.Servers),
			"auth", newCfg.Auth != nil && newCfg.Auth.Enabled,
			"rate_limit", newCfg.RateLimit != nil && newCfg.RateLimit.Enabled,
			"audit", newCfg.Audit != nil && newCfg.Audit.Enabled,
		)
	}

	// Signals: SIGINT/SIGTERM = shutdown, SIGHUP = reload.
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()

	// SIGHUP handler — always on, no flag needed.
	go func() {
		for range hupCh {
			slog.Info("SIGHUP received, reloading config", "path", *configPath)
			newCfg, err := config.Load(*configPath)
			if err != nil {
				slog.Error("reload failed, keeping previous config", "error", err)
				continue
			}
			reload(newCfg)
		}
	}()

	// Optional file-watch reload (opt-in via -watch).
	if *watchFlag {
		go config.Watch(watchCtx, *configPath, *watchInterval,
			func(c *config.Config) error {
				reload(c)
				return nil
			},
			func(err error) {
				slog.Error("config watch reload failed, keeping previous config", "error", err)
			},
		)
	}

	go func() {
		slog.Info("mcpx gateway starting",
			"version", version,
			"listen", cfg.Listen,
			"servers", len(cfg.Servers),
			"auth", cfg.Auth != nil && cfg.Auth.Enabled,
			"rate_limit", cfg.RateLimit != nil && cfg.RateLimit.Enabled,
			"audit", cfg.Audit != nil && cfg.Audit.Enabled,
			"watch", *watchFlag,
		)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-shutdownCh
	slog.Info("shutting down gracefully...")
	stopWatch()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}

	sm.CloseAll()

	// Flush any buffered spans before exit (no-op when tracing is disabled).
	if err := traceShutdown(ctx); err != nil {
		slog.Warn("failed to flush traces", "error", err)
	}

	auditMu.Lock()
	if currentAudit != nil {
		if err := currentAudit.Close(); err != nil {
			slog.Warn("failed to close audit logger", "error", err)
		}
	}
	auditMu.Unlock()

	slog.Info("mcpx stopped")
}

// buildHandler constructs the full mux (MCP routes + health + metrics +
// servers listing) wrapped in the middleware chain derived from cfg.
// It is called once at startup and again on every hot-reload.
//
// The metrics collector is passed in so that counters survive reloads.
// The returned audit logger is owned by the caller, which must Close it
// when the handler is retired (reload swap or shutdown).
func buildHandler(cfg *config.Config, mc *metrics.Collector, ts *integrity.Store, bm *breaker.Manager, sm *stdio.Manager, cs *cache.Store) (http.Handler, *audit.Logger) {
	mc.SetServersRegistered(int64(len(cfg.Servers)))

	// Build health checker with server info
	healthServers := make([]health.ServerInfo, 0, len(cfg.Servers))
	for _, srv := range cfg.Servers {
		hs := health.ServerInfo{
			Name: srv.Name,
			URL:  srv.URL,
		}
		if srv.Transport == "stdio" {
			// No URL to poke; the child process reports its own state.
			hs.URL = "stdio:" + srv.Command
			hs.Probe = sm.Ensure(srv.Name, stdio.FromServerConfig(srv)).Probe
		} else if t, err := proxy.BackendTransport(srv); err == nil && t != nil {
			// Probe with the backend's own TLS settings; a TLS error here
			// also fails proxy.New below, which reports it.
			hs.Transport = t
		}
		if srv.Policy != nil {
			hs.Policy = &health.PolicySummary{
				ReadOnly:   srv.Policy.ReadOnly,
				AllowTools: srv.Policy.AllowTools,
				DenyTools:  srv.Policy.DenyTools,
			}
		}
		healthServers = append(healthServers, hs)
	}
	checker := health.NewChecker(healthServers, version)

	// Policy enforcement and audit logging live inside the gateway: they
	// need the parsed MCP message (server, method, tool), which the proxy
	// already extracts when routing. The remaining concerns (auth, rate
	// limiting, metrics, CORS) are HTTP-level and wrap the gateway.
	pe := policy.New(cfg.Servers, cfg.Clients)

	auditCfg := config.AuditConfig{}
	if cfg.Audit != nil {
		auditCfg = *cfg.Audit
	}
	al, err := audit.New(auditCfg)
	if err != nil {
		slog.Error("failed to initialize audit logger, continuing without audit", "error", err)
		al, _ = audit.New(config.AuditConfig{})
	}

	gw, err := proxy.New(cfg, pe, al, ts, bm, sm, mc, cs)
	if err != nil {
		slog.Error("failed to build gateway, serving 503 on /mcp/", "error", err)
	}

	// Assemble middleware chain (outermost first): CORS -> Metrics -> Auth -> Rate Limit -> Gateway.
	var handler http.Handler
	if gw != nil {
		handler = gw
	} else {
		handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httperr.Write(w, http.StatusServiceUnavailable, httperr.CodeMisconfigured, "gateway misconfigured")
		})
	}

	if cfg.RateLimit != nil && cfg.RateLimit.Enabled {
		handler = ratelimit.New(*cfg.RateLimit).Middleware()(handler)
	}

	if cfg.Auth != nil && cfg.Auth.Enabled {
		handler = auth.Middleware(*cfg.Auth)(handler)
	}

	// Tracing wraps just outside auth so the root span covers auth, rate
	// limiting, and the gateway. No-op when tracing is disabled.
	if cfg.Tracing != nil && cfg.Tracing.Enabled {
		handler = tracing.Middleware(handler)
	}

	handler = metricsMiddleware(mc, handler)

	if cfg.CORS != nil && cfg.CORS.Enabled {
		corsCfg := cors.Config{
			AllowedOrigins: cfg.CORS.AllowedOrigins,
			AllowedMethods: cfg.CORS.AllowedMethods,
			AllowedHeaders: cfg.CORS.AllowedHeaders,
			MaxAge:         cfg.CORS.MaxAge,
		}
		handler = cors.Middleware(corsCfg, handler)
	} else {
		handler = cors.Middleware(cors.DefaultConfig(), handler)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp/", handler)
	mux.HandleFunc("/health", checker.Handler())
	mux.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		serversHandler(w, r, cfg)
	})
	mux.HandleFunc("/metrics", mc.Handler())

	// When acting as an OAuth 2.1 resource server, publish RFC 9728 Protected
	// Resource Metadata so clients can discover the authorization server.
	if cfg.Auth != nil && cfg.Auth.Enabled && cfg.Auth.Type == "oauth" && cfg.Auth.OAuth != nil {
		mux.HandleFunc(auth.MetadataPath, auth.ProtectedResourceMetadataHandler(*cfg.Auth.OAuth))
	}

	return middleware.RequestID(mux), al
}

// reloadableHandler is an http.Handler that forwards every request to
// an atomically-swappable inner handler. New requests see the new
// handler the instant swap() returns; in-flight requests finish against
// whichever handler they started with.
type reloadableHandler struct {
	current atomic.Pointer[http.Handler]
}

func newReloadableHandler(h http.Handler) *reloadableHandler {
	r := &reloadableHandler{}
	r.current.Store(&h)
	return r
}

func (r *reloadableHandler) swap(h http.Handler) {
	r.current.Store(&h)
}

func (r *reloadableHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := *r.current.Load()
	h.ServeHTTP(w, req)
}

// metricsMiddleware wraps a handler to track request count, latency, and active connections.
func metricsMiddleware(mc *metrics.Collector, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mc.IncrActiveConnections()
		defer mc.DecrActiveConnections()

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		server := extractServerName(r.URL.Path)
		method := r.Header.Get("X-MCP-Method")
		if method == "" {
			method = r.Method
		}

		mc.RecordRequest(server, method, rw.statusCode, time.Since(start))

		// Auth and rate-limit middleware are the only sources of these status
		// codes in the chain, so the response status tells us which fired.
		switch rw.statusCode {
		case http.StatusUnauthorized:
			mc.RecordAuthFailure()
		case http.StatusTooManyRequests:
			mc.RecordRateLimitHit()
		}
	})
}

// responseWriter captures the status code for metrics. It stays
// streaming-transparent: Flush delegates so SSE events reach the client
// immediately, and Unwrap lets http.ResponseController (used by the
// gateway to lift write deadlines for streams) reach the real writer.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriter) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

// extractServerName extracts the server name from /mcp/{server}/...
func extractServerName(path string) string {
	if len(path) < 5 {
		return "unknown"
	}
	rest := path[5:] // strip "/mcp/"
	for i, c := range rest {
		if c == '/' {
			return rest[:i]
		}
	}
	return rest
}

// serversHandler returns the list of registered backend servers.
func serversHandler(w http.ResponseWriter, _ *http.Request, cfg *config.Config) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"servers":[`))
	for i, srv := range cfg.Servers {
		if i > 0 {
			w.Write([]byte(","))
		}
		url := srv.URL
		if srv.Transport == "stdio" {
			url = "stdio:" + srv.Command
		}
		fmt.Fprintf(w, `{"name":%q,"url":%q}`, srv.Name, url)
	}
	w.Write([]byte("]}"))
}
