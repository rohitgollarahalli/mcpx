# mcpx Roadmap

## Vision

Make mcpx the simplest, fastest way to secure MCP servers in production. One binary, one config file, zero dependencies.

## Design Principles

1. **Zero dependencies at runtime** — single static binary, no sidecars, no databases
2. **One config file** — everything in `mcpx.yaml`, no scattered env vars
3. **Protocol-aware** — the gateway understands MCP, not just HTTP
4. **Secure by default** — auth on, audit on, deny-by-default policies

## Phase 1: Foundation ✅

- [x] HTTP reverse proxy with MCP message inspection
- [x] Bearer token and API key authentication
- [x] Tool-level allow/deny policy engine
- [x] Global and per-tool rate limiting (token bucket)
- [x] Structured audit logging (slog + JSON)
- [x] Multi-server routing (`/mcp/{server}`)
- [x] Health check endpoint (`/health`)
- [x] Server listing endpoint (`/servers`)
- [x] Docker support
- [x] CI pipeline (build + test + lint)

## Phase 2: Observability & Browser Support ✅

- [x] Prometheus metrics endpoint (`/metrics`) — request counts, latencies, tool usage, policy decisions
- [x] Deep health checks — probe each backend, report individual status and latency
- [x] CORS middleware — support browser-based MCP clients
- [x] Request ID propagation — trace requests across gateway and backends
- [x] Structured error responses — consistent JSON error format with error codes

## Phase 3: Transport Support

- [x] Server-Sent Events (SSE) proxy — streaming MCP transport (Streamable HTTP pass-through)
- [ ] WebSocket proxy — bidirectional streaming MCP transport
- [x] Stdio transport — spawn and manage local MCP servers as child processes
- [x] Transport auto-detection — streaming responses detected per response via Content-Type

## Phase 4: Enterprise Security

- [x] OAuth 2.1 authentication (aligned with MCP authorization spec)
- [x] JWT validation with JWKS endpoint support (RS256)
- [x] Audience validation (RFC 8707) + RFC 9728 Protected Resource Metadata
- [x] Tool integrity pinning — full-schema hashing detects rug-pull/mutation (CVE-2025-54136)
- [x] Tool-list filtering — hide policy-denied tools from `tools/list`
- [x] mTLS between gateway and backends (`servers[].tls`)
- [x] Per-client policies (multi-tenant access control)
- [x] Argument-level policy rules (e.g., allow `read_file` only for specific paths)
- [x] Secret injection — inject backend credentials (`servers[].headers`, `${env:}` / `${file:}` references); vault providers to follow
- [x] ES256/EdDSA token signature support (plus ES384/ES512, PS*, RS384/RS512)

## Phase 5: Operational Excellence

- [x] OpenTelemetry tracing integration (OTLP/HTTP spans, W3C context propagation)
- [ ] Prometheus metrics with Grafana dashboard template
- [x] Hot config reload (SIGHUP or watch mode)
- [x] Graceful shutdown with connection draining
- [x] Circuit breaker per backend
- [x] Request/response caching for idempotent tools (bounded LRU + TTL, per-tool opt-in, single-flight)
- [ ] Admin API for runtime config changes

## Phase 6: Ecosystem

- [ ] Plugin system — custom middleware in Go or WASM
- [ ] Web dashboard — real-time request monitoring
- [ ] CLI companion — `mcpx status`, `mcpx logs`, `mcpx test`
- [ ] Terraform provider for declarative config
- [ ] Helm chart for Kubernetes deployments
- [ ] Published to Homebrew, apt, and AUR

## How mcpx is Different

| | mcpx | Microsoft MCP Gateway | Docker MCP Gateway | Kong AI MCP Proxy |
|---|---|---|---|---|
| Setup | Single binary + YAML | Kubernetes cluster | Docker Desktop | Kong Gateway + plugin |
| Dependencies | Single static binary | K8s, Azure | Docker | Kong, Lua |
| Config | One file | CRDs + Helm | UI + profiles | kong.yaml + plugins |
| Overhead | ~10MB binary | Cluster | Docker daemon | Full API gateway |
| Target | Individual devs, small teams | Enterprise on Azure | Docker users | Existing Kong users |
| License | MIT | MIT | Apache 2.0 | Apache 2.0 |

mcpx is for developers who want to add security to their MCP servers in 5 minutes, not 5 days.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pick any unchecked item above and open an issue to claim it.
