# mcpx

**Secure your MCP servers in 5 minutes. One binary. One config file. No infrastructure to run.**

[![CI](https://github.com/rohitgs28/mcpx/workflows/CI/badge.svg)](https://github.com/rohitgs28/mcpx/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/rohitgs28/mcpx)](https://goreportcard.com/report/github.com/rohitgs28/mcpx)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Built with Go](https://img.shields.io/badge/built_with-Go-00ADD8.svg)](https://go.dev)

---

## What is mcpx, in plain English?

[MCP](https://modelcontextprotocol.io/) servers give AI assistants **real tools** — the ability to read your files, query your database, call your APIs. That is powerful, but out of the box there is a catch: **any client that connects can call any tool, with any input, as often as it likes.** No login, no limits, no record of what happened.

**mcpx is the checkpoint you put in front of them** — think of it as a bouncer with a guest list, standing between your AI assistants and your tools:

- ✅ **Checks ID** — only clients with a valid token or key get in *(auth)*
- 🚫 **Blocks the dangerous stuff** — you decide which tools each client may call, and with what arguments *(policy)*
- ⏱️ **Stops abuse** — caps how many calls come through per second *(rate limiting)*
- 📝 **Keeps a logbook** — records who called what, when, and whether it was allowed *(audit, metrics, tracing)*
- 🕵️ **Catches tampering** — flags when a server secretly rewrites a tool you already trusted *(integrity pinning)*

It is **one small binary and one YAML file** — no Kubernetes, no Docker Desktop, no gateway cluster. You point your AI clients at mcpx instead of directly at your servers, and your servers do not change at all.

**Who is it for?** Developers and teams running MCP servers behind Claude, Cursor, VS Code, or custom agents who want a lock on the door before going to production.

```
MCP Client (Claude, Cursor, etc.)
      │
      ▼
  ┌────────┐
  │  mcpx  │  auth · rate limit · policy · audit · metrics · tracing · tool integrity
  └────────┘
      │
  ┌───┴────────┐
  ▼            ▼
Server A    Server B
(filesystem)  (database)
```

## Why mcpx?

MCP servers are powerful but have **no built-in access control**. Any connected client can call any tool with any arguments. In production, you need auth, rate limiting, policies, and audit trails.

Most MCP gateway solutions require Kubernetes clusters, Docker Desktop, or full API gateway stacks. **mcpx doesn't.** It's a single binary with a single YAML config file.

| | mcpx | Microsoft MCP Gateway | Docker MCP Gateway | Kong AI MCP Proxy |
|---|---|---|---|---|
| **Setup time** | 5 minutes | Hours (K8s required) | Docker Desktop | Kong cluster |
| **Dependencies** | Single static binary | Kubernetes, Azure | Docker | Kong, Lua runtime |
| **Config** | One YAML file | CRDs + Helm charts | UI + profiles | kong.yaml + plugins |
| **Binary size** | ~10 MB | Cluster | Docker image | Full gateway |
| **Target users** | Devs & small teams | Enterprise Azure | Docker users | Existing Kong users |
| **Prometheus metrics** | ✅ Built-in | Via adapter | Via Docker | Via plugin |
| **Deep health checks** | ✅ Per-backend | ❌ | ❌ | Via plugin |
| **License** | MIT | MIT | Apache 2.0 | Apache 2.0 |

## Quick Start

```bash
# Install from source
git clone https://github.com/rohitgs28/mcpx
cd mcpx
go build -o mcpx ./cmd/mcpx

# Or install directly
go install github.com/rohitgs28/mcpx/cmd/mcpx@latest

# Run with config
./mcpx -c mcpx.yaml

# Hot-reload the config file on every change
./mcpx -c mcpx.yaml -watch
```

Send `SIGHUP` to force a reload at any time (`kill -HUP $(pidof mcpx)`). Reloads rebuild the handler chain atomically: in-flight requests finish against the old config, new ones see the new config. Invalid configs are rejected and the previous config keeps running.

```bash
# Or use Docker
docker build -t mcpx .
docker run -p 8080:8080 -v $(pwd)/mcpx.yaml:/etc/mcpx/mcpx.yaml mcpx
```

The gateway starts on `:8080`. Point your MCP clients to `http://localhost:8080/mcp/{server_name}` instead of directly to your backend servers.

## Try it in 60 seconds

The repo ships a tiny mock MCP server so you can see the gateway work with no setup.

```bash
# One command (Docker):
docker compose up --build

# …or run locally in two terminals:
go run ./examples/mock-mcp                  # terminal 1 - mock server on :3001
go run ./cmd/mcpx -c examples/demo.yaml     # terminal 2 - gateway on :8080
```

Then list the tools through the gateway:

```bash
curl -s localhost:8080/mcp/demo \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools[].name'
# "echo"
# "read_file"          ← dangerous_delete is filtered out by policy

curl -s localhost:8080/mcp/demo \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dangerous_delete"}}'
# {"jsonrpc":"2.0",...,"error":{"code":-32600,"message":"tool \"dangerous_delete\" is denied ..."}}  (HTTP 403)
```

The mock advertises `echo`, `read_file`, and `dangerous_delete`; the demo policy denies the last one, so it's hidden from `tools/list` and blocked on call.

## Configuration

```yaml
listen: ":8080"

servers:
  - name: filesystem
    url: http://localhost:3001
    policy:
      allow_tools:
        - read_file
        - list_directory
      deny_tools:
        - write_file
        - delete_file

  - name: database
    url: http://localhost:3002
    policy:
      read_only: true  # blocks tools/call, allows tools/list

  - name: github            # local stdio server, spawned by the gateway
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_..."

auth:
  enabled: true
  type: bearer
  token: "your-secret-token"

audit:
  enabled: true
  output: stdout

rate_limit:
  enabled: true
  rps: 100
  burst: 20
  per_tool: true
  tool_rps: 10
  tool_burst: 5

inspection:
  tool_integrity: enforce   # off | warn | enforce - pin tool schemas, block mutation
  filter_tools_list: true   # hide policy-denied tools from tools/list responses

tracing:
  enabled: true
  exporter: otlp            # otlp (OTLP/HTTP, default) | stdout (debug)
  endpoint: localhost:4318  # OTLP/HTTP collector (required for exporter: otlp)
  sample_ratio: 1.0         # 0.0-1.0, fraction of requests traced (default 1.0)

cache:
  enabled: true             # per-tool opt-in under servers[].cache.tools
  max_entries: 1000
  default_ttl: 60s
```

## Features

### 🔐 Authentication

Bearer token, API key, and **OAuth 2.1** authentication. Requests without valid credentials are rejected before reaching any backend.

In `oauth` mode mcpx acts as an OAuth 2.1 protected resource server aligned with the [MCP authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization): it verifies JWT (RS256) signatures against the authorization server's JWKS and enforces **audience binding** (RFC 8707) - a token is rejected unless its `aud` claim names this gateway, which is the spec's defense against token-passthrough and confused-deputy attacks. It also publishes [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) Protected Resource Metadata at `/.well-known/oauth-protected-resource` and advertises it via `WWW-Authenticate` on `401` responses.

```yaml
auth:
  enabled: true
  type: oauth
  oauth:
    resource: "https://gateway.example.com/mcp"   # expected token audience
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"
    issuer: "https://auth.example.com"             # optional
    authorization_servers:
      - "https://auth.example.com"
```

The credential a client presents to mcpx (the `Authorization` header, or the API-key header) is stripped once it is verified and is **never forwarded to a backend**. Backends that need their own credentials get them through secret injection, described next.

### 🔑 Secret Injection

Keep backend credentials in the gateway so clients never see them. `servers[].headers` is set on every request forwarded to that backend and replaces any client header with the same name. Values can reference secrets instead of holding them in plain text:

| Reference | Resolves to |
|---|---|
| `${env:NAME}` | the environment variable `NAME` |
| `${file:PATH}` | the contents of `PATH`, with trailing newlines trimmed (works with Docker and Kubernetes secret mounts) |
| `$${` | a literal `${` |

```yaml
servers:
  - name: github
    url: https://api.githubcopilot.com/mcp/
    headers:
      Authorization: "Bearer ${file:/run/secrets/github_token}"
      X-Tenant: acme
  - name: local
    transport: stdio
    command: npx
    args: ["-y", "some-mcp-server"]
    env:
      API_KEY: ${env:SOME_API_KEY}     # stdio servers get secrets via env

auth:
  enabled: true
  type: bearer
  token: ${env:MCPX_GATEWAY_TOKEN}     # gateway tokens can be references too
```

References work in `servers[].headers`, `servers[].env`, `auth.token`, `auth.clients[].token`, and `tracing.headers`. Backend URLs are left as written because they show up in logs and on `/servers`. Resolution **fails closed**: an unset variable, an unreadable file, or an empty value stops startup (or rejects the reload). Error messages name the reference and never the value. References are resolved again on every reload. To rotate a credential, update the secret file and send `SIGHUP`; `-watch` only watches the config file itself. Stdio children restart automatically when their resolved env changes.

### 🔒 Backend TLS and mTLS

`servers[].tls` sets how mcpx connects to an `https` backend. It can trust a private CA, present a client certificate for **mutual TLS**, override the verified server name, and require a minimum TLS version. Health probes use the same settings.

```yaml
servers:
  - name: internal-tools
    url: https://10.0.4.12:8443/mcp
    tls:
      ca_file: /etc/mcpx/internal-ca.pem     # replaces system roots for this backend
      cert_file: /etc/mcpx/gateway.pem       # client certificate (mTLS)
      key_file: /etc/mcpx/gateway.key
      server_name: tools.internal            # SNI and verification name (default: the url host)
      min_version: "1.3"                     # "1.2" (default) or "1.3"
```

Certificates and keys are loaded and checked when the config loads. A missing file, a CA file with no certificates, or a key that doesn't match its certificate stops startup or rejects the reload, instead of failing on the first request. Files are read again on every reload, so to rotate a certificate, replace the files and send `SIGHUP`. `insecure_skip_verify: true` turns verification off and is meant for local testing only.

### 🛡️ Tool-Level Access Control

Define allow and deny lists per server. Use `read_only: true` to let clients discover tools without calling them. Deny lists take precedence.

```yaml
policy:
  allow_tools: [read_file, list_directory]
  deny_tools: [write_file, delete_file]
```

With `inspection.filter_tools_list: true`, denied tools are also stripped from `tools/list` responses, so the model never even sees a tool it cannot call. Filtering is per client when auth provides an identity.

### 🎯 Argument-Level Rules

Constrain *what* a tool may be called with, not just whether it may be called. Constraints (`equals`, `one_of`, `prefix`, `suffix`, `regex`, `required`) are ANDed per argument and evaluated deterministically - violations return a `403` naming the violated rule.

```yaml
policy:
  tool_rules:
    read_file:
      args:
        path: { prefix: "/data/" }
    query:
      args:
        sql: { regex: "^SELECT ", required: true }
```

Scalar values compare as strings (bools and numbers normalized); a rule that targets a non-scalar value fails closed. `prefix` is a literal check - no path canonicalization.

### 👥 Per-Client Policies

Give each caller an identity and a policy. Bearer/API-key auth accepts multiple named credentials; OAuth derives the identity from a JWT claim (`identity_claim`, default `sub`). The effective decision is the **intersection** of the server policy and the client's override - both must allow a call, so overrides can only restrict, never widen, the baseline.

```yaml
auth:
  enabled: true
  type: bearer
  clients:
    - { name: ci-bot,  token: "ci-secret" }
    - { name: analyst, token: "analyst-secret" }

clients:
  ci-bot:
    servers:
      filesystem:
        allow_tools: [read_file]
```

Each client sees its own filtered `tools/list`, audit entries carry the client name, and the tool-call metric gains a `client` label.

### 📡 Streaming (SSE) Pass-Through

MCP Streamable HTTP responses (`Content-Type: text/event-stream`) stream through the gateway unbuffered - events reach the client as the backend emits them, and streams may outlive the server's write timeout. Request-side auth, policy, and rate limiting apply as usual. To keep the `tools/list` security guarantee, when inspection is enabled the gateway pins `tools/list` requests to JSON responses (rewrites `Accept`), so integrity pinning and list filtering cannot be bypassed by a streaming response.

### 🖥️ Stdio Transport (Local MCP Servers)

Most real-world MCP servers are local processes spoken to over stdin/stdout (`npx ...`, `uvx ...`). With `transport: stdio` the gateway spawns the server itself and bridges HTTP JSON-RPC onto it - so auth, policies, rate limiting, audit logging, tool integrity pinning, and list filtering all apply to local servers exactly as they do to HTTP backends.

```yaml
servers:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    env:                    # extra environment for the child
      LOG_LEVEL: info
    workdir: /data          # optional working directory
    request_timeout: 30s    # per-request reply deadline (default 30s)
    policy:
      allow_tools: [read_file, list_directory]
```

One shared child process serves all gateway clients: it is spawned lazily on first request, respawned (with backoff) if it crashes, and retired when its config entry changes or disappears. Request IDs are rewritten internally so concurrent clients never collide, and the MCP `initialize` handshake is cached - later clients get the cached result, and the handshake is replayed automatically after a respawn so existing sessions keep working. Children survive config hot-reloads that leave their entry untouched, and a graceful gateway shutdown closes their stdin (killing only those that linger).

Notifications return `202 Accepted` (mirroring the Streamable HTTP spec). Server-initiated messages (sampling, log notifications) are dropped with a log line - there is no single addressable client on a shared gateway.

### ⚡ Circuit Breaker

After a configurable number of consecutive backend failures (transport errors or `5xx`), the gateway fails fast with `503` instead of queueing requests against a dead upstream. After a cooldown, limited probe requests test recovery. State survives config hot-reloads.

```yaml
circuit_breaker:
  enabled: true
  failure_threshold: 5
  cooldown: 30s
  half_open_max: 1
```

### 💾 Response Caching

Repeat calls to expensive, idempotent tools can be served from memory instead of the backend. Caching is **deny-by-default**: enabling the section caches nothing until you name a tool.

```yaml
cache:
  enabled: true
  max_entries: 1000        # bounded LRU
  default_ttl: 60s         # used by tools with no ttl of their own
  max_body_bytes: 262144   # 256 KiB; larger responses pass through uncached
  purge_on_reload: false   # true empties the cache on every config reload

servers:
  - name: docs
    url: http://localhost:3004
    cache:
      tools:
        search_docs: { ttl: 5m }
        get_page: {}         # inherits default_ttl
```

Every response carries `X-Mcpx-Cache: hit|miss`, and hits also carry an `Age` header. Cached entries survive config hot-reloads, and `mcpx_cache_lookups_total` breaks hits and misses down per server and tool.

**What is never cached** - the cache is designed so a wrong answer is impossible rather than unlikely:

- **Anything a client is not allowed to call.** Policy is evaluated *before* the cache, so a newly-denied tool can never be answered from a warm entry.
- **Failures.** JSON-RPC errors, MCP results with `isError: true`, and non-`200` responses are skipped - a transient blip must not be pinned for the whole TTL.
- **Streams.** An SSE or event-stream response passes straight through to the client, unbuffered.
- **Oversized bodies.** Responses past `max_body_bytes` are streamed through, so one huge result cannot evict the whole cache.
- **Tools you didn't name.** No wildcards, no heuristics about which tools "look" read-only.

Entries are keyed by **server + tool + client identity + canonical arguments**, so two clients with different per-client policies never share one, and argument key order doesn't split entries. Cached bodies are re-pointed at the current request's JSON-RPC `id` before being served, so a client always sees a reply to the request it actually sent.

Concurrent identical misses are collapsed by **single-flight**: the first caller fetches, the rest wait and share its result rather than stampeding the backend. A waiter whose client disconnects stops waiting instead of outliving its request.

Because a hit costs the backend nothing, the cache sits *in front of* the circuit breaker: cached tools keep answering while a backend is down.

### 🔎 Tool Integrity Pinning

mcpx hashes the **full schema** of every tool (name, description, and input schema) the first time a backend advertises it, then flags any later change. This deterministically detects **rug-pull tool mutation** ([CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136)), cross-server shadowing, and full-schema poisoning - attacks where a server silently rewrites a tool the client already approved.

```yaml
inspection:
  tool_integrity: enforce   # off | warn | enforce
```

- **`warn`** - log a violation to the audit trail, pass the tool through.
- **`enforce`** - log it and drop the mutated tool from `tools/list` so clients can't invoke it.

The baseline lives in memory and survives config hot-reloads. Hashing is canonical (key-order independent), so legitimate re-serialization doesn't trigger false positives.

> **Scope note:** this defends *static* tool-schema integrity, which is deterministically checkable. It does **not** attempt regex/LLM scanning of tool descriptions or runtime tool *output* for prompt injection - those are bypassable and better handled by least-privilege scoping, so mcpx deliberately doesn't ship security theater there.

### ⏱️ Rate Limiting

Global rate limiting protects all backends. Per-tool rate limiting prevents abuse of expensive operations. Token bucket algorithm with configurable burst.

### 📊 Prometheus Metrics

Built-in `/metrics` endpoint exposes request counts, latencies, tool usage, policy decisions, auth failures, and rate limit hits. Plug into Grafana, Datadog, or any Prometheus-compatible system.

```
mcpx_requests_total{server="filesystem",method="tools/call",status_code="2xx"} 42
mcpx_tool_calls_total{server="filesystem",tool="read_file",decision="allow",client="ci-bot"} 38
mcpx_request_duration_ms_bucket{server="filesystem",le="50"} 35
mcpx_auth_failures_total 3
mcpx_rate_limit_hits_total 1
mcpx_breaker_trips_total 1
mcpx_breaker_state{server="database"} 1
mcpx_cache_lookups_total{server="docs",tool="search_docs",result="hit"} 17
mcpx_cache_entries 24
```

### 🔭 Distributed Tracing (OpenTelemetry)

Emit one OpenTelemetry span per request, exported over **OTLP/HTTP** to Jaeger, Tempo, Grafana, or any OTLP collector. Each request produces a root `mcpx.request` span with child spans for policy evaluation (`mcpx.policy`) and the backend call (`mcpx.proxy`), tagged with the server, MCP method, tool, client, and allow/deny decision. Inbound W3C `traceparent` headers are honored and trace context is propagated to instrumented HTTP backends, so a single trace spans the caller, the gateway, and the upstream server.

```yaml
tracing:
  enabled: true
  exporter: otlp            # otlp (OTLP/HTTP, default) | stdout (debug)
  endpoint: localhost:4318  # OTLP/HTTP collector
  service_name: mcpx        # optional (default "mcpx")
  sample_ratio: 1.0         # optional, 0.0-1.0 (default 1.0)
  insecure: true            # optional, plain HTTP; set false for TLS
  headers:                  # optional, e.g. auth for a hosted collector
    authorization: "Bearer ..."
```

Tracing is strictly opt-in: when disabled (the default) it is a no-op with negligible overhead, and no exporter connection is made. It uses the OTLP/HTTP exporter (not gRPC) to keep the binary lean. Settings are read once at startup, so changing them needs a restart.

### 🏥 Deep Health Checks

`/health` probes each backend server and reports individual status, latency, and policy configuration. Returns `degraded` when some backends are down, `unhealthy` when all are down.

```json
{
  "status": "degraded",
  "servers": [
    {"name": "filesystem", "healthy": true, "latency_ms": 2.1},
    {"name": "database", "healthy": false, "error": "unreachable: connection refused"}
  ]
}
```

### 📝 Audit Logging

Every request is logged with server name, method, tool name, authenticated client, client IP, policy decision, and latency. JSON output for your existing log infrastructure. Every response carries an `X-Request-ID` for correlation, and all gateway-generated errors share a consistent JSON envelope (`{"error":{"code":...,"message":...}}`, or a JSON-RPC error when the request carried a parseable message).

### 🌐 CORS Support

Browser-based MCP clients can connect through the gateway with configurable CORS headers.

### 🔀 Multi-Server Routing

Register multiple MCP servers behind a single gateway. Clients address them by name: `/mcp/filesystem`, `/mcp/database`, `/mcp/github`.

## API

| Endpoint | Description |
|---|---|
| `POST /mcp/{server}` | Proxy MCP JSON-RPC requests to the named backend |
| `GET /health` | Deep health check with per-backend status |
| `GET /servers` | List all registered backend servers |
| `GET /metrics` | Prometheus metrics |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata (only when `auth.type: oauth`) |

## Architecture

```
cmd/mcpx/main.go              CLI entrypoint, middleware chain assembly
internal/
├── config/config.go           YAML config loading and validation
├── mcp/message.go             MCP JSON-RPC message types and parsing
├── proxy/proxy.go             Core reverse proxy with request inspection
├── auth/auth.go               Bearer, API key, and OAuth 2.1 middleware
├── auth/oauth.go              JWT/JWKS validation + RFC 9728 metadata
├── ratelimit/ratelimit.go     Global and per-tool rate limiting
├── audit/audit.go             Structured audit logging (slog + JSON)
├── policy/policy.go           Tool/argument/client policy engine
├── integrity/integrity.go     Full-schema tool pinning (rug-pull detection)
├── breaker/breaker.go         Per-backend circuit breaker
├── cache/cache.go             Response cache: bounded LRU + TTL + single-flight
├── httperr/httperr.go         Consistent JSON error envelopes
├── middleware/requestid.go    X-Request-ID propagation
├── metrics/metrics.go         Prometheus-compatible metrics (no deps)
├── tracing/tracing.go         OpenTelemetry OTLP tracing + root-span middleware
├── health/health.go           Deep health checking with backend probes
└── cors/cors.go               CORS middleware for browser clients
```

**Middleware chain:** CORS → Metrics → Auth → Rate Limit → Gateway (Policy → Cache → Breaker → Proxy → Audit)

Every request is inspected at the MCP protocol level. The gateway parses JSON-RPC messages to extract the method and tool name, evaluates the policy before forwarding, and inspects `tools/list` responses for schema integrity and policy filtering on the way back.

## Security

mcpx is explicit about what it defends and what it doesn't. See **[SECURITY.md](SECURITY.md)** for the full threat model - which MCP attacks (rug-pulls, token passthrough, confused deputy, schema poisoning) it mitigates and how, plus the deliberate non-goals (it does **not** do bypassable regex/LLM prompt-injection scanning). Report vulnerabilities via [GitHub Security Advisories](https://github.com/rohitgs28/mcpx/security/advisories/new).

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan. Key upcoming work:

- [x] OAuth 2.1 authentication (audience validation + RFC 9728 metadata)
- [x] Full-schema tool integrity pinning (rug-pull detection)
- [x] Hot config reload (SIGHUP + watch)
- [x] SSE / Streamable HTTP pass-through
- [x] Argument-level and per-client policies
- [x] Per-backend circuit breaker
- [x] Stdio transport (spawn local MCP servers)
- [x] OpenTelemetry tracing (OTLP/HTTP spans, W3C context propagation)
- [x] Response caching for idempotent tools (LRU + TTL + single-flight)
- [x] Secret injection for backend credentials (env/file references; no token passthrough)
- [x] Backend mTLS (client certificates, private CA, server name override)
- [ ] WebSocket transport proxying
- [ ] Web dashboard
- [ ] Plugin system (Go + WASM)
- [ ] Helm chart

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

```bash
go test ./...       # run tests
go vet ./...        # lint
golangci-lint run   # extended lint
```

## License

MIT. See [LICENSE](LICENSE) for details.
