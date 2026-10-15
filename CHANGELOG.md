# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OAuth mode now verifies ECDSA (`ES256`, `ES384`, `ES512`), Ed25519
  (`EdDSA`), and RSA-PSS (`PS256`/`PS384`/`PS512`) tokens, as well as
  `RS384`/`RS512`, from EC and OKP keys in the JWKS. Before this, only RS256
  worked. Each key is bound to the algorithms its type and curve permit, and
  narrowed further by its JWK `alg` when one is set, so a token header cannot
  pick a different algorithm for a key. `auth.oauth.algorithms` optionally
  limits which algorithms are accepted. HMAC and `none` are never accepted.
  JWKS entries that are malformed or off-curve, encryption keys, and RSA keys
  under 2048 bits are skipped.

- Backend TLS and mutual TLS (`servers[].tls`): a private CA bundle
  (`ca_file`, which replaces the system roots for that backend), a client
  certificate (`cert_file`/`key_file`), `server_name` (SNI and verification
  name), `min_version` ("1.2" or "1.3"), and `insecure_skip_verify` for
  testing. Certificates are loaded and checked at config load and on every
  reload, so a bad file or mismatched key pair is rejected up front. Deep
  health probes use each backend's TLS settings.

- Secret injection for backend credentials. `servers[].headers` sets headers
  on every request forwarded to an HTTP/SSE backend, replacing any
  client-supplied header with the same name, so backend credentials never pass
  through or reach clients. Values (and `servers[].env`, `auth.token`,
  `auth.clients[].token`, `tracing.headers`) can use `${env:NAME}` and
  `${file:PATH}` secret references. These are resolved at load and on every
  reload (rotate with `SIGHUP`) and fail closed when unset, unreadable, or
  empty. Injected header names are validated: reserved and hop-by-hop headers
  are rejected, and values containing CR/LF/NUL are rejected.

### Security

- The credential a client presents to the gateway (`Authorization` for
  `bearer`/`oauth`, or the API-key header for `api_key`) is now stripped after
  authentication instead of being forwarded to backends. Before this change,
  every backend received the client's gateway token, which is the token
  passthrough the MCP authorization spec forbids. If a backend relied on that
  passthrough, configure its credential under `servers[].headers`. Nothing
  changes when gateway auth is disabled.

- Response caching for idempotent tools (`cache` section). A bounded in-memory
  LRU with per-tool TTLs serves repeat `tools/call` requests without touching
  the backend. Caching is opt-in per tool under `servers[].cache.tools`; entries
  are keyed by server, tool, client identity, and canonical arguments, so
  clients never share one. Errors, `isError` results, streamed responses, and
  bodies over `max_body_bytes` are never stored, and the cache is consulted only
  after policy evaluation. Concurrent identical misses are collapsed into a
  single backend call (single-flight). Responses carry `X-Mcpx-Cache: hit|miss`,
  hits carry `Age`, and `mcpx_cache_lookups_total` / `mcpx_cache_entries` /
  `mcpx_cache_evictions_total` are exported at `/metrics`.

## [0.1.0] - 2026-06-21

First public release. mcpx is a lightweight gateway proxy that sits between MCP
clients and MCP servers, adding security and observability without modifying the
backends. Single static binary, single YAML config.

### Added

- Reverse proxy for MCP JSON-RPC over HTTP, with multi-server routing (`/mcp/{server}`).
- Authentication: bearer token, API key, and OAuth 2.1 (JWT/JWKS validation,
  audience binding per RFC 8707, RFC 9728 protected-resource metadata).
- Tool-level access control: per-server allow/deny lists and `read_only` mode.
- Argument-level rules (`equals`, `one_of`, `prefix`, `suffix`, `regex`, `required`).
- Per-client policies with identity from auth, enforced as the intersection of
  server and client policy.
- Tool-integrity pinning: full-schema hashing to detect rug-pull tool mutation
  (CVE-2025-54136), with `off` / `warn` / `enforce` modes.
- `tools/list` filtering so clients never see tools they cannot call.
- Stdio transport: spawn and bridge local MCP servers (`npx`, `uvx`, ...).
- Streamable HTTP (SSE) pass-through.
- Per-backend circuit breaker.
- Global and per-tool rate limiting (token bucket).
- Prometheus metrics at `/metrics`.
- Deep health checks at `/health` with per-backend status.
- Structured JSON audit logging with `X-Request-ID` correlation.
- CORS support and hot config reload (SIGHUP + `-watch`).

[0.1.0]: https://github.com/rohitgs28/mcpx/releases/tag/v0.1.0
