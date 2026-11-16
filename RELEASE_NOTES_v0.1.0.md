# mcpx v0.1.0

The first public release of **mcpx**, a lightweight security gateway for Model
Context Protocol (MCP) servers. It sits between your MCP clients and servers and
adds auth, rate limiting, tool-level access control, and audit logging. No
Kubernetes, no Docker Desktop: one static binary, one YAML file.

## Highlights

- Authentication: bearer, API key, and OAuth 2.1 (audience binding, RFC 9728 metadata)
- Tool-, argument-, and client-level access policies
- Tool-integrity pinning to detect rug-pull tool mutation (CVE-2025-54136)
- Stdio transport for local MCP servers, plus SSE pass-through
- Per-backend circuit breaker, rate limiting, Prometheus metrics, deep health checks

## Install

```bash
go install github.com/rohitgollarahalli/mcpx/cmd/mcpx@v0.1.0
```

Or download a prebuilt binary for your platform from the assets below.

## Try it in 60 seconds

```bash
docker compose up --build
# or run the mock server + gateway locally; see the README quick start.
```

See the [README](https://github.com/rohitgollarahalli/mcpx#readme) for full configuration
and the [threat model](https://github.com/rohitgollarahalli/mcpx/blob/main/SECURITY.md).
