# Contributing to mcpx

Thanks for your interest in mcpx. This document covers how to set up, develop, test, and submit contributions.

## Getting Started

### Prerequisites

- Go 1.22 or later
- Git

### Setup

```bash
git clone https://github.com/rohitgollarahalli/mcpx
cd mcpx
go build -o mcpx ./cmd/mcpx
```

### Running Tests

```bash
go test ./...
```

### Linting

```bash
go vet ./...
# If you have golangci-lint installed:
golangci-lint run
```

## Project Structure

```
cmd/mcpx/main.go           CLI entrypoint and middleware chain
internal/
├── config/config.go        YAML config loading and validation
├── mcp/message.go          MCP JSON-RPC message types and parsing
├── proxy/proxy.go          Core reverse proxy with request inspection
├── auth/auth.go            Bearer token and API key middleware
├── ratelimit/ratelimit.go  Global and per-tool rate limiting
├── audit/audit.go          Structured audit logging
├── policy/policy.go        Tool-level allow/deny policy engine
├── metrics/metrics.go      Prometheus-compatible metrics
├── health/health.go        Deep health checking with backend probes
└── cors/cors.go            CORS middleware for browser clients
```

## How to Contribute

### Reporting Bugs

Open an issue with:
- What you did
- What you expected
- What happened instead
- Your Go version and OS

### Suggesting Features

Open an issue with the `enhancement` label. Describe the use case, not just the solution.

### Submitting Code

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Write your code and tests
4. Run `go test ./...` and `go vet ./...`
5. Commit with a clear message: `feat: add websocket transport support`
6. Push and open a PR against `main`

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding tests
- `refactor:` code change that neither fixes a bug nor adds a feature
- `chore:` build process or tooling changes

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Every exported function needs a doc comment
- Every new package needs a package-level doc comment
- Tests go in `_test.go` files in the same package
- No external dependencies without discussion — mcpx stays lightweight

### What We're Looking For

Check the [ROADMAP.md](ROADMAP.md) for planned work. High-impact areas:

- **Transport support**: SSE, WebSocket, stdio proxying
- **Security**: OAuth 2.1, JWT validation, mTLS
- **Observability**: OpenTelemetry integration
- **Tests**: Integration tests, edge cases, error paths
- **Documentation**: Architecture docs, usage examples, tutorials

## Code of Conduct

Be respectful, be constructive, be kind. We're all here to build something useful.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
