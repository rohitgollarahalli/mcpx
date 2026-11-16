# Security Model

mcpx is a security gateway, so it should be explicit about **what it defends, how, and — just as importantly — what it does not**. This document maps the known MCP attack surface to mcpx's controls, with citations, and is honest about the limits of a deterministic proxy.

## Reporting a vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/rohitgollarahalli/mcpx/security/advisories/new) rather than a public issue. We aim to acknowledge within 72 hours.

## Design stance

mcpx's defensible niche is **deterministic identity, integrity, and policy enforcement** — checks that are exact, fast, and not themselves bypassable by clever wording. It deliberately does **not** try to detect prompt injection in natural-language tool descriptions or tool output with regexes or an LLM, because those are bypassable and create a false sense of safety. The MCP security literature is clear that runtime-output injection "must be addressed at the agent system level," not by a content-matching proxy ([CyberArk](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe), [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)).

## Threat coverage

| Attack | What it is | mcpx control | Coverage |
|---|---|---|---|
| **Rug-pull / tool mutation** | A server silently changes a tool's definition *after* the client approved it ([CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136)) | **Tool integrity pinning** — SHA-256 over each tool's *full* schema on first sighting; `warn` logs drift, `enforce` drops the mutated tool | ✅ Strong (deterministic) |
| **Full-schema poisoning (FSP)** | Malicious instructions hidden in parameter names, enums, or defaults — not just the description ([CyberArk](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)) | Pinning hashes the **entire** tool object, so any schema change is caught regardless of where it hides | ✅ Strong against *changes*; see limits below |
| **Cross-server shadowing** | A poisoned tool on one server alters behavior of a trusted tool on another ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) | Per-server pinning + tool-list filtering reduce the surface; a newly appearing/mutated tool is flagged | ⚠️ Partial |
| **Token passthrough** | The gateway forwards the client's token to an upstream that wasn't its intended audience | mcpx validates the token's **audience** and does not forward it; upstream credentials are separate | ✅ Strong |
| **Confused deputy** | A token issued for one party is accepted by another | **RFC 8707 audience binding** — a token is rejected unless its `aud` claim names this gateway | ✅ Strong |
| **Unauthorized tool access** | Any client calling any tool | **Policy engine** (allow/deny/read-only) + **tools/list filtering** so the model never even sees denied tools | ✅ Strong |
| **Resource exhaustion** | Hammering expensive tools | Global + per-tool **rate limiting** | ✅ Good |
| **Tool-description prompt injection** | Imperative instructions embedded in a description the model reads ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) | Pinning detects *changes*; least-privilege policy limits blast radius | ⚠️ Partial — see non-goals |
| **Advanced Tool Poisoning (ATPA) / runtime output injection** | Payload appears only in dynamic tool *output* or error strings ([CyberArk](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)) | — | ❌ Out of scope |
| **Indirect prompt injection / lethal trifecta** | Untrusted data + sensitive data + an exfiltration channel in one agent session ([Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)) | — (architectural; address with least-privilege scoping at the agent layer) | ❌ Out of scope |

## OAuth 2.1 resource-server conformance

When `auth.type: oauth`, mcpx implements the resource-server obligations from the [MCP authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization):

- **[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) audience validation** — a JWT is rejected unless its `aud` claim contains the configured `resource`. This is the spec's defense against token passthrough and confused-deputy.
- **[RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) Protected Resource Metadata** — published at `/.well-known/oauth-protected-resource` and advertised via `WWW-Authenticate` on `401` so clients can discover the authorization server.
- **Signature + expiry** — RS256 verified against the authorization server's JWKS; `exp` required; `iss` checked when configured.

Current limits: RS256 only (ES256/EdDSA on the roadmap); the gateway is the resource server and does not itself broker the authorization-code flow.

## Non-goals (by design)

mcpx does **not**:

- Scan tool descriptions or tool **output** for prompt injection with regex/LLM heuristics. These are bypassable and miss runtime-output attacks (ATPA). The right mitigations are least-privilege scoping and breaking the lethal trifecta at the agent layer — not gateway content matching.
- Detect a *first-seen* poisoned tool. Integrity pinning detects **changes** from a baseline; if a tool is malicious on first sighting, pinning will faithfully pin the malicious schema. Pair pinning with explicit allow-lists for tools you trust.
- Sandbox or isolate the backend MCP servers (cf. Docker MCP Gateway's container isolation). mcpx is a network gateway, not a runtime.

## Hardening checklist

- Set `auth.enabled: true` (prefer `oauth` with audience validation in production).
- Use `policy.allow_tools` (allow-list) rather than only deny-lists.
- Enable `inspection.tool_integrity: enforce` and `inspection.filter_tools_list: true`.
- Enable audit logging and ship it somewhere durable.
- Put expensive/destructive tools behind tighter per-tool rate limits.
- Terminate TLS in front of mcpx; never accept bearer tokens over plaintext.
