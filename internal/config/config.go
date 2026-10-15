// Package config handles loading and validating mcpx gateway configuration.
//
// Configuration is loaded from a YAML file specified with the -c flag.
// All sections are optional with sensible defaults.
package config

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration accepts Go duration strings ("30s", "2m") in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dd, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q (use Go syntax, e.g. \"30s\"): %w", s, err)
	}
	*d = Duration(dd)
	return nil
}

// Config is the top-level gateway configuration.
type Config struct {
	Listen     string                  `yaml:"listen"`
	Servers    []ServerConfig          `yaml:"servers"`
	Auth       *AuthConfig             `yaml:"auth"`
	Audit      *AuditConfig            `yaml:"audit"`
	RateLimit  *RateLimitConfig        `yaml:"rate_limit"`
	CORS       *CORSConfig             `yaml:"cors"`
	Inspection *InspectionConfig       `yaml:"inspection"`
	Clients    map[string]ClientConfig `yaml:"clients"` // per-client policy overrides, keyed by client name
	// CircuitBreaker fails fast per backend after repeated upstream failures.
	// Settings are read once at startup (like inspection.tool_integrity) so
	// breaker state survives config hot-reloads; changing them needs a restart.
	CircuitBreaker *CircuitBreakerConfig `yaml:"circuit_breaker"`
	// Tracing configures OpenTelemetry distributed tracing. Like the circuit
	// breaker, its settings are read once at startup (the exporter connection
	// persists across reloads), so changing them needs a restart.
	Tracing *TracingConfig `yaml:"tracing"`
	// Cache configures response caching for idempotent tools. Store sizing is
	// read once at startup (cached entries survive reloads); which tools are
	// cacheable is per-server and does reload. Enabling it globally caches
	// nothing on its own: every cached tool is opted in under servers[].cache.
	Cache *CacheConfig `yaml:"cache"`
}

// CacheConfig sizes the shared response cache. Zero values take defaults
// (max_entries 1000, default_ttl 60s, max_body_bytes 262144).
type CacheConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxEntries bounds the LRU; the least recently used entry is evicted
	// past this point.
	MaxEntries int `yaml:"max_entries"`
	// DefaultTTL applies to cached tools that do not set their own ttl.
	DefaultTTL Duration `yaml:"default_ttl"`
	// MaxBodyBytes skips caching responses larger than this, so one huge
	// result cannot push everything else out of a bounded cache.
	MaxBodyBytes int `yaml:"max_body_bytes"`
	// PurgeOnReload empties the cache on every config reload. Off by default:
	// entries are keyed by server, tool, client, and arguments, so a reload
	// that changes policy cannot serve a newly-denied call (policy is
	// evaluated before the cache is consulted). Turn it on when backends
	// change behaviour under the same tool name.
	PurgeOnReload bool `yaml:"purge_on_reload"`
}

// ServerCacheConfig opts individual tools on one server into response caching.
// Caching is deny-by-default: a tool absent from Tools is never cached.
type ServerCacheConfig struct {
	// Tools maps tool name to its cache rule. An empty rule uses the global
	// default_ttl.
	Tools map[string]CacheRule `yaml:"tools"`
}

// CacheRule is the per-tool cache policy.
type CacheRule struct {
	// TTL is how long a response for this tool stays fresh (default: the
	// global cache.default_ttl).
	TTL Duration `yaml:"ttl"`
}

// TracingConfig configures OpenTelemetry (OTLP) distributed tracing. When
// enabled, mcpx emits one root span per request with child spans for policy
// evaluation and the backend call, and propagates W3C trace context to
// instrumented HTTP backends. When disabled (the default) tracing is a
// near-zero-cost no-op. Zero values take defaults: exporter "otlp",
// service_name "mcpx", sample_ratio 1.0, insecure true.
type TracingConfig struct {
	Enabled bool `yaml:"enabled"`
	// Exporter selects the span exporter: "otlp" (default, OTLP over HTTP) or
	// "stdout" (prints spans to stdout, for local debugging).
	Exporter string `yaml:"exporter"`
	// Endpoint is the OTLP/HTTP collector address (host:port, default port
	// 4318). Required when exporter is "otlp".
	Endpoint string `yaml:"endpoint"`
	// ServiceName is reported as service.name on every span (default "mcpx").
	ServiceName string `yaml:"service_name"`
	// SampleRatio is the head-based sampling probability in [0,1] (default 1.0,
	// sample everything). Applied via a parent-based ratio sampler.
	SampleRatio *float64 `yaml:"sample_ratio"` // pointer so 0.0 is distinguishable from unset
	// Insecure sends OTLP over plain HTTP instead of HTTPS (default true, for
	// local collectors). Set false to use TLS.
	Insecure *bool `yaml:"insecure"` // pointer so false is distinguishable from unset
	// Headers are extra HTTP headers sent to the OTLP collector, e.g. an
	// authorization header for a hosted backend.
	Headers map[string]string `yaml:"headers"`
}

// CircuitBreakerConfig tunes the per-backend circuit breaker. Zero values
// take defaults (threshold 5, cooldown 30s, half_open_max 1).
type CircuitBreakerConfig struct {
	Enabled          bool     `yaml:"enabled"`
	FailureThreshold int      `yaml:"failure_threshold"` // consecutive failures that open the breaker
	Cooldown         Duration `yaml:"cooldown"`          // open -> half-open delay
	HalfOpenMax      int      `yaml:"half_open_max"`     // probes admitted while half-open
}

// ClientConfig narrows what an authenticated client may do, per server.
// The effective decision is the intersection of the server policy and the
// client's override: BOTH must allow a call. Client names come from auth
// (named credentials for bearer/api_key, the identity claim for OAuth);
// a client with no entry here gets the server baseline policy.
type ClientConfig struct {
	Servers map[string]*Policy `yaml:"servers"`
}

// InspectionConfig controls response-level inspection of tools/list payloads.
type InspectionConfig struct {
	// ToolIntegrity pins tool schemas and reacts to mutation:
	// "off" (default), "warn" (log only), or "enforce" (drop changed tools).
	ToolIntegrity string `yaml:"tool_integrity"`
	// FilterToolsList removes policy-denied tools from tools/list responses
	// so clients never see tools they are not permitted to call.
	FilterToolsList bool `yaml:"filter_tools_list"`
}

// ServerConfig defines a backend MCP server.
type ServerConfig struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`       // http/sse only
	Transport string `yaml:"transport"` // "http" (default), its alias "sse" (SSE streams are auto-detected per response), or "stdio"
	// Headers are set on every request forwarded to this backend, replacing
	// any client-supplied header of the same name, so backend credentials
	// stay in the gateway: clients never see or need them. Values may use
	// secret references (${env:NAME}, ${file:PATH}). http/sse only.
	Headers map[string]string `yaml:"headers"`
	// TLS configures the connection to an https backend: a private CA, a
	// client certificate for mutual TLS, and verification settings.
	// http/sse only, and only with an https url.
	TLS *BackendTLSConfig `yaml:"tls"`
	// Stdio transport: the gateway spawns Command as a child process and
	// speaks newline-delimited JSON-RPC over its stdin/stdout. One shared
	// process serves all gateway clients.
	Command        string            `yaml:"command"`         // stdio only: executable to spawn
	Args           []string          `yaml:"args"`            // stdio only: arguments for Command
	Env            map[string]string `yaml:"env"`             // stdio only: extra environment for the child (values may use secret references)
	WorkDir        string            `yaml:"workdir"`         // stdio only: working directory for the child
	RequestTimeout Duration          `yaml:"request_timeout"` // stdio only: per-request reply deadline (default 30s)
	Policy         *Policy           `yaml:"policy"`
	// Cache names the tools on this server whose responses may be cached.
	// Ignored unless the top-level cache section is enabled.
	Cache *ServerCacheConfig `yaml:"cache"`
}

// Policy defines tool-level access control for a server.
type Policy struct {
	ReadOnly   bool                `yaml:"read_only"`
	AllowTools []string            `yaml:"allow_tools"`
	DenyTools  []string            `yaml:"deny_tools"`
	ToolRules  map[string]ToolRule `yaml:"tool_rules"` // per-tool argument constraints
}

// ToolRule constrains the arguments a tool may be called with.
type ToolRule struct {
	Args map[string]ArgRule `yaml:"args"`
}

// ArgRule is a deterministic constraint on a single top-level tool argument.
// Multiple constraints on the same argument are ANDed. Rules only constrain
// the arguments they name: an absent argument passes unless Required is set.
// Scalar values are compared as strings (bools as "true"/"false", numbers in
// their shortest decimal form); a rule that targets a non-scalar value
// (object, array, null) denies the call — what cannot be compared cannot be
// allowed. Prefix is a literal string check: no path canonicalization is
// performed.
type ArgRule struct {
	Equals   *string  `yaml:"equals"` // pointer so "" is distinguishable from unset
	OneOf    []string `yaml:"one_of"`
	Prefix   string   `yaml:"prefix"`
	Suffix   string   `yaml:"suffix"`
	Regex    string   `yaml:"regex"`
	Required bool     `yaml:"required"`
}

// AuthConfig defines authentication settings.
type AuthConfig struct {
	Enabled bool         `yaml:"enabled"`
	Type    string       `yaml:"type"`   // "bearer", "api_key", "none", "oauth"
	Token   string       `yaml:"token"`  // single shared token for bearer/api_key (identifies as client "default")
	Header  string       `yaml:"header"` // for api_key auth (default: X-API-Key)
	OAuth   *OAuthConfig `yaml:"oauth"`  // for oauth (OAuth 2.1 resource server)
	// Clients lists named credentials for bearer/api_key auth so requests
	// carry a client identity (used by per-client policies and audit logs).
	// May be combined with Token, which matches as client "default".
	Clients []ClientCredential `yaml:"clients"`
	// IdentityClaim is the JWT claim used as the client identity for oauth
	// (default "sub").
	IdentityClaim string `yaml:"identity_claim"`
}

// ClientCredential is a named bearer/api_key token.
type ClientCredential struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
}

// OAuthConfig configures the gateway as an OAuth 2.1 protected resource server,
// per the MCP authorization spec. Inbound JWT access tokens are validated for
// signature, expiry, and — critically — audience (RFC 8707): a token MUST list
// this resource in its aud claim or it is rejected. Tokens are never forwarded
// upstream.
type OAuthConfig struct {
	// Resource is this gateway's canonical resource identifier (an https URL),
	// the value an access token's aud claim MUST contain.
	Resource string `yaml:"resource"`
	// AuthorizationServers lists trusted issuer URLs advertised in the
	// RFC 9728 Protected Resource Metadata document.
	AuthorizationServers []string `yaml:"authorization_servers"`
	// JWKSURI is the authorization server's JSON Web Key Set endpoint used to
	// verify token signatures (RS256).
	JWKSURI string `yaml:"jwks_uri"`
	// Issuer, when set, is validated against the token's iss claim.
	Issuer string `yaml:"issuer"`
	// Algorithms restricts the accepted JWS signature algorithms (default:
	// all of SupportedJWTAlgorithms). Whatever is allowed here, a token is
	// only verified with a JWKS key whose type matches its algorithm.
	Algorithms []string `yaml:"algorithms"`
}

// SupportedJWTAlgorithms are the asymmetric JWS algorithms OAuth mode can
// verify. HMAC (HS*) and "none" are deliberately absent: a resource server
// verifying with a shared secret could forge tokens itself.
var SupportedJWTAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// AuditConfig defines audit logging settings.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Output  string `yaml:"output"` // "stdout", "file", "json"
	Path    string `yaml:"path"`   // file path when output is "file"
}

// RateLimitConfig defines rate limiting settings.
type RateLimitConfig struct {
	Enabled   bool    `yaml:"enabled"`
	RPS       float64 `yaml:"rps"`
	Burst     int     `yaml:"burst"`
	PerTool   bool    `yaml:"per_tool"`
	ToolRPS   float64 `yaml:"tool_rps"`
	ToolBurst int     `yaml:"tool_burst"`
}

// CORSConfig defines CORS settings for browser-based MCP clients.
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
	MaxAge         string   `yaml:"max_age"`
}

// Load reads and validates configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{
		Listen: ":8080", // default
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Resolve secret references before validation so checks (non-empty
	// tokens, header values free of CR/LF) see the real values.
	if err := cfg.resolveSecrets(); err != nil {
		return nil, fmt.Errorf("resolving secrets: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}

	for i, srv := range c.Servers {
		if srv.Name == "" {
			return fmt.Errorf("server %d: name is required", i)
		}
		switch srv.Transport {
		case "":
			c.Servers[i].Transport = "http"
			fallthrough
		case "http", "sse":
			// valid; "sse" is an alias of "http" — streaming responses are
			// detected per-response via Content-Type, not per-server.
			if srv.URL == "" {
				return fmt.Errorf("server %q: url is required", srv.Name)
			}
			if srv.Command != "" {
				return fmt.Errorf("server %q: command is only valid with transport \"stdio\"", srv.Name)
			}
			if err := validateHeaders(srv.Headers, fmt.Sprintf("server %q: headers", srv.Name)); err != nil {
				return err
			}
			if srv.TLS != nil {
				if !strings.HasPrefix(strings.ToLower(srv.URL), "https://") {
					return fmt.Errorf("server %q: tls requires an https:// url (got %q)", srv.Name, srv.URL)
				}
				// Building loads the CA and key pair, so a missing file or
				// mismatched cert/key fails the load (or reload), not the
				// first request.
				if _, err := srv.TLS.ClientConfig(); err != nil {
					return fmt.Errorf("server %q: tls: %w", srv.Name, err)
				}
			}
		case "stdio":
			if srv.Command == "" {
				return fmt.Errorf("server %q: command is required with transport \"stdio\"", srv.Name)
			}
			if srv.URL != "" {
				return fmt.Errorf("server %q: url must not be set with transport \"stdio\"", srv.Name)
			}
			if srv.TLS != nil {
				return fmt.Errorf("server %q: tls is only valid with transport \"http\" or \"sse\"", srv.Name)
			}
			if len(srv.Headers) > 0 {
				return fmt.Errorf("server %q: headers are only valid with transport \"http\" or \"sse\" (use env to pass credentials to a stdio server)", srv.Name)
			}
			for k, v := range srv.Env {
				if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, 0) {
					return fmt.Errorf("server %q: env: invalid entry %q (names must be non-empty without '=' or NUL; values must not contain NUL)", srv.Name, k)
				}
			}
		default:
			return fmt.Errorf("server %q: transport must be \"http\", \"sse\", or \"stdio\" (got %q)", srv.Name, srv.Transport)
		}
		if srv.RequestTimeout < 0 {
			return fmt.Errorf("server %q: request_timeout must not be negative", srv.Name)
		}
		if err := validatePolicy(srv.Policy, fmt.Sprintf("server %q", srv.Name)); err != nil {
			return err
		}
		if srv.Cache != nil {
			for tool, rule := range srv.Cache.Tools {
				if tool == "" {
					return fmt.Errorf("server %q: cache.tools: tool name must not be empty", srv.Name)
				}
				if rule.TTL < 0 {
					return fmt.Errorf("server %q: cache.tools.%s.ttl must not be negative", srv.Name, tool)
				}
			}
		}
	}

	if c.Auth != nil && c.Auth.Enabled {
		switch c.Auth.Type {
		case "bearer", "api_key", "none", "oauth", "":
			// valid
		default:
			return fmt.Errorf("auth.type must be \"bearer\", \"api_key\", \"oauth\", or \"none\" (got %q)", c.Auth.Type)
		}
		if (c.Auth.Type == "bearer" || c.Auth.Type == "api_key") && c.Auth.Token == "" && len(c.Auth.Clients) == 0 {
			return fmt.Errorf("auth.token or auth.clients is required when auth.type is %q", c.Auth.Type)
		}
		seen := make(map[string]bool, len(c.Auth.Clients))
		for i, cc := range c.Auth.Clients {
			if cc.Name == "" {
				return fmt.Errorf("auth.clients[%d]: name is required", i)
			}
			if cc.Token == "" {
				return fmt.Errorf("auth.clients[%d] (%q): token is required", i, cc.Name)
			}
			if seen[cc.Name] {
				return fmt.Errorf("auth.clients: duplicate client name %q", cc.Name)
			}
			seen[cc.Name] = true
		}
		if c.Auth.Type == "oauth" {
			if c.Auth.OAuth == nil {
				return fmt.Errorf("auth.oauth is required when auth.type is \"oauth\"")
			}
			if c.Auth.OAuth.Resource == "" {
				return fmt.Errorf("auth.oauth.resource is required (the audience tokens must be bound to)")
			}
			if c.Auth.OAuth.JWKSURI == "" {
				return fmt.Errorf("auth.oauth.jwks_uri is required to verify token signatures")
			}
			for _, a := range c.Auth.OAuth.Algorithms {
				if slices.Contains(SupportedJWTAlgorithms, a) {
					continue
				}
				return fmt.Errorf("auth.oauth.algorithms: unsupported algorithm %q (supported: %s)", a, strings.Join(SupportedJWTAlgorithms, ", "))
			}
		}
	}

	if c.RateLimit != nil && c.RateLimit.Enabled {
		if c.RateLimit.RPS <= 0 {
			return fmt.Errorf("rate_limit.rps must be positive (got %.1f)", c.RateLimit.RPS)
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be positive (got %d)", c.RateLimit.Burst)
		}
	}

	if c.Inspection != nil {
		switch c.Inspection.ToolIntegrity {
		case "", "off", "warn", "enforce":
			// valid
		default:
			return fmt.Errorf("inspection.tool_integrity must be \"off\", \"warn\", or \"enforce\" (got %q)", c.Inspection.ToolIntegrity)
		}
	}

	if cb := c.CircuitBreaker; cb != nil && cb.Enabled {
		if cb.FailureThreshold < 0 {
			return fmt.Errorf("circuit_breaker.failure_threshold must not be negative (got %d)", cb.FailureThreshold)
		}
		if cb.Cooldown < 0 {
			return fmt.Errorf("circuit_breaker.cooldown must not be negative")
		}
		if cb.HalfOpenMax < 0 {
			return fmt.Errorf("circuit_breaker.half_open_max must not be negative (got %d)", cb.HalfOpenMax)
		}
	}

	if tr := c.Tracing; tr != nil && tr.Enabled {
		switch tr.Exporter {
		case "", "otlp", "stdout":
			// valid; empty defaults to "otlp"
		default:
			return fmt.Errorf("tracing.exporter must be \"otlp\" or \"stdout\" (got %q)", tr.Exporter)
		}
		if tr.Exporter != "stdout" && tr.Endpoint == "" {
			return fmt.Errorf("tracing.endpoint is required when tracing.exporter is \"otlp\"")
		}
		if tr.SampleRatio != nil && (*tr.SampleRatio < 0 || *tr.SampleRatio > 1) {
			return fmt.Errorf("tracing.sample_ratio must be between 0.0 and 1.0 (got %v)", *tr.SampleRatio)
		}
	}

	if ca := c.Cache; ca != nil && ca.Enabled {
		if ca.MaxEntries < 0 {
			return fmt.Errorf("cache.max_entries must not be negative (got %d)", ca.MaxEntries)
		}
		if ca.DefaultTTL < 0 {
			return fmt.Errorf("cache.default_ttl must not be negative")
		}
		if ca.MaxBodyBytes < 0 {
			return fmt.Errorf("cache.max_body_bytes must not be negative (got %d)", ca.MaxBodyBytes)
		}
	}

	// Client policy names are deliberately not checked against auth.clients:
	// OAuth identities (JWT subjects) are not enumerable in config.
	for name, cc := range c.Clients {
		if name == "" {
			return fmt.Errorf("clients: client name must not be empty")
		}
		for srv, p := range cc.Servers {
			if err := validatePolicy(p, fmt.Sprintf("clients.%s.servers.%s", name, srv)); err != nil {
				return err
			}
		}
	}

	return nil
}

// reservedHeaders may not be injected: the reverse proxy manages framing,
// routing, and connection headers itself, and overriding them would corrupt
// or misroute the forwarded request.
var reservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true,
	"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true,
	"Upgrade": true, "Proxy-Connection": true,
}

// validateHeaders checks injected header names are valid HTTP tokens, not
// reserved, and unique case-insensitively, and that values (already
// secret-expanded) contain no CR, LF, or NUL that could split the request.
func validateHeaders(h map[string]string, where string) error {
	seen := make(map[string]bool, len(h))
	for name, value := range h {
		if !isToken(name) {
			return fmt.Errorf("%s: invalid header name %q", where, name)
		}
		canon := http.CanonicalHeaderKey(name)
		if reservedHeaders[canon] {
			return fmt.Errorf("%s: header %q is managed by the proxy and cannot be injected", where, name)
		}
		if seen[canon] {
			return fmt.Errorf("%s: duplicate header %q (names are case-insensitive)", where, canon)
		}
		seen[canon] = true
		if strings.ContainsAny(value, "\r\n\x00") {
			// Deliberately does not echo the value: it may be a secret.
			return fmt.Errorf("%s: value of %q contains a CR, LF, or NUL character", where, name)
		}
	}
	return nil
}

// isToken reports whether s is a valid HTTP header field name (RFC 9110 token).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// validatePolicy checks a policy's tool_rules: every argument rule must carry
// at least one constraint (which also catches misspelled constraint keys,
// since those leave the rule empty) and regexes must compile.
func validatePolicy(p *Policy, where string) error {
	if p == nil {
		return nil
	}
	for tool, tr := range p.ToolRules {
		for arg, ar := range tr.Args {
			if ar.Equals == nil && len(ar.OneOf) == 0 && ar.Prefix == "" && ar.Suffix == "" && ar.Regex == "" && !ar.Required {
				return fmt.Errorf("%s: tool_rules.%s.args.%s: at least one constraint (equals, one_of, prefix, suffix, regex, required) is required", where, tool, arg)
			}
			if ar.Regex != "" {
				if _, err := regexp.Compile(ar.Regex); err != nil {
					return fmt.Errorf("%s: tool_rules.%s.args.%s: invalid regex: %w", where, tool, arg, err)
				}
			}
		}
	}
	return nil
}
