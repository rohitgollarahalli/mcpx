// Package auth provides authentication middleware for the MCP gateway.
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/rohitgs28/mcpx/internal/config"
	"github.com/rohitgs28/mcpx/internal/httperr"
)

func Middleware(cfg config.AuthConfig) func(http.Handler) http.Handler {
	// Build the OAuth validator once (it caches JWKS keys), not per request.
	var validator *OAuthValidator
	if cfg.Enabled && cfg.Type == "oauth" && cfg.OAuth != nil {
		validator = NewOAuthValidator(*cfg.OAuth)
	}
	// Named credentials for bearer/api_key; the legacy single token keeps
	// working and identifies as client "default".
	creds := cfg.Clients
	if cfg.Token != "" {
		creds = append([]config.ClientCredential{{Name: "default", Token: cfg.Token}}, creds...)
	}
	return func(next http.Handler) http.Handler {
		if !cfg.Enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var client string
			switch cfg.Type {
			case "bearer":
				h := r.Header.Get("Authorization")
				if !strings.HasPrefix(h, "Bearer ") {
					httperr.Write(w, http.StatusUnauthorized, httperr.CodeUnauthorized, "missing Authorization header")
					return
				}
				name, ok := matchCredential(creds, strings.TrimPrefix(h, "Bearer "))
				if !ok {
					httperr.Write(w, http.StatusUnauthorized, httperr.CodeUnauthorized, "invalid token")
					return
				}
				client = name
			case "api_key":
				name, ok := matchCredential(creds, r.Header.Get(credentialHeader(cfg)))
				if !ok {
					httperr.Write(w, http.StatusUnauthorized, httperr.CodeUnauthorized, "invalid API key")
					return
				}
				client = name
			case "oauth":
				h := r.Header.Get("Authorization")
				if !strings.HasPrefix(h, "Bearer ") {
					w.Header().Set("WWW-Authenticate", challenge(validator.cfg.Resource))
					httperr.Write(w, http.StatusUnauthorized, httperr.CodeUnauthorized, "missing bearer token")
					return
				}
				id, err := validator.Validate(strings.TrimPrefix(h, "Bearer "), cfg.IdentityClaim)
				if err != nil {
					w.Header().Set("WWW-Authenticate", challenge(validator.cfg.Resource))
					httperr.Write(w, http.StatusUnauthorized, httperr.CodeUnauthorized, "invalid token")
					return
				}
				client = id
			}
			if client != "" {
				r = r.WithContext(WithClient(r.Context(), client))
			}
			// The credential was issued for the gateway, not the backend:
			// strip it so it is never forwarded upstream (the MCP spec forbids
			// token passthrough). Backends that need credentials get them via
			// servers[].headers instead.
			if hdr := credentialHeader(cfg); hdr != "" {
				r.Header.Del(hdr)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// credentialHeader names the request header carrying the gateway credential
// for the configured auth type, or "" when there is none.
func credentialHeader(cfg config.AuthConfig) string {
	switch cfg.Type {
	case "bearer", "oauth":
		return "Authorization"
	case "api_key":
		if cfg.Header != "" {
			return cfg.Header
		}
		return "X-API-Key"
	}
	return ""
}

// matchCredential compares the presented token against every credential in
// constant time per credential and without early exit, so response timing
// does not reveal which (or whether any) token matched.
func matchCredential(creds []config.ClientCredential, presented string) (string, bool) {
	p := []byte(presented)
	matched := -1
	for i := range creds {
		if subtle.ConstantTimeCompare(p, []byte(creds[i].Token)) == 1 && matched == -1 {
			matched = i
		}
	}
	if matched == -1 {
		return "", false
	}
	return creds[matched].Name, true
}
