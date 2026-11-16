package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rohitgollarahalli/mcpx/internal/auth"
	"github.com/rohitgollarahalli/mcpx/internal/config"
)

const (
	testKID      = "test-key"
	testResource = "https://gateway.example.com/mcp"
	testIssuer   = "https://auth.example.com"
)

// jwksServer generates an RSA key and serves its public half as a JWKS.
func jwksServer(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	doc, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{"kty": "RSA", "kid": testKID, "alg": "RS256", "use": "sig", "n": n, "e": e},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return priv, srv.URL
}

func signToken(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"aud": testResource,
		"iss": testIssuer,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func newValidator(jwksURI string) *auth.OAuthValidator {
	return auth.NewOAuthValidator(config.OAuthConfig{
		Resource: testResource,
		JWKSURI:  jwksURI,
		Issuer:   testIssuer,
	})
}

func TestOAuth_ValidToken(t *testing.T) {
	priv, jwks := jwksServer(t)
	v := newValidator(jwks)
	if _, err := v.Validate(signToken(t, priv, validClaims()), ""); err != nil {
		t.Fatalf("expected valid token to pass, got %v", err)
	}
}

func TestOAuth_IdentityFromClaims(t *testing.T) {
	priv, jwks := jwksServer(t)
	v := newValidator(jwks)

	c := validClaims()
	c["sub"] = "user-42"
	c["client_name"] = "svc-batch"

	// Default claim is sub.
	id, err := v.Validate(signToken(t, priv, c), "")
	if err != nil || id != "user-42" {
		t.Fatalf("default claim: id = %q, err %v; want user-42", id, err)
	}
	// Custom identity claim.
	id, err = v.Validate(signToken(t, priv, c), "client_name")
	if err != nil || id != "svc-batch" {
		t.Fatalf("custom claim: id = %q, err %v; want svc-batch", id, err)
	}
	// Missing claim yields empty identity but no error.
	noSub := validClaims()
	id, err = v.Validate(signToken(t, priv, noSub), "")
	if err != nil || id != "" {
		t.Fatalf("missing claim: id = %q, err %v; want empty", id, err)
	}
}

func TestOAuth_MiddlewarePutsIdentityInContext(t *testing.T) {
	priv, jwks := jwksServer(t)
	cfg := config.AuthConfig{
		Enabled: true, Type: "oauth",
		OAuth: &config.OAuthConfig{Resource: testResource, JWKSURI: jwks, Issuer: testIssuer},
	}
	var got string
	h := auth.Middleware(cfg)(clientCapture(&got))

	c := validClaims()
	c["sub"] = "user-42"
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, priv, c))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || got != "user-42" {
		t.Fatalf("status = %d, client = %q; want 200, user-42", rec.Code, got)
	}
}

func TestOAuth_WrongAudienceRejected(t *testing.T) {
	priv, jwks := jwksServer(t)
	v := newValidator(jwks)
	c := validClaims()
	c["aud"] = "https://some-other-resource.example.com"
	if _, err := v.Validate(signToken(t, priv, c), ""); err == nil {
		t.Fatal("expected token with wrong audience to be rejected (RFC 8707)")
	}
}

func TestOAuth_ExpiredRejected(t *testing.T) {
	priv, jwks := jwksServer(t)
	v := newValidator(jwks)
	c := validClaims()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, err := v.Validate(signToken(t, priv, c), ""); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestOAuth_WrongIssuerRejected(t *testing.T) {
	priv, jwks := jwksServer(t)
	v := newValidator(jwks)
	c := validClaims()
	c["iss"] = "https://evil-issuer.example.com"
	if _, err := v.Validate(signToken(t, priv, c), ""); err == nil {
		t.Fatal("expected token with wrong issuer to be rejected")
	}
}

func TestOAuth_BadSignatureRejected(t *testing.T) {
	_, jwks := jwksServer(t)
	v := newValidator(jwks)
	// Sign with a different key than the one published in the JWKS.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Validate(signToken(t, other, validClaims()), ""); err == nil {
		t.Fatal("expected token signed by an unknown key to be rejected")
	}
}

func TestOAuth_MiddlewareMissingTokenChallenges(t *testing.T) {
	_, jwks := jwksServer(t)
	cfg := config.AuthConfig{
		Enabled: true, Type: "oauth",
		OAuth: &config.OAuthConfig{Resource: testResource, JWKSURI: jwks},
	}
	h := auth.Middleware(cfg)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, "resource_metadata=") || !strings.Contains(wa, testResource) {
		t.Errorf("expected WWW-Authenticate to advertise metadata discovery, got %q", wa)
	}
}

func TestOAuth_MiddlewareValidTokenPasses(t *testing.T) {
	priv, jwks := jwksServer(t)
	cfg := config.AuthConfig{
		Enabled: true, Type: "oauth",
		OAuth: &config.OAuthConfig{Resource: testResource, JWKSURI: jwks, Issuer: testIssuer},
	}
	h := auth.Middleware(cfg)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, priv, validClaims()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid token, got %d", rec.Code)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	h := auth.ProtectedResourceMetadataHandler(config.OAuthConfig{
		Resource:             testResource,
		AuthorizationServers: []string{testIssuer},
	})
	req := httptest.NewRequest(http.MethodGet, auth.MetadataPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if doc["resource"] != testResource {
		t.Errorf("resource = %v, want %v", doc["resource"], testResource)
	}
	if _, ok := doc["authorization_servers"]; !ok {
		t.Error("expected authorization_servers in metadata")
	}
}
