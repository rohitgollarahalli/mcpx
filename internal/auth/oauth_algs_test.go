package auth_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rohitgs28/mcpx/internal/auth"
	"github.com/rohitgs28/mcpx/internal/config"
)

var b64 = base64.RawURLEncoding

// serveJWKS serves the given keys as a JWKS document.
func serveJWKS(t *testing.T, keys ...map[string]string) string {
	t.Helper()
	doc, _ := json.Marshal(map[string]any{"keys": keys})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(doc) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func ecJWK(kid string, k *ecdsa.PrivateKey) map[string]string {
	size := (k.Curve.Params().BitSize + 7) / 8
	return map[string]string{
		"kty": "EC", "kid": kid, "crv": k.Curve.Params().Name,
		"x": b64.EncodeToString(k.X.FillBytes(make([]byte, size))),
		"y": b64.EncodeToString(k.Y.FillBytes(make([]byte, size))),
	}
}

func rsaJWK(kid string, k *rsa.PrivateKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": kid,
		"n": b64.EncodeToString(k.N.Bytes()),
		"e": b64.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

func sign(t *testing.T, m jwt.SigningMethod, kid string, key crypto.PrivateKey) string {
	t.Helper()
	tok := jwt.NewWithClaims(m, validClaims())
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign %s: %v", m.Alg(), err)
	}
	return s
}

func validate(jwksURI, token string, algs ...string) error {
	v := auth.NewOAuthValidator(config.OAuthConfig{Resource: testResource, JWKSURI: jwksURI, Issuer: testIssuer, Algorithms: algs})
	_, err := v.Validate(token, "")
	return err
}

func TestOAuth_AsymmetricAlgorithms(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := serveJWKS(t,
		ecJWK("p256", p256), ecJWK("p384", p384), ecJWK("p521", p521),
		map[string]string{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": b64.EncodeToString(edPub)},
		rsaJWK("rsa", rsaKey),
	)
	cases := []struct {
		m   jwt.SigningMethod
		kid string
		key crypto.PrivateKey
	}{
		{jwt.SigningMethodES256, "p256", p256},
		{jwt.SigningMethodES384, "p384", p384},
		{jwt.SigningMethodES512, "p521", p521},
		{jwt.SigningMethodEdDSA, "ed", edPriv},
		{jwt.SigningMethodRS384, "rsa", rsaKey},
		{jwt.SigningMethodPS256, "rsa", rsaKey},
	}
	for _, c := range cases {
		if err := validate(jwks, sign(t, c.m, c.kid, c.key)); err != nil {
			t.Errorf("%s: valid token rejected: %v", c.m.Alg(), err)
		}
	}
}

// TestOAuth_AlgorithmConfusionRejected covers tokens whose header algorithm
// does not match the key their kid selects.
func TestOAuth_AlgorithmConfusionRejected(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pinned := rsaJWK("rsa-rs256", rsaKey)
	pinned["alg"] = "RS256"
	jwks := serveJWKS(t, ecJWK("p256", p256), pinned)

	// HS256 "signed" with the public RSA modulus: the classic confusion attack.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	hs.Header["kid"] = "rsa-rs256"
	hsTok, _ := hs.SignedString([]byte(pinned["n"]))

	cases := map[string]string{
		"ES384 token on a P-256 key":   sign(t, jwt.SigningMethodES384, "p256", p384),
		"PS256 on a key pinned RS256":  sign(t, jwt.SigningMethodPS256, "rsa-rs256", rsaKey),
		"HS256 with the RSA modulus":   hsTok,
		"EdDSA token on an EC key kid": sign(t, jwt.SigningMethodEdDSA, "p256", ed25519.NewKeyFromSeed(make([]byte, 32))),
	}
	for name, tok := range cases {
		if err := validate(jwks, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOAuth_AlgorithmsAllowList(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := serveJWKS(t, ecJWK("p256", p256))
	tok := sign(t, jwt.SigningMethodES256, "p256", p256)
	if err := validate(jwks, tok, "RS256"); err == nil {
		t.Error("ES256 token accepted although algorithms allows only RS256")
	}
	if err := validate(jwks, tok, "RS256", "ES256"); err != nil {
		t.Errorf("ES256 token rejected although allowed: %v", err)
	}
}

// TestOAuth_BadKeysSkipped checks malformed JWKS entries are ignored while
// the usable keys in the same set keep working.
func TestOAuth_BadKeysSkipped(t *testing.T) {
	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	offCurve := ecJWK("bad", good)
	offCurve["y"] = b64.EncodeToString(make([]byte, 32)) // (x, 0) is not on P-256
	jwks := serveJWKS(t, offCurve, ecJWK("good", good))

	if err := validate(jwks, sign(t, jwt.SigningMethodES256, "good", good)); err != nil {
		t.Fatalf("good key stopped working: %v", err)
	}
	err := validate(jwks, sign(t, jwt.SigningMethodES256, "bad", good))
	if err == nil || !strings.Contains(err.Error(), "no matching key") {
		t.Fatalf("off-curve key used: %v", err)
	}
}
