package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func TestParseJWK_Rejects(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	b64 := base64.RawURLEncoding
	cases := map[string]struct {
		k    jwk
		want string
	}{
		"encryption key":    {jwk{Kty: "OKP", Use: "enc", Crv: "Ed25519", X: b64.EncodeToString(make([]byte, 32))}, "not \"sig\""},
		"symmetric key":     {jwk{Kty: "oct"}, "unsupported key type"},
		"X25519 curve":      {jwk{Kty: "OKP", Crv: "X25519"}, "unsupported OKP curve"},
		"short Ed25519":     {jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(make([]byte, 31))}, "invalid Ed25519"},
		"secp256k1":         {jwk{Kty: "EC", Crv: "secp256k1"}, "unsupported EC curve"},
		"short EC coords":   {jwk{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"}, "invalid P-256 coordinates"},
		"1024-bit RSA":      {jwk{Kty: "RSA", N: b64.EncodeToString(small.N.Bytes()), E: b64.EncodeToString(big.NewInt(65537).Bytes())}, "at least 2048"},
		"alg/type mismatch": {jwk{Kty: "OKP", Crv: "Ed25519", Alg: "ES256", X: b64.EncodeToString(make([]byte, 32))}, "does not match"},
	}
	for name, c := range cases {
		if _, err := parseJWK(c.k); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %v, want containing %q", name, err, c.want)
		}
	}
}
