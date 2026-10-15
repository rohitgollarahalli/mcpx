package auth

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// jwk is one JSON Web Key as served by a JWKS endpoint (RFC 7517), limited
// to the fields needed for signature verification.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC (crv P-256/P-384/P-521) and OKP (crv Ed25519)
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// verificationKey is a parsed public key bound to the JWT algorithms it may
// verify. Binding the algorithm to the key, not to the token header, is what
// prevents algorithm confusion: a token cannot choose to have an RSA key
// treated as an HMAC secret, or a P-384 key used for ES256.
type verificationKey struct {
	key  any
	algs []string
}

func (k verificationKey) allows(alg string) bool { return slices.Contains(k.algs, alg) }

// parseJWK converts a JWK into a verification key. Keys not meant for
// signatures (use other than "sig") and unsupported key types are rejected.
// A JWK "alg" narrows the key to exactly that algorithm.
func parseJWK(k jwk) (verificationKey, error) {
	if k.Use != "" && k.Use != "sig" {
		return verificationKey{}, fmt.Errorf("key use %q is not \"sig\"", k.Use)
	}
	var vk verificationKey
	switch k.Kty {
	case "RSA":
		pk, err := rsaPublicKey(k.N, k.E)
		if err != nil {
			return vk, err
		}
		if pk.N.BitLen() < 2048 {
			return vk, fmt.Errorf("RSA key is %d bits; at least 2048 required", pk.N.BitLen())
		}
		vk = verificationKey{pk, []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}}
	case "EC":
		pk, alg, err := ecPublicKey(k.Crv, k.X, k.Y)
		if err != nil {
			return vk, err
		}
		vk = verificationKey{pk, []string{alg}}
	case "OKP":
		if k.Crv != "Ed25519" {
			return vk, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return vk, fmt.Errorf("invalid Ed25519 public key")
		}
		vk = verificationKey{ed25519.PublicKey(x), []string{"EdDSA"}}
	default:
		return vk, fmt.Errorf("unsupported key type %q", k.Kty)
	}
	if k.Alg != "" {
		if !vk.allows(k.Alg) {
			return verificationKey{}, fmt.Errorf("key alg %q does not match its %s key type", k.Alg, k.Kty)
		}
		vk.algs = []string{k.Alg}
	}
	return vk, nil
}

func rsaPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

// ecPublicKey decodes an EC JWK and returns the key with the one JWS
// algorithm its curve is defined for (RFC 7518 section 3.4). The point is
// validated through crypto/ecdh, which rejects off-curve and identity points.
func ecPublicKey(crv, xB64, yB64 string) (*ecdsa.PublicKey, string, error) {
	var (
		curve elliptic.Curve
		ec    ecdh.Curve
		alg   string
	)
	switch crv {
	case "P-256":
		curve, ec, alg = elliptic.P256(), ecdh.P256(), "ES256"
	case "P-384":
		curve, ec, alg = elliptic.P384(), ecdh.P384(), "ES384"
	case "P-521":
		curve, ec, alg = elliptic.P521(), ecdh.P521(), "ES512"
	default:
		return nil, "", fmt.Errorf("unsupported EC curve %q", crv)
	}
	size := (curve.Params().BitSize + 7) / 8
	x, errX := base64.RawURLEncoding.DecodeString(xB64)
	y, errY := base64.RawURLEncoding.DecodeString(yB64)
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return nil, "", fmt.Errorf("invalid %s coordinates", crv)
	}
	uncompressed := append(append([]byte{4}, x...), y...)
	if _, err := ec.NewPublicKey(uncompressed); err != nil {
		return nil, "", fmt.Errorf("invalid %s point: %w", crv, err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, alg, nil
}

// keyTypes summarizes key types for error messages, e.g. "RSA, EC".
func keyTypes(keys []jwk) string {
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		if !seen[k.Kty] {
			seen[k.Kty] = true
			out = append(out, k.Kty)
		}
	}
	return strings.Join(out, ", ")
}
