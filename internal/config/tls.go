package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// BackendTLSConfig configures the gateway's TLS client toward one backend.
// Files are read on every load and reload, so rotating a certificate takes a
// SIGHUP (connections opened under the old certificate drain naturally).
type BackendTLSConfig struct {
	// CAFile is a PEM bundle of CAs trusted to sign the backend's
	// certificate. When set it REPLACES the system roots for this backend
	// (pinning it to a private CA); when unset the system roots are used.
	CAFile string `yaml:"ca_file"`
	// CertFile and KeyFile are the PEM client certificate and private key
	// presented for mutual TLS. Set both or neither.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ServerName overrides the name used for SNI and certificate
	// verification (default: the url's host), e.g. when connecting by IP.
	ServerName string `yaml:"server_name"`
	// MinVersion is the lowest TLS version accepted: "1.2" (default) or "1.3".
	MinVersion string `yaml:"min_version"`
	// InsecureSkipVerify disables verification of the backend's certificate.
	// For local testing only: it makes the connection open to interception.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// ClientConfig builds the crypto/tls client configuration, loading the CA
// bundle and client key pair from disk.
func (t *BackendTLSConfig) ClientConfig() (*tls.Config, error) {
	if (t.CertFile == "") != (t.KeyFile == "") {
		return nil, errors.New("cert_file and key_file must be set together")
	}
	if t.InsecureSkipVerify && t.CAFile != "" {
		return nil, errors.New("insecure_skip_verify disables verification, so ca_file would be ignored; set one or the other")
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         t.ServerName,
		InsecureSkipVerify: t.InsecureSkipVerify, // explicit opt-in, documented as testing-only
	}
	switch t.MinVersion {
	case "", "1.2":
	case "1.3":
		tc.MinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("min_version must be \"1.2\" or \"1.3\" (got %q)", t.MinVersion)
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %q contains no PEM certificates", t.CAFile)
		}
		tc.RootCAs = pool
	}
	if t.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return tc, nil
}
