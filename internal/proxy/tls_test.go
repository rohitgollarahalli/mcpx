package proxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rohitgs28/mcpx/internal/config"
)

// testPKI is a throwaway CA with one server and one client certificate,
// written as PEM files under a temp dir.
type testPKI struct {
	caPool                                *x509.CertPool
	serverCert                            tls.Certificate
	caFile, clientCertFile, clientKeyFile string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey := mustKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mcpx test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	p := &testPKI{caPool: x509.NewCertPool(), caFile: filepath.Join(dir, "ca.pem")}
	p.caPool.AddCert(caCert)
	writePEM(t, p.caFile, "CERTIFICATE", caDER)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, dns []string) ([]byte, *ecdsa.PrivateKey) {
		key := mustKey(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	// The server cert names only backend.internal, so reaching it on
	// 127.0.0.1 requires the server_name override.
	srvDER, srvKey := issue(2, "backend", x509.ExtKeyUsageServerAuth, []string{"backend.internal"})
	p.serverCert = tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}

	cliDER, cliKey := issue(3, "mcpx-gateway", x509.ExtKeyUsageClientAuth, nil)
	p.clientCertFile = filepath.Join(dir, "client.pem")
	p.clientKeyFile = filepath.Join(dir, "client.key")
	writePEM(t, p.clientCertFile, "CERTIFICATE", cliDER)
	keyDER, err := x509.MarshalECPrivateKey(cliKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, p.clientKeyFile, "EC PRIVATE KEY", keyDER)
	return p
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mtlsUpstream starts an https backend that requires a client certificate
// signed by the test CA, and records the client cert's common name.
func mtlsUpstream(t *testing.T, p *testPKI, seenCN *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seenCN = r.TLS.PeerCertificates[0].Subject.CommonName
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientCAs:    p.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestBackendMutualTLS(t *testing.T) {
	p := newTestPKI(t)
	var seenCN string
	up := mtlsUpstream(t, p, &seenCN)

	full := &config.BackendTLSConfig{CAFile: p.caFile, CertFile: p.clientCertFile, KeyFile: p.clientKeyFile, ServerName: "backend.internal"}
	cases := []struct {
		name   string
		tls    *config.BackendTLSConfig
		status int
	}{
		{"ca + client cert", full, http.StatusOK},
		{"no client cert", &config.BackendTLSConfig{CAFile: p.caFile, ServerName: "backend.internal"}, http.StatusBadGateway},
		{"system roots only", &config.BackendTLSConfig{CertFile: p.clientCertFile, KeyFile: p.clientKeyFile, ServerName: "backend.internal"}, http.StatusBadGateway},
		{"name mismatch", &config.BackendTLSConfig{CAFile: p.caFile, CertFile: p.clientCertFile, KeyFile: p.clientKeyFile}, http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seenCN = ""
			cfg := &config.Config{Servers: []config.ServerConfig{{Name: "up", URL: up.URL, Transport: "http", TLS: c.tls}}}
			gw := newGatewayFromConfig(t, cfg)
			req := httptest.NewRequest(http.MethodPost, "/mcp/up", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, req)
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, c.status, rec.Body)
			}
			if c.status == http.StatusOK && seenCN != "mcpx-gateway" {
				t.Errorf("backend saw client cert CN %q, want mcpx-gateway", seenCN)
			}
		})
	}
}
