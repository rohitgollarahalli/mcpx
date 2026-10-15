package proxy

import (
	"net/http"

	"github.com/rohitgs28/mcpx/internal/config"
)

// BackendTransport returns the HTTP transport for an http/sse backend: a
// clone of the default transport carrying the server's TLS settings, or nil
// (meaning http.DefaultTransport) when it has none. The health checker uses
// the same transport so probes succeed against mTLS and private-CA backends.
func BackendTransport(sc config.ServerConfig) (*http.Transport, error) {
	if sc.TLS == nil {
		return nil, nil
	}
	tc, err := sc.TLS.ClientConfig()
	if err != nil {
		return nil, err
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tc
	return t, nil
}
