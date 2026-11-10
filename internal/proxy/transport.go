package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rohitgs28/mcpx/internal/config"
	"github.com/rohitgs28/mcpx/internal/openapi"
)

// NewOpenAPIServer builds the in-process MCP server for an openapi backend:
// the spec's operations as tools, calling the API at sc.URL with the
// server's injected headers and TLS settings.
func NewOpenAPIServer(sc config.ServerConfig) (*openapi.Server, error) {
	o := sc.OpenAPI
	if o == nil {
		return nil, fmt.Errorf("openapi section is required")
	}
	spec := o.Parsed
	if spec == nil {
		var err error
		if spec, err = config.LoadOpenAPISpec(o.Spec); err != nil {
			return nil, err
		}
	}
	base := sc.URL
	if base == "" {
		base = spec.ServerURL
	}
	opts := openapi.Options{
		Name:             sc.Name,
		BaseURL:          base,
		Headers:          sc.Headers,
		Filter:           o.Filter(),
		Timeout:          time.Duration(sc.RequestTimeout),
		MaxResponseBytes: o.MaxResponseBytes,
		Version:          spec.Version,
	}
	t, err := BackendTransport(sc)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if t != nil {
		opts.Transport = t
	}
	return openapi.New(spec, opts)
}

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
