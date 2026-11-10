package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testSpec = `{
  "openapi": "3.0.3",
  "info": {"title": "Pets", "version": "1.0.0"},
  "servers": [{"url": "https://api.pets.example.com/v1"}],
  "paths": {
    "/pets": {"get": {"operationId": "listPets"}, "post": {"operationId": "createPet"}},
    "/pets/{id}": {"delete": {"operationId": "deletePet",
      "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}]}}
  }
}`

// writeOpenAPIConfig writes spec and config files into one directory and
// loads the config. The config refers to the spec by a relative path.
func writeOpenAPIConfig(t *testing.T, spec, server string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	if spec != "" {
		if err := os.MkdirAll(filepath.Join(dir, "specs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "specs", "pets.json"), []byte(spec), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(dir, "mcpx.yaml")
	// JSON is valid YAML; it keeps these fixtures unambiguous.
	if err := os.WriteFile(cfgPath, []byte(`{"servers": [`+server+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(cfgPath)
}

func TestOpenAPIServerLoads(t *testing.T) {
	cfg, err := writeOpenAPIConfig(t, testSpec, `{
	  "name": "pets", "transport": "openapi",
	  "headers": {"Authorization": "Bearer x"},
	  "request_timeout": "5s",
	  "openapi": {"spec": "specs/pets.json", "methods": ["get", "POST"], "exclude_operations": ["create*"],
	              "max_response_bytes": 2048}}`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv := cfg.Servers[0]
	if srv.URL != "https://api.pets.example.com/v1" {
		t.Errorf("url not defaulted from the spec: %q", srv.URL)
	}
	o := srv.OpenAPI
	if o.Parsed == nil {
		t.Fatal("parsed spec not stored")
	}
	if !filepath.IsAbs(o.Spec) || !strings.HasSuffix(o.Spec, filepath.Join("specs", "pets.json")) {
		t.Errorf("spec path not resolved against the config dir: %q", o.Spec)
	}
	tools, err := o.Parsed.BuildTools(o.Filter())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "listPets" {
		t.Errorf("filter not applied: %v", tools)
	}
	if o.MaxResponseBytes != 2048 {
		t.Errorf("max_response_bytes = %d", o.MaxResponseBytes)
	}
}

func TestOpenAPIExplicitURLWins(t *testing.T) {
	cfg, err := writeOpenAPIConfig(t, testSpec, `{"name": "pets", "transport": "openapi",
	  "url": "http://localhost:9000/api", "openapi": {"spec": "specs/pets.json"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Servers[0].URL != "http://localhost:9000/api" {
		t.Errorf("url = %q", cfg.Servers[0].URL)
	}
}

func TestOpenAPIValidationErrors(t *testing.T) {
	noServers := strings.Replace(testSpec, `"servers": [{"url": "https://api.pets.example.com/v1"}],`, "", 1)
	relativeServer := strings.Replace(testSpec, "https://api.pets.example.com/v1", "/v1", 1)
	cases := []struct {
		name, spec, server, want string
	}{
		{"missing openapi section", testSpec, `{"name": "p", "transport": "openapi", "url": "https://x.example.com"}`, "openapi.spec is required"},
		{"openapi on http server", testSpec, `{"name": "p", "url": "https://x.example.com", "openapi": {"spec": "specs/pets.json"}}`, "only valid with transport \"openapi\""},
		{"missing spec file", "", `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json"}}`, "reading openapi spec"},
		{"invalid spec", `{"swagger": "2.0"}`, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json"}}`, "Swagger 2.0"},
		{"no base url", noServers, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json"}}`, "absolute http(s) base URL"},
		{"relative server url", relativeServer, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json"}}`, "absolute http(s) base URL"},
		{"stdio fields", testSpec, `{"name": "p", "transport": "openapi", "command": "x", "openapi": {"spec": "specs/pets.json"}}`, "only valid with transport \"stdio\""},
		{"bad method", testSpec, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json", "methods": ["FETCH"]}}`, "unknown HTTP method"},
		{"bad pattern", testSpec, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json", "include_operations": ["[x"]}}`, "invalid operation pattern"},
		{"filter leaves nothing", testSpec, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json", "include_tags": ["none"]}}`, "no operations left"},
		{"tls needs https", testSpec, `{"name": "p", "transport": "openapi", "url": "http://x.example.com", "tls": {"insecure_skip_verify": true}, "openapi": {"spec": "specs/pets.json"}}`, "tls requires an https"},
		{"bad header", testSpec, `{"name": "p", "transport": "openapi", "headers": {"Host": "x"}, "openapi": {"spec": "specs/pets.json"}}`, "managed by the proxy"},
		{"negative max bytes", testSpec, `{"name": "p", "transport": "openapi", "openapi": {"spec": "specs/pets.json", "max_response_bytes": -1}}`, "must not be negative"},
	}
	for _, c := range cases {
		_, err := writeOpenAPIConfig(t, c.spec, c.server)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

func TestLoadOpenAPISpecYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pets.yaml")
	doc := `openapi: 3.0.3
info:
  title: Pets
  version: "1.0"
servers:
  - url: https://api.pets.example.com
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        200:
          description: ok
`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := LoadOpenAPISpec(p)
	if err != nil {
		t.Fatalf("LoadOpenAPISpec: %v", err)
	}
	if spec.Title != "Pets" || spec.ServerURL != "https://api.pets.example.com" {
		t.Errorf("spec = %+v", spec)
	}
}

func TestJSONCompatibleStringifiesKeys(t *testing.T) {
	in := map[string]any{"responses": map[any]any{200: map[string]any{"x": []any{map[any]any{true: 1}}}}}
	want := map[string]any{"responses": map[string]any{"200": map[string]any{"x": []any{map[string]any{"true": 1}}}}}
	if got := jsonCompatible(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v", got)
	}
}
