package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/auth"
	"github.com/rohitgollarahalli/mcpx/internal/config"
)

// clientCapture records the client identity the middleware put in context.
func clientCapture(got *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = auth.ClientFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddleware_NamedClients(t *testing.T) {
	cfg := config.AuthConfig{
		Enabled: true,
		Type:    "bearer",
		Token:   "legacy-token",
		Clients: []config.ClientCredential{
			{Name: "ci-bot", Token: "tok-ci"},
			{Name: "analyst", Token: "tok-an"},
		},
	}

	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantClient string
	}{
		{"named client 1", "tok-ci", http.StatusOK, "ci-bot"},
		{"named client 2", "tok-an", http.StatusOK, "analyst"},
		{"legacy token maps to default", "legacy-token", http.StatusOK, "default"},
		{"unknown token rejected", "tok-nope", http.StatusUnauthorized, ""},
		{"empty token rejected", "", http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			h := auth.Middleware(cfg)(clientCapture(&got))
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got != tt.wantClient {
				t.Errorf("client = %q, want %q", got, tt.wantClient)
			}
		})
	}
}

func TestMiddleware_NamedClients_APIKey(t *testing.T) {
	cfg := config.AuthConfig{
		Enabled: true,
		Type:    "api_key",
		Clients: []config.ClientCredential{{Name: "ci-bot", Token: "key-ci"}},
	}
	var got string
	h := auth.Middleware(cfg)(clientCapture(&got))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-API-Key", "key-ci")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || got != "ci-bot" {
		t.Fatalf("status = %d, client = %q; want 200, ci-bot", rec.Code, got)
	}

	// No token configured at all: empty presented key must NOT authenticate.
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty key should 401, got %d", rec.Code)
	}
}

func TestClientFrom_NoIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if got := auth.ClientFrom(req.Context()); got != "" {
		t.Fatalf("expected empty client on bare context, got %q", got)
	}
}
