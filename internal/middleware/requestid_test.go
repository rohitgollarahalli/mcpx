package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rohitgollarahalli/mcpx/internal/middleware"
)

func TestRequestID_GeneratesID(t *testing.T) {
	var capturedID string
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = middleware.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if capturedID == "" {
		t.Fatal("expected a generated request ID in context")
	}
	if len(capturedID) != 16 {
		t.Fatalf("expected 16-char hex ID, got %d chars: %s", len(capturedID), capturedID)
	}

	// Verify response header is set
	responseID := rec.Header().Get(middleware.HeaderRequestID)
	if responseID != capturedID {
		t.Fatalf("response header %q != context ID %q", responseID, capturedID)
	}
}

func TestRequestID_ReusesClientID(t *testing.T) {
	clientID := "client-trace-abc123"
	var capturedID string
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = middleware.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(middleware.HeaderRequestID, clientID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if capturedID != clientID {
		t.Fatalf("expected client ID %q, got %q", clientID, capturedID)
	}
	if rec.Header().Get(middleware.HeaderRequestID) != clientID {
		t.Fatal("expected client ID to be echoed in response")
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	ids := make(map[string]bool)
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := middleware.GetRequestID(r.Context())
		if ids[id] {
			t.Fatalf("duplicate request ID: %s", id)
		}
		ids[id] = true
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	if len(ids) != 100 {
		t.Fatalf("expected 100 unique IDs, got %d", len(ids))
	}
}

func TestGetRequestID_EmptyContext(t *testing.T) {
	id := middleware.GetRequestID(context.Background())
	if id != "" {
		t.Fatalf("expected empty string for context without request ID, got %q", id)
	}
}
