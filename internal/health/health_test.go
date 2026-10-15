package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthyBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	checker := NewChecker([]ServerInfo{
		{Name: "test-server", URL: backend.URL},
	}, "0.1.0")

	report := checker.Check(context.Background())

	if report.Status != "healthy" {
		t.Errorf("expected healthy, got %s", report.Status)
	}
	if len(report.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(report.Servers))
	}
	if !report.Servers[0].Healthy {
		t.Error("expected server to be healthy")
	}
	if report.Servers[0].LatencyMs <= 0 {
		t.Error("expected positive latency")
	}
}

func TestUnhealthyBackend(t *testing.T) {
	checker := NewChecker([]ServerInfo{
		{Name: "dead-server", URL: "http://127.0.0.1:1"},
	}, "0.1.0")

	report := checker.Check(context.Background())

	if report.Status != "unhealthy" {
		t.Errorf("expected unhealthy, got %s", report.Status)
	}
	if report.Servers[0].Healthy {
		t.Error("expected server to be unhealthy")
	}
	if report.Servers[0].Error == "" {
		t.Error("expected error message")
	}
}

func TestDegradedStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	checker := NewChecker([]ServerInfo{
		{Name: "healthy-server", URL: backend.URL},
		{Name: "dead-server", URL: "http://127.0.0.1:1"},
	}, "0.1.0")

	report := checker.Check(context.Background())

	if report.Status != "degraded" {
		t.Errorf("expected degraded, got %s", report.Status)
	}
}

func TestPolicySummaryIncluded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	checker := NewChecker([]ServerInfo{
		{
			Name: "fs",
			URL:  backend.URL,
			Policy: &PolicySummary{
				AllowTools: []string{"read_file"},
				DenyTools:  []string{"delete_file"},
			},
		},
	}, "0.1.0")

	report := checker.Check(context.Background())

	if report.Servers[0].Policy == nil {
		t.Fatal("expected policy summary")
	}
	if len(report.Servers[0].Policy.AllowTools) != 1 || report.Servers[0].Policy.AllowTools[0] != "read_file" {
		t.Error("expected allow_tools to contain read_file")
	}
}

func TestHandlerReturns503WhenUnhealthy(t *testing.T) {
	checker := NewChecker([]ServerInfo{
		{Name: "dead", URL: "http://127.0.0.1:1"},
	}, "0.1.0")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	checker.Handler()(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var report Report
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if report.Status != "unhealthy" {
		t.Errorf("expected unhealthy status in body, got %s", report.Status)
	}
}

func TestVersionInReport(t *testing.T) {
	checker := NewChecker(nil, "1.2.3")
	report := checker.Check(context.Background())

	if report.Version != "1.2.3" {
		t.Errorf("expected version 1.2.3, got %s", report.Version)
	}
}

func TestNoServersIsHealthy(t *testing.T) {
	checker := NewChecker(nil, "0.1.0")
	report := checker.Check(context.Background())

	if report.Status != "healthy" {
		t.Errorf("expected healthy with no servers, got %s", report.Status)
	}
}

// TestProbeUsesServerTransport checks a backend's own transport (carrying
// its TLS trust settings) is used for the probe.
func TestProbeUsesServerTransport(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	c := NewChecker([]ServerInfo{
		{Name: "default", URL: backend.URL},
		{Name: "trusted", URL: backend.URL, Transport: backend.Client().Transport},
	}, "0.1.0")
	r := c.Check(context.Background())
	if r.Servers[0].Healthy {
		t.Error("probe without the backend's CA should fail verification")
	}
	if !r.Servers[1].Healthy {
		t.Errorf("probe with the backend's transport failed: %s", r.Servers[1].Error)
	}
}
