// Package health provides deep health checking for mcpx and its backends.
//
// Unlike the basic /health endpoint, this package probes each registered
// backend server and reports individual status, latency, and capabilities.
// Useful for dashboards, alerting, and debugging connectivity issues.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Status represents the health of a single backend server.
type Status struct {
	Name      string         `json:"name"`
	URL       string         `json:"url"`
	Healthy   bool           `json:"healthy"`
	LatencyMs float64        `json:"latency_ms,omitempty"`
	Error     string         `json:"error,omitempty"`
	CheckedAt time.Time      `json:"checked_at"`
	Policy    *PolicySummary `json:"policy,omitempty"`
}

// PolicySummary is a brief view of the policy applied to a server.
type PolicySummary struct {
	ReadOnly   bool     `json:"read_only,omitempty"`
	AllowTools []string `json:"allow_tools,omitempty"`
	DenyTools  []string `json:"deny_tools,omitempty"`
}

// Report is the full health check response.
type Report struct {
	Status    string    `json:"status"` // "healthy", "degraded", "unhealthy"
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime"`
	Servers   []Status  `json:"servers"`
	Timestamp time.Time `json:"timestamp"`
}

// ServerInfo holds the info needed to probe a backend. Probe, when set,
// replaces the default HTTP GET — backends without a URL to poke (stdio
// child processes) report their health through it.
type ServerInfo struct {
	Name   string
	URL    string
	Policy *PolicySummary
	Probe  func(ctx context.Context) error
	// Transport, when set, carries the backend's TLS settings (private CA,
	// client certificate) for the default HTTP probe.
	Transport http.RoundTripper
}

// Checker performs health checks against registered backends.
type Checker struct {
	servers   []ServerInfo
	version   string
	startTime time.Time
	client    *http.Client
}

// NewChecker creates a Checker for the given backend servers.
func NewChecker(servers []ServerInfo, version string) *Checker {
	return &Checker{
		servers:   servers,
		version:   version,
		startTime: time.Now(),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Check probes all backends concurrently and returns a Report.
func (c *Checker) Check(ctx context.Context) Report {
	statuses := make([]Status, len(c.servers))
	var wg sync.WaitGroup

	for i, srv := range c.servers {
		wg.Add(1)
		go func(idx int, s ServerInfo) {
			defer wg.Done()
			statuses[idx] = c.probe(ctx, s)
		}(i, srv)
	}
	wg.Wait()

	// Determine overall status
	overall := "healthy"
	unhealthyCount := 0
	for _, s := range statuses {
		if !s.Healthy {
			unhealthyCount++
		}
	}
	if unhealthyCount == len(statuses) && len(statuses) > 0 {
		overall = "unhealthy"
	} else if unhealthyCount > 0 {
		overall = "degraded"
	}

	uptime := time.Since(c.startTime)
	return Report{
		Status:    overall,
		Version:   c.version,
		Uptime:    formatDuration(uptime),
		Servers:   statuses,
		Timestamp: time.Now().UTC(),
	}
}

// probe checks a single backend by making an HTTP request.
func (c *Checker) probe(ctx context.Context, srv ServerInfo) Status {
	start := time.Now()
	status := Status{
		Name:      srv.Name,
		URL:       srv.URL,
		CheckedAt: time.Now().UTC(),
		Policy:    srv.Policy,
	}

	if srv.Probe != nil {
		if err := srv.Probe(ctx); err != nil {
			status.Error = err.Error()
			return status
		}
		status.Healthy = true
		status.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
		return status
	}

	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("invalid url: %v", err)
		return status
	}

	client := c.client
	if srv.Transport != nil {
		client = &http.Client{Timeout: c.client.Timeout, Transport: srv.Transport}
	}
	resp, err := client.Do(req)
	latency := time.Since(start)
	status.LatencyMs = float64(latency.Microseconds()) / 1000.0

	if err != nil {
		status.Error = fmt.Sprintf("unreachable: %v", err)
		return status
	}
	defer resp.Body.Close()

	// Any response means the server is alive
	status.Healthy = true
	if resp.StatusCode >= 500 {
		status.Healthy = false
		status.Error = fmt.Sprintf("server error: %d", resp.StatusCode)
	}

	return status
}

// Handler returns an http.HandlerFunc for the deep health endpoint.
func (c *Checker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := c.Check(r.Context())

		w.Header().Set("Content-Type", "application/json")
		switch report.Status {
		case "unhealthy":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "degraded":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	}
}

// formatDuration produces a human-readable duration string.
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
