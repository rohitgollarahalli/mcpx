package metrics

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// dashboardPath is the bundled Grafana dashboard, relative to this package.
const dashboardPath = "../../deploy/grafana/dashboards/mcpx.json"

var metricNameRe = regexp.MustCompile(`\bmcpx_[a-z_]+\b`)

// TestGrafanaDashboardMetricsExist guards the bundled Grafana dashboard
// against drift: every mcpx_* series a panel queries must actually be
// exposed by the collector. Renaming or removing a metric without updating
// deploy/grafana/dashboards/mcpx.json fails here instead of silently
// leaving an empty panel.
func TestGrafanaDashboardMetricsExist(t *testing.T) {
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}

	var dash map[string]any
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	if uid, _ := dash["uid"].(string); uid == "" {
		t.Error("dashboard must have a stable uid so provisioning and links keep working")
	}

	exprs := collectExprs(dash)
	if len(exprs) == 0 {
		t.Fatal("no PromQL expressions found in dashboard")
	}

	referenced := map[string]bool{}
	for _, e := range exprs {
		for _, name := range metricNameRe.FindAllString(e, -1) {
			referenced[name] = true
		}
	}

	exposed := exposedSeriesNames(t, populatedCollector())

	var missing []string
	for name := range referenced {
		if !exposed[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("dashboard queries metrics the collector does not expose: %s",
			strings.Join(missing, ", "))
	}
}

// TestGrafanaDashboardPanelsHaveUniqueIDs catches copy-paste mistakes that
// make Grafana silently drop or merge panels.
func TestGrafanaDashboardPanelsHaveUniqueIDs(t *testing.T) {
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	var dash struct {
		Panels []struct {
			ID    int    `json:"id"`
			Title string `json:"title"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	seen := map[int]string{}
	for _, p := range dash.Panels {
		if p.ID == 0 {
			t.Errorf("panel %q has no id", p.Title)
			continue
		}
		if prev, ok := seen[p.ID]; ok {
			t.Errorf("panels %q and %q share id %d", prev, p.Title, p.ID)
		}
		seen[p.ID] = p.Title
	}
}

// populatedCollector exercises every recording method so all metric
// families (including lazily created labelled ones) appear in the output.
func populatedCollector() *Collector {
	c := New()
	c.RecordRequest("fs", "tools/call", 200, 12*time.Millisecond)
	c.RecordRequest("fs", "tools/call", 503, 900*time.Millisecond)
	c.RecordToolCall("fs", "read_file", "allow", "ci-bot")
	c.RecordToolCall("fs", "delete_file", "deny", "")
	c.RecordAuthFailure()
	c.RecordRateLimitHit()
	c.RecordBreakerTrip()
	c.SetBreakerState("fs", 1)
	c.RecordCacheLookup("fs", "read_file", "hit")
	c.SetCacheStats(3, 1)
	c.IncrActiveConnections()
	c.SetServersRegistered(1)
	return c
}

// exposedSeriesNames scrapes the collector and returns every sample name.
func exposedSeriesNames(t *testing.T, c *Collector) map[string]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest("GET", "/metrics", nil))

	names := map[string]bool{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		names[name] = true
	}
	return names
}

// collectExprs walks the dashboard JSON and returns every PromQL string:
// panel target "expr" fields and templating query definitions.
func collectExprs(v any) []string {
	var out []string
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, val := range x {
				if s, ok := val.(string); ok && (k == "expr" || k == "definition") {
					out = append(out, s)
				}
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		}
	}
	walk(v)
	return out
}
