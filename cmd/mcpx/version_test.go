package main

import (
	"runtime/debug"
	"testing"
)

func TestBuildInfoVersion(t *testing.T) {
	vcs := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0123"},
		{Key: "vcs.time", Value: "2026-11-22T10:00:00Z"},
	}
	tests := []struct {
		name                string
		ldVersion           string
		bi                  *debug.BuildInfo
		wantV, wantC, wantD string
	}{
		{"ldflags win", "0.2.0", &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, "0.2.0", "none", "unknown"},
		{"go install tag", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}, Settings: vcs}, "0.2.0", "0123456", "2026-11-22T10:00:00Z"},
		{"local devel build", "dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs}, "dev", "0123456", "2026-11-22T10:00:00Z"},
		{"no build info", "dev", nil, "dev", "none", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, c, d := resolveVersion(tt.ldVersion, "none", "unknown", tt.bi)
			if v != tt.wantV || c != tt.wantC || d != tt.wantD {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", v, c, d, tt.wantV, tt.wantC, tt.wantD)
			}
		})
	}
}
