package scan

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSARIFVersionField(t *testing.T) {
	for _, tc := range []struct {
		version string
		semver  bool
	}{{"0.2.0", true}, {"dev", false}} {
		var buf bytes.Buffer
		r := &Report{Version: tc.version}
		if err := r.WriteSARIF(&buf); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver map[string]any `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		d := doc.Runs[0].Tool.Driver
		_, hasSem := d["semanticVersion"]
		if hasSem != tc.semver {
			t.Errorf("version %q: semanticVersion present=%v, want %v", tc.version, hasSem, tc.semver)
		}
		if d["version"] != tc.version {
			t.Errorf("version %q: driver.version=%v", tc.version, d["version"])
		}
	}
}
