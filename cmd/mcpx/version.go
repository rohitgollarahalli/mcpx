package main

import (
	"runtime/debug"
	"strings"
)

// resolveVersion fills in version metadata for builds that did not get
// GoReleaser's -ldflags (go install, go build, the from-source Dockerfile).
// Values set by ldflags always win. Otherwise the module version recorded by
// `go install module@vX.Y.Z` is used, and the VCS stamp supplies commit and
// date when present. A local build reports version "dev".
func resolveVersion(v, c, d string, bi *debug.BuildInfo) (string, string, string) {
	if v != "dev" || bi == nil {
		return v, c, d
	}
	if mv := bi.Main.Version; mv != "" && mv != "(devel)" {
		v = strings.TrimPrefix(mv, "v")
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if c == "none" && s.Value != "" {
				c = s.Value
				if len(c) > 7 {
					c = c[:7]
				}
			}
		case "vcs.time":
			if d == "unknown" && s.Value != "" {
				d = s.Value
			}
		}
	}
	return v, c, d
}

func init() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	version, commit, date = resolveVersion(version, commit, date, bi)
}
