package config

import (
	"context"
	"os"
	"time"
)

// ReloadFunc is invoked with a freshly loaded, validated config
// whenever the watched file changes. If it returns an error, the
// watcher logs it (via the caller's onError) and keeps watching.
type ReloadFunc func(*Config) error

// Watch polls the config file for modifications and calls onReload
// with a freshly validated Config each time the file changes on disk.
//
// Polling is used (instead of fsnotify) to preserve mcpx's zero-dependency
// promise. The default interval is 2 seconds when interval <= 0.
//
// Watch blocks until ctx is cancelled. Load errors are reported via
// onError but do not stop the watcher — a broken config should not
// take down a running gateway.
func Watch(ctx context.Context, path string, interval time.Duration, onReload ReloadFunc, onError func(error)) {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	lastMod, lastSize := statSnapshot(path)
	// failedMod/failedSize remember a version that failed to load, so it is
	// retried every tick (a spec URL may come back) but logged only once.
	var failedMod time.Time
	var failedSize int64 = -1

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mod, size := statSnapshot(path)
			if mod.Equal(lastMod) && size == lastSize {
				continue
			}

			// A save that truncates before writing can be seen as an empty
			// file, which would parse as a valid config with no servers.
			// Wait for content instead of reloading it.
			if size == 0 {
				continue
			}

			cfg, err := Load(path)
			// If the file changed while it was being read, the read may
			// have seen a partial write. Retry on the next tick.
			if mod2, size2 := statSnapshot(path); !mod2.Equal(mod) || size2 != size {
				continue
			}
			if err != nil {
				if onError != nil && (!mod.Equal(failedMod) || size != failedSize) {
					onError(err)
				}
				failedMod, failedSize = mod, size
				continue
			}
			lastMod, lastSize = mod, size
			failedSize = -1
			if err := onReload(cfg); err != nil {
				if onError != nil {
					onError(err)
				}
			}
		}
	}
}

// statSnapshot returns the file mtime and size, or zero values if the
// file is missing. Missing files are treated as "unchanged" so that a
// transient rename-during-write (common editor pattern) does not flap.
func statSnapshot(path string) (time.Time, int64) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, 0
	}
	return fi.ModTime(), fi.Size()
}
