//go:build integration

package geo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/config"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
)

// TestPrepareGeoFilesIntegration downloads all four geo files from the default
// URLs and verifies they land on disk with correct permissions.
// Run with: go test -tags integration ./internal/geo/...
func TestPrepareGeoFilesIntegration(t *testing.T) {
	dir := t.TempDir()
	cacheSubDir := filepath.Join(dir, ".cache")

	cfg := &config.Config{
		Geo: config.GeoConfig{
			Enabled:    true,
			Redownload: true,
			URLs: config.GeoURLs{
				GeoIP:   "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
				GeoSite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
				MMDB:    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
				ASN:     "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
			},
		},
		Paths: config.Paths{
			MihomoData: dir,
		},
		Version: "test",
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := PrepareGeoFiles(cfg, log); err != nil {
		t.Fatalf("PrepareGeoFiles failed: %v", err)
	}

	expected := []string{
		filepath.Join(dir, "geoip.dat"),
		filepath.Join(dir, "geosite.dat"),
		filepath.Join(dir, "geoip.metadb"),
		filepath.Join(dir, "GeoLite2-ASN.mmdb"),
	}

	for _, f := range expected {
		info, err := os.Stat(f)
		if err != nil {
			t.Errorf("expected file not found: %s: %v", f, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file is empty: %s", f)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file %s has permissions %04o, want 0600", f, perm)
		}
	}

	// Cache metadata must have been written.
	entries, err := os.ReadDir(cacheSubDir)
	if err != nil {
		t.Fatalf("cache directory not created: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("expected 4 cache metadata files, got %d", len(entries))
	}

	// Second run must skip all downloads (ETag / Last-Modified match).
	cfg.Geo.Redownload = false
	if err := PrepareGeoFiles(cfg, log); err != nil {
		t.Fatalf("second PrepareGeoFiles failed: %v", err)
	}
}
