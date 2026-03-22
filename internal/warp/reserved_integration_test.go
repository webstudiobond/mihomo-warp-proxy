//go:build integration

package warp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
)

// TestFetchReservedIntegration requires a real wgcf-account.toml produced by
// "wgcf register". Set WGCF_ACCOUNT_FILE env variable to the path of the file,
// or place it at ./testdata/wgcf-account.toml.
//
// Run with: go test -tags integration ./internal/warp/...
func TestFetchReservedIntegration(t *testing.T) {
	accountFile := os.Getenv("WGCF_ACCOUNT_FILE")
	if accountFile == "" {
		accountFile = filepath.Join("testdata", "wgcf-account.toml")
	}

	if _, err := os.Stat(accountFile); os.IsNotExist(err) {
		t.Skipf("account file not found at %q — skipping (set WGCF_ACCOUNT_FILE to override)", accountFile)
	}

	// Ensure permissions are acceptable before the test touches the file.
	if err := os.Chmod(accountFile, 0600); err != nil {
		t.Fatalf("chmod account file: %v", err)
	}

	log := logging.New(logging.LevelDebug, "test")

	reserved, err := FetchReserved(accountFile, log)
	if err != nil {
		t.Fatalf("FetchReserved failed: %v", err)
	}

	// All-zero result means the API returned a zero client_id, which is
	// technically valid but highly unlikely for a real registered device.
	if reserved == [3]byte{0, 0, 0} {
		t.Log("WARN: reserved bytes are all zero — verify account file is from a registered device")
	}

	t.Logf("reserved bytes: [%d, %d, %d]", reserved[0], reserved[1], reserved[2])
}
