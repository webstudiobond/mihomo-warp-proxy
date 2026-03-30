package usermode

import (
	"os"
	"testing"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/config"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/fsutil"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
)

var testLog = logging.New(logging.LevelDebug, "test")

func testCfg(mihomoData, wgcfData string) *config.Config {
	return &config.Config{
		ProxyUID:      911,
		ProxyGID:      911,
		MultiUserMode: true,
		Paths: config.Paths{
			MihomoData:       mihomoData,
			WgcfData:         wgcfData,
			SuExecBin:        "/sbin/su-exec",
			MihomoConfigFile: mihomoData + "/config.yaml",
		},
	}
}

// --- nonRootLegacy ---

func TestNonRootLegacyWrongUID(t *testing.T) {
	// This test runs as the current user (not 911:911 in most dev environments).
	uid := os.Getuid()
	gid := os.Getgid()
	if uid == 911 && gid == 911 {
		t.Skip("test process is already 911:911")
	}

	err := nonRootLegacy(testLog)
	if err == nil {
		t.Error("expected error for non-911:911 uid in legacy mode, got nil")
	}
}

// --- nonRootMultiUser ---

func TestNonRootMultiUserMissingDir(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")

	err := nonRootMultiUser(cfg, testLog)
	if err == nil {
		t.Error("expected error when MihomoData does not exist, got nil")
	}
}

func TestNonRootMultiUserWritable(t *testing.T) {
	dir := t.TempDir()
	mihomoData := dir + "/mihomo"
	wgcfData := dir + "/wgcf"

	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wgcfData, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := testCfg(mihomoData, wgcfData)

	if err := nonRootMultiUser(cfg, testLog); err != nil {
		t.Errorf("unexpected error for writable dirs: %v", err)
	}

	// ProxyUID/GID must be updated to the current process identity.
	if cfg.ProxyUID != uint32(os.Getuid()) { // #nosec G115
		t.Errorf("ProxyUID not updated: got %d, want %d", cfg.ProxyUID, os.Getuid())
	}
	if cfg.ProxyGID != uint32(os.Getgid()) { // #nosec G115
		t.Errorf("ProxyGID not updated: got %d, want %d", cfg.ProxyGID, os.Getgid())
	}
}

// --- isDirWritable ---

func TestIsDirWritable(t *testing.T) {
	dir := t.TempDir()
	if !fsutil.IsDirWritable(dir) {
		t.Error("temp dir should be writable")
	}
	if fsutil.IsDirWritable("/proc/1") {
		t.Error("/proc/1 should not be writable")
	}
}

// --- isDirOwnedBy ---

func TestIsDirOwnedBy(t *testing.T) {
	dir := t.TempDir()
	uid := uint32(os.Getuid()) // #nosec G115
	gid := uint32(os.Getgid()) // #nosec G115

	if !isDirOwnedBy(dir, uid, gid) {
		t.Errorf("isDirOwnedBy: expected true for current uid:gid %d:%d", uid, gid)
	}
	if isDirOwnedBy(dir, uid+1, gid) {
		t.Error("isDirOwnedBy: expected false for wrong uid")
	}
	if isDirOwnedBy("/nonexistent", uid, gid) {
		t.Error("isDirOwnedBy: expected false for nonexistent path")
	}
}

// --- Dispatch: reexec path ---

func TestDispatchReexecSkipsAllBranches(t *testing.T) {
	cfg := testCfg(t.TempDir(), t.TempDir())
	// reexec=true must return nil immediately regardless of uid.
	if err := Dispatch(cfg, true, testLog); err != nil {
		t.Errorf("Dispatch with reexec=true returned error: %v", err)
	}
}
