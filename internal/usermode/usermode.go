// Package usermode handles the three container startup modes and the
// privilege-drop mechanism. The root branch replaces the current process
// via syscall.Exec(su-exec) so that mihomo ultimately runs under an
// unprivileged UID:GID with PID inherited from tini.
package usermode

import (
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/config"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
)

// knownFiles lists files in MihomoData whose ownership is updated on startup.
var knownFiles = []string{
	"config.yaml",
	"config.yaml.back",
	"cache.db",
	"geoip.dat",
	"geosite.dat",
	"geoip.metadb",
	"GeoLite2-ASN.mmdb",
}

// knownDirs lists subdirectories in MihomoData that are chowned recursively.
// These are created and owned entirely by the entrypoint — not user data.
var knownDirs = []string{
	".cache",
}

var knownWgcfFiles = []string{
	"wgcf-account.toml",
	"wgcf-profile.conf",
}

// Dispatch selects and executes the appropriate startup branch.
//
// When reexec is true the binary was invoked with --run-as-user by the root
// branch's su-exec call — skip directly to the caller's common tasks.
//
// Branch selection for non-reexec invocations:
//
//	root (uid 0)              → rootBranch  (never returns — calls syscall.Exec)
//	non-root + MultiUserMode  → nonRootMultiUser
//	non-root + !MultiUserMode → nonRootLegacy (only uid/gid 911:911 allowed)
func Dispatch(cfg *config.Config, reexec bool, log *logging.Logger) error {
	if reexec {
		return nil
	}

	if os.Getuid() == 0 {
		return rootBranch(cfg, log)
	}

	if cfg.MultiUserMode {
		return nonRootMultiUser(cfg, log)
	}

	return nonRootLegacy(log)
}

// rootBranch prepares directory ownership then replaces the current process
// with an unprivileged re-exec via su-exec. syscall.Exec never returns on
// success; a non-nil return value always indicates failure.
func rootBranch(cfg *config.Config, log *logging.Logger) error {
	log.Debugf("usermode: running as root, will drop to %d:%d", cfg.ProxyUID, cfg.ProxyGID)

	if err := prepareDirectories(cfg, log); err != nil {
		return err
	}

	// When MIHOMO_DATA is already owned by the target UID:GID the directory
	// was either mounted from the host with correct ownership or was already
	// prepared — chown would corrupt host-side file ownership in bind mounts.
	if isDirOwnedBy(cfg.Paths.MihomoData, cfg.ProxyUID, cfg.ProxyGID) {
		log.Debugf("usermode: %s already owned by %d:%d — skipping chown, re-execing",
			cfg.Paths.MihomoData, cfg.ProxyUID, cfg.ProxyGID)
	} else {
		if err := chownImageDirs(cfg, log); err != nil {
			return err
		}
	}

	return reexecAsUser(cfg, log)
}

// nonRootMultiUser allows any UID:GID as long as the process can write to the
// required directories. The effective UID/GID overrides PROXY_UID/GID so
// downstream packages use the actual runtime identity.
func nonRootMultiUser(cfg *config.Config, log *logging.Logger) error {
	uid := os.Getuid()
	gid := os.Getgid()

	if uid < 0 || int64(uid) > math.MaxUint32 || gid < 0 || int64(gid) > math.MaxUint32 {
		return fmt.Errorf("usermode: UID %d or GID %d is out of bounds for uint32", uid, gid)
	}
	log.Debugf("usermode: multi-user mode, running as %d:%d", uid, gid)

	if _, err := os.Stat(cfg.Paths.MihomoData); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("usermode: %s does not exist — mount the volume or run as root first", cfg.Paths.MihomoData)
		}
		return fmt.Errorf("usermode: stat %s: %w", cfg.Paths.MihomoData, err)
	}
	if _, err := os.Stat(cfg.Paths.WgcfData); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("usermode: %s does not exist — mount the volume or run as root first", cfg.Paths.WgcfData)
		}
		return fmt.Errorf("usermode: stat %s: %w", cfg.Paths.WgcfData, err)
	}

	if !isDirWritable(cfg.Paths.MihomoData) {
		return fmt.Errorf("usermode: no write access to %s — ensure the directory is owned by %d:%d",
			cfg.Paths.MihomoData, uid, gid)
	}
	if !isDirWritable(cfg.Paths.WgcfData) {
		return fmt.Errorf("usermode: no write access to %s — ensure the directory is owned by %d:%d",
			cfg.Paths.WgcfData, uid, gid)
	}

	cfg.ProxyUID = uint32(uid)
	cfg.ProxyGID = uint32(gid)
	return nil
}

// nonRootLegacy enforces the historical constraint that only uid/gid 911:911
// is accepted when MULTI_USER_MODE is disabled. This preserves backward
// compatibility for deployments that use --user=911:911 explicitly.
func nonRootLegacy(log *logging.Logger) error {
	uid := os.Getuid()
	gid := os.Getgid()

	if uid == 911 && gid == 911 {
		log.Debug("usermode: running as 911:911 (legacy mode)")
		return nil
	}

	return fmt.Errorf(
		"usermode: container started as %d:%d which is not allowed in legacy mode.\n"+
			"Allowed options:\n"+
			"  1) Run as root (no --user flag) — entrypoint drops privileges automatically\n"+
			"  2) Run as --user=911:911\n"+
			"  3) Set MULTI_USER_MODE=true to allow any UID:GID",
		uid, gid,
	)
}

// prepareDirectories creates MihomoData and WgcfData with secure permissions.
func prepareDirectories(cfg *config.Config, log *logging.Logger) error {
	for _, dir := range []string{cfg.Paths.MihomoData, cfg.Paths.WgcfData} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("usermode: mkdir %s: %w", dir, err)
		}
		log.Debugf("usermode: ensured directory %s", dir)
	}
	return nil
}

// chownImageDirs sets ownership of the image-internal directories and the
// known files within them to PROXY_UID:PROXY_GID.
func chownImageDirs(cfg *config.Config, log *logging.Logger) error {
	uid := int(cfg.ProxyUID)
	gid := int(cfg.ProxyGID)

	log.Debugf("usermode: setting ownership of image directories to %d:%d", uid, gid)

	for _, dir := range []string{cfg.Paths.MihomoData, cfg.Paths.WgcfData} {
		if err := os.Lchown(dir, uid, gid); err != nil {
			return fmt.Errorf("usermode: chown %s: %w", dir, err)
		}
	}

	for _, name := range knownFiles {
		path := cfg.Paths.MihomoData + "/" + name
		if _, err := os.Lstat(path); err == nil {
			if err := os.Lchown(path, uid, gid); err != nil {
				log.Warnf("usermode: chown %s: %v", path, err)
			}
		}
	}

	for _, name := range knownDirs {
		path := cfg.Paths.MihomoData + "/" + name
		if err := chownDirRecursive(path, uid, gid); err != nil {
			log.Warnf("usermode: chown %s: %v", path, err)
		}
	}

	for _, name := range knownWgcfFiles {
		path := cfg.Paths.WgcfData + "/" + name
		if _, err := os.Lstat(path); err == nil {
			if err := os.Lchown(path, uid, gid); err != nil {
				log.Warnf("usermode: chown %s: %v", path, err)
			}
		}
	}

	return nil
}

// reexecAsUser calls su-exec to replace the current process with an
// unprivileged instance of this binary. The --run-as-user flag signals the
// new instance to skip Dispatch and proceed directly to common tasks.
// syscall.Exec replaces the process image; on success it never returns.
func reexecAsUser(cfg *config.Config, log *logging.Logger) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("usermode: resolve executable path: %w", err)
	}

	suExec, err := exec.LookPath(cfg.Paths.SuExecBin)
	if err != nil {
		// Try the literal path from config before failing.
		if _, statErr := os.Stat(cfg.Paths.SuExecBin); statErr != nil {
			return fmt.Errorf("usermode: su-exec not found at %s: %w", cfg.Paths.SuExecBin, err)
		}
		suExec = cfg.Paths.SuExecBin
	}

	uidGid := fmt.Sprintf("%d:%d", cfg.ProxyUID, cfg.ProxyGID)
	args := []string{suExec, uidGid, self, "--run-as-user"}

	log.Debugf("usermode: re-execing as %s via su-exec", uidGid)

	// #nosec G204 -- suExec path and arguments are internally constructed from config.
	return syscall.Exec(suExec, args, config.FilterEnviron(os.Environ()))
}

// isDirOwnedBy returns true when the directory's owner matches uid:gid.
// Used to detect host-mounted volumes that the operator pre-chowned.
func isDirOwnedBy(dir string, uid, gid uint32) bool {
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == uid && stat.Gid == gid
}

// isDirWritable probes write access by creating and removing a temp file.
func isDirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".write_probe_*.tmp")
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	return true
}

// chownDirRecursive recursively sets ownership of dir and all its contents.
func chownDirRecursive(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}
		// #nosec G122 -- Lchown prevents symlink traversal; dir is exclusively controlled.
		return os.Lchown(path, uid, gid)
	})
}
