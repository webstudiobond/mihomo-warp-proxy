// Command entrypoint is the container init process for mihomo-warp-proxy.
// It runs under tini (PID 1), performs all setup, then replaces itself with
// the mihomo binary via syscall.Exec. The process tree is:
//
//	tini → entrypoint [--run-as-user] → (su-exec →) entrypoint --run-as-user → mihomo
//
// The --run-as-user flag is set by the root branch after su-exec drops
// privileges, signalling this instance to skip Dispatch and go straight to
// common tasks.
package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/backup"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/config"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/geo"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/mihomo"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/usermode"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/warp"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/wgcf"
)

// version is set at build time via -ldflags="-X main.version=<ver>".
var version = "dev"

func main() {
	reexec := len(os.Args) > 1 && os.Args[1] == "--run-as-user"

	// Bootstrap with WARN level until Config is loaded and the operator's
	// chosen level is known. Version is injected at build time via
	// -ldflags "-X main.version=..." — no version file in the image.
	log := logging.New(logging.LevelWarn, version)

	cfg, err := config.Load(version)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	// Reinitialise logger at the operator-configured level.
	level, err := logging.ParseLevel(cfg.LogLevelStr)
	if err != nil {
		log.Warnf("%v — using WARN", err)
		level = logging.LevelWarn
	}
	log = logging.New(level, version)

	log.Debugf("configuration loaded: port=%d warp=%v geo=%v", cfg.ProxyPort, cfg.Warp.Enabled, cfg.Geo.Enabled)

	log.Debugf("entrypoint starting (version %s, reexec=%v)", version, reexec)

	if err := usermode.Dispatch(cfg, reexec, log); err != nil {
		log.Fatalf("usermode: %v", err)
	}

	// From this point the process runs as PROXY_UID:PROXY_GID.

	if err := backup.ConfigFile(cfg.Paths.MihomoConfigFile); err != nil {
		// A failed backup is not fatal — mihomo can still start. The operator
		// is warned so they know the safety net is absent for this run.
		log.Warnf("config backup failed: %v", err)
	} else {
		log.Debugf("config backup created: %s.back", cfg.Paths.MihomoConfigFile)
	}

	if err := runCommonTasks(cfg, log); err != nil {
		log.Fatalf("%v", err)
	}

	execMihomo(cfg, log)
}

// runCommonTasks performs geo download and WARP provisioning in sequence.
// It is called both from the re-execed unprivileged instance and from
// non-root startup paths.
func runCommonTasks(cfg *config.Config, log *logging.Logger) error {
	if cfg.Geo.Enabled {
		log.Debug("starting geo file preparation")
		if err := geo.PrepareGeoFiles(cfg, log); err != nil {
			return fmt.Errorf("geo: %w", err)
		}
		log.Debug("geo file preparation complete")
	}

	if cfg.Warp.Enabled {
		log.Debug("starting warp setup")
		return runWarpSetup(cfg, log)
	}

	log.Debug("warp disabled — ensuring minimal mihomo config")
	return mihomo.EnsureConfig(cfg, nil, [3]byte{}, log)
}

// runWarpSetup provisions the WARP account, parses the profile, optionally
// fetches reserved bytes, then updates the mihomo config.
func runWarpSetup(cfg *config.Config, log *logging.Logger) error {
	if err := wgcf.Setup(cfg, log); err != nil {
		return fmt.Errorf("wgcf setup: %w", err)
	}
	log.Debug("wgcf setup complete")

	profile, err := wgcf.ParseProfile(cfg)
	if err != nil {
		return fmt.Errorf("wgcf parse profile: %w", err)
	}

	var reserved [3]byte
	r, err := warp.FetchReserved(cfg.Paths.WgcfAccountFile, log)
	if err != nil {
		// Non-fatal: mihomo works without reserved bytes.
		log.Warnf("could not fetch WARP reserved bytes: %v", err)
	} else {
		reserved = r
	}

	return mihomo.EnsureConfig(cfg, profile, reserved, log)
	// ensureConfig logs internally
}

// execMihomo replaces the current process with the mihomo binary.
// This call never returns on success.
func execMihomo(cfg *config.Config, log *logging.Logger) {
	args := []string{
		cfg.Paths.MihomoBin,
		"-d", cfg.Paths.MihomoData,
		"-f", cfg.Paths.MihomoConfigFile,
	}

	log.Debugf("exec: %v", args)

	// #nosec G204 -- Arguments are strictly constructed from statically validated
	// internal constants and safe configuration values. No untrusted input is passed.
	if err := syscall.Exec(cfg.Paths.MihomoBin, args, config.FilterEnviron(os.Environ())); err != nil {
		log.Fatalf("exec mihomo: %v", err)
	}
}
