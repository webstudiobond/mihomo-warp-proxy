// Package wgcf manages the Cloudflare WARP WireGuard configuration lifecycle
// via the wgcf binary. It handles account registration, WARP+ key updates,
// profile generation, and parsing of the resulting WireGuard INI profile.
// Note: runWgcf logs CombinedOutput of the wgcf process. If a future version
// of wgcf echoes sensitive flags in its output, sanitizeOutput will not redact
// them — only the argument list is masked via redactArgs.
package wgcf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

// maxWgcfFileSize caps reads of wgcf-generated files to prevent OOM if an
// attacker replaces them with oversized content in the mounted volume.
const maxWgcfFileSize = 64 * 1024 // 64 KB — wgcf files are never larger than a few KB

// Profile holds the WireGuard parameters extracted from wgcf-profile.conf
// that are needed to populate the mihomo proxy block.
type Profile struct {
	PrivateKey string
	PublicKey  string
	// IPv4 and IPv6 are the interface addresses without CIDR notation.
	IPv4 string
	IPv6 string
}

// Setup ensures a valid wgcf account and WireGuard profile exist under
// cfg.Paths.WgcfData, creating or regenerating them as directed by cfg.
//
// Scenario matrix:
//
//	account  profile  WARP_REGENERATE  action
//	yes      yes      true             delete both → register → generate
//	yes      yes      false            update key if set → generate if key set
//	yes      no       any              update key if set → generate
//	no       any      any              register → update key if set → generate
func Setup(cfg *config.Config, log *logging.Logger) error {
	if err := os.MkdirAll(cfg.Paths.WgcfData, 0o750); err != nil {
		return fmt.Errorf("wgcf: create data directory %q: %w", cfg.Paths.WgcfData, err)
	}

	accountExists := fileExists(cfg.Paths.WgcfAccountFile)
	profileExists := fileExists(cfg.Paths.WgcfProfileFile)

	log.Debugf("wgcf: account exists=%v profile exists=%v regenerate=%v",
		accountExists, profileExists, cfg.Warp.Regenerate)

	if accountExists && profileExists && cfg.Warp.Regenerate {
		log.Debug("wgcf: WARP_REGENERATE=true, removing existing account and profile")
		if err := os.Remove(cfg.Paths.WgcfAccountFile); err != nil {
			return fmt.Errorf("wgcf: remove account file: %w", err)
		}
		if err := os.Remove(cfg.Paths.WgcfProfileFile); err != nil {
			return fmt.Errorf("wgcf: remove profile file: %w", err)
		}
		accountExists = false
		profileExists = false
	}

	if !accountExists {
		log.Debug("wgcf: registering new account")
		if err := register(cfg, log); err != nil {
			return err
		}
	}

	if cfg.Warp.PlusKey != "" {
		log.Debug("wgcf: applying WARP+ license key")
		if err := updateLicense(cfg, log); err != nil {
			// A failed license update is non-fatal: the free account still
			// functions. The error is logged by updateLicense itself.
			log.Warnf("wgcf: WARP+ key update failed, continuing with free account: %v", err)
		}
	}

	// Regenerate the profile when it is missing or when a WARP+ key was just
	// applied — the key change alters the account tier reflected in the profile.
	if !profileExists || cfg.Warp.PlusKey != "" {
		log.Debug("wgcf: generating WireGuard profile")
		if err := generate(cfg, log); err != nil {
			return err
		}
	}

	if err := secureFiles(cfg); err != nil {
		return err
	}

	return nil
}

// ParseProfile reads cfg.Paths.WgcfProfileFile and returns the extracted
// WireGuard parameters. The profile must already exist (call Setup first).
func ParseProfile(cfg *config.Config) (*Profile, error) {
	path := cfg.Paths.WgcfProfileFile

	perms, err := filePermissions(path)
	if err != nil {
		return nil, fmt.Errorf("wgcf: stat profile %q: %w", path, err)
	}
	if perms != 0o600 && perms != 0o400 {
		return nil, fmt.Errorf("wgcf: profile %q has unsafe permissions %04o (want 0o600 or 0o400)", path, perms)
	}

	// #nosec G304 -- Path is strictly internal (cfg.Paths.WgcfProfileFile) and
	// its permission boundaries are asserted directly above this call.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("wgcf: read profile %q: %w", path, err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only file

	data, err := io.ReadAll(io.LimitReader(f, maxWgcfFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("wgcf: read profile %q: %w", path, err)
	}
	if len(data) > maxWgcfFileSize {
		return nil, fmt.Errorf("wgcf: profile %q exceeds 64KB limit", path)
	}

	p, err := parseINI(string(data))
	if err != nil {
		return nil, fmt.Errorf("wgcf: parse profile %q: %w", path, err)
	}

	if err := validateProfile(p); err != nil {
		return nil, fmt.Errorf("wgcf: invalid profile %q: %w", path, err)
	}

	return p, nil
}

// register runs "wgcf register --accept-tos" in cfg.Paths.WgcfData.
func register(cfg *config.Config, log *logging.Logger) error {
	return runWgcf(cfg, log, "register", "--accept-tos")
}

// updateLicense runs "wgcf update --license-key KEY" in cfg.Paths.WgcfData.
func updateLicense(cfg *config.Config, log *logging.Logger) error {
	return runWgcf(cfg, log, "update", "--license-key", cfg.Warp.PlusKey)
}

// generate runs "wgcf generate" in cfg.Paths.WgcfData.
func generate(cfg *config.Config, log *logging.Logger) error {
	return runWgcf(cfg, log, "generate")
}

// runWgcf executes the wgcf binary with the given arguments. It changes the
// working directory to WgcfData because wgcf writes output files relative to
// cwd. Arguments are passed as a slice — never interpolated into a shell
// string — to prevent injection via cfg.Warp.PlusKey.
func runWgcf(cfg *config.Config, log *logging.Logger, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.Paths.WgcfBin, args...) // #nosec G204 -- args are validated; no untrusted input reaches this call
	cmd.Dir = cfg.Paths.WgcfData

	out, err := cmd.CombinedOutput()
	if err != nil {
		// Include captured output in the error so the operator can diagnose
		// wgcf failures without needing to re-run manually.
		return fmt.Errorf("wgcf %s: %w\noutput: %s",
			redactArgs(args), err, sanitizeOutput(out))
	}

	log.Debugf("wgcf %s: ok", redactArgs(args))
	return nil
}

// redactArgs returns a loggable representation of args with the value
// following --license-key replaced by a placeholder to prevent credential leaks.
func redactArgs(args []string) string {
	safe := make([]string, len(args))
	copy(safe, args)
	for i, arg := range safe {
		if arg == "--license-key" && i+1 < len(safe) {
			safe[i+1] = "***REDACTED***"
			break
		}
	}
	return strings.Join(safe, " ")
}

// secureFiles sets 0o600 permissions on the account and profile files.
// wgcf may create them with broader permissions depending on the system umask.
func secureFiles(cfg *config.Config) error {
	for _, path := range []string{cfg.Paths.WgcfAccountFile, cfg.Paths.WgcfProfileFile} {
		// #nosec G304 -- Paths are static constants strictly validated on startup.
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("wgcf: open %q: %w", path, err)
		}
		chmodErr := f.Chmod(0o600)
		_ = f.Close() //nolint:errcheck // close immediately in loop
		if chmodErr != nil {
			return fmt.Errorf("wgcf: chmod %q: %w", path, chmodErr)
		}
	}
	return nil
}

// parseINI extracts WireGuard profile fields from the INI-format content
// produced by wgcf. Only the fields needed by mihomo are extracted.
func parseINI(content string) (*Profile, error) {
	p := &Profile{}
	var currentSection string

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch {
		case currentSection == "Interface" && key == "PrivateKey":
			p.PrivateKey = value

		case currentSection == "Interface" && key == "Address":
			ipv4, ipv6, err := splitAddresses(value)
			if err != nil {
				return nil, fmt.Errorf("parse Address %q: %w", value, err)
			}
			p.IPv4 = ipv4
			p.IPv6 = ipv6

		case currentSection == "Peer" && key == "PublicKey":
			p.PublicKey = value
		}
	}

	return p, nil
}

// splitAddresses splits a comma-separated WireGuard Address field into
// individual IPv4 and IPv6 addresses, stripping CIDR notation.
// wgcf always produces exactly one IPv4 and one IPv6 address.
func splitAddresses(raw string) (ipv4, ipv6 string, err error) {
	for part := range strings.SplitSeq(raw, ",") {
		addr := strings.TrimSpace(part)
		// Strip CIDR mask.
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		if strings.Contains(addr, ":") {
			ipv6 = addr
		} else {
			ipv4 = addr
		}
	}
	if ipv4 == "" {
		return "", "", fmt.Errorf("no IPv4 address found in %q", raw)
	}
	if ipv6 == "" {
		return "", "", fmt.Errorf("no IPv6 address found in %q", raw)
	}
	return ipv4, ipv6, nil
}

// validateProfile checks that all required fields are present and have the
// expected format. WireGuard keys are 44-character base64 strings.
func validateProfile(p *Profile) error {
	if len(p.PrivateKey) != 44 {
		return fmt.Errorf("PrivateKey must be 44 characters, got %d", len(p.PrivateKey))
	}
	if len(p.PublicKey) != 44 {
		return fmt.Errorf("PublicKey must be 44 characters, got %d", len(p.PublicKey))
	}
	if p.IPv4 == "" {
		return errors.New("IPv4 address missing")
	}
	if p.IPv6 == "" {
		return errors.New("IPv6 address missing")
	}
	for _, r := range p.PrivateKey {
		if !isBase64Char(r) {
			return fmt.Errorf("PrivateKey contains invalid character %q", r)
		}
	}
	for _, r := range p.PublicKey {
		if !isBase64Char(r) {
			return fmt.Errorf("PublicKey contains invalid character %q", r)
		}
	}
	return nil
}

func isBase64Char(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '='
}

// fileExists returns true if path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// filePermissions returns the permission bits of path.
func filePermissions(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat file %q: %w", path, err)
	}
	return info.Mode().Perm(), nil
}

// sanitizeOutput trims and truncates wgcf command output for inclusion in
// error messages, preventing unbounded error string length.
func sanitizeOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	const limit = 512
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

// EndpointHost returns the hostname part of cfg.Warp.Endpoint.
func EndpointHost(cfg *config.Config) string {
	host, _, _ := strings.Cut(cfg.Warp.Endpoint, ":")
	return host
}

// EndpointPort returns the port part of cfg.Warp.Endpoint.
func EndpointPort(cfg *config.Config) string {
	_, port, _ := strings.Cut(cfg.Warp.Endpoint, ":")
	return port
}

// ProfilePath returns the absolute path to the wgcf profile file,
// resolved relative to WgcfData if not already absolute.
func ProfilePath(cfg *config.Config) string {
	return filepath.Join(cfg.Paths.WgcfData, "wgcf-profile.conf")
}
