// Package config loads and validates all runtime configuration from environment
// variables. It is the single source of truth for variable names, defaults, and
// acceptable value ranges. All other packages receive a *Config — they never
// read os.Getenv directly.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
	"github.com/underhax/mihomo-warp-proxy/internal/validate"
)

// Paths groups filesystem locations that are fixed by the image layout.
// They are not user-configurable but are centralised here so every package
// references the same constants rather than scattering string literals.
type Paths struct {
	MihomoData       string
	MihomoConfigFile string
	WgcfData         string
	WgcfAccountFile  string
	WgcfProfileFile  string
	MihomoBin        string
	WgcfBin          string
	SuExecBin        string
	VersionFile      string
}

// GeoURLs holds the four geodata download endpoints.
type GeoURLs struct {
	GeoIP   string
	GeoSite string
	MMDB    string
	ASN     string
}

// GeoConfig controls geodata download behaviour.
type GeoConfig struct {
	URLs       GeoURLs
	AuthUser   string
	AuthPass   string
	Enabled    bool
	Redownload bool
	AutoUpdate bool
}

// AmneziaConfig holds AmneziaWG obfuscation parameters.
// JMin and JMax are only meaningful when Enabled is true; the validator
// enforces 0 <= JMin < JMax <= 1280 as required by the AmneziaWG spec.
type AmneziaConfig struct {
	// I1–I5 are AmneziaWG v2 init packet templates. Empty string means unused.
	I       [5]string
	JC      int
	JMin    int
	JMax    int
	Enabled bool
}

// WarpConfig controls Cloudflare WARP provisioning via wgcf.
type WarpConfig struct {
	// DNS is the parsed, validated list of DNS resolvers injected into the
	// mihomo WireGuard proxy block. Supports IPv4, IPv6, DoT, DoH, DoQ.
	DNS     []string
	PlusKey string
	// Endpoint is the validated "host:port" string for the WARP UDP endpoint.
	Endpoint   string
	Amnezia    AmneziaConfig
	Enabled    bool
	Regenerate bool
}

// Config is the fully parsed and validated runtime configuration.
// Zero values are never meaningful — always obtain via Load().
type Config struct {
	Paths         Paths
	TZ            string
	LogLevelStr   string
	ProxyLogLevel string
	ProxyUser     string
	ProxyPass     string
	Version       string
	Geo           GeoConfig
	Warp          WarpConfig
	ProxyUID      uint32
	ProxyGID      uint32
	ProxyPort     uint16
	MultiUserMode bool
	UseIP6        bool
}

// defaultPaths returns the fixed filesystem layout baked into the image.
func defaultPaths() Paths {
	return Paths{
		MihomoData:       "/app/mihomo",
		MihomoConfigFile: "/app/mihomo/config.yaml",
		WgcfData:         "/app/wgcf",
		WgcfAccountFile:  "/app/wgcf/wgcf-account.toml",
		WgcfProfileFile:  "/app/wgcf/wgcf-profile.conf",
		MihomoBin:        "/usr/local/bin/mihomo",
		WgcfBin:          "/usr/local/bin/wgcf",
		SuExecBin:        "/sbin/su-exec",
		VersionFile:      "/app/version",
	}
}

// Load reads all environment variables, applies defaults, and validates values.
// It returns a fully populated Config or an error describing the first
// validation failure. It never calls os.Exit.
func Load(version string) (*Config, error) {
	cfg := &Config{
		Paths:   defaultPaths(),
		Version: version,
	}

	if err := validatePaths(&cfg.Paths); err != nil {
		return nil, err
	}

	cfg.TZ = getEnv(contract.EnvTZ, "UTC")
	if err := validateTZ(cfg.TZ); err != nil {
		return nil, err
	}

	cfg.LogLevelStr = getEnv(contract.EnvScriptLogLevel, contract.LogLevelWarn)
	if err := validateScriptLogLevel(cfg.LogLevelStr); err != nil {
		return nil, err
	}
	cfg.LogLevelStr = strings.ToUpper(strings.TrimSpace(cfg.LogLevelStr))

	cfg.ProxyLogLevel = getEnv(contract.EnvProxyLogLevel, "info")
	if err := validateProxyLogLevel(cfg.ProxyLogLevel); err != nil {
		return nil, err
	}
	cfg.ProxyLogLevel = strings.ToLower(strings.TrimSpace(cfg.ProxyLogLevel))

	uid, err := parseUint32Env(contract.EnvProxyUID, "911", 1, 65535)
	if err != nil {
		return nil, err
	}
	cfg.ProxyUID = uid

	gid, err := parseUint32Env(contract.EnvProxyGID, "911", 1, 65535)
	if err != nil {
		return nil, err
	}
	cfg.ProxyGID = gid

	port, err := parseUint16Env(contract.EnvProxyPort, "7890", 1, 65535)
	if err != nil {
		return nil, err
	}
	cfg.ProxyPort = port

	cfg.ProxyUser = getEnv(contract.EnvProxyUser, "")
	cfg.ProxyPass = getEnv(contract.EnvProxyPass, "")
	err = validateCredentialPair(cfg.ProxyUser, cfg.ProxyPass)
	if err != nil {
		return nil, err
	}

	multiUser, err := parseBoolEnv(contract.EnvMultiUserMode, true)
	if err != nil {
		return nil, err
	}
	cfg.MultiUserMode = multiUser

	useIP6, err := parseBoolEnv(contract.EnvUseIP6, true)
	if err != nil {
		return nil, err
	}
	cfg.UseIP6 = useIP6

	geo, err := loadGeoConfig()
	if err != nil {
		return nil, err
	}
	cfg.Geo = geo

	warp, err := loadWarpConfig()
	if err != nil {
		return nil, err
	}
	cfg.Warp = warp

	return cfg, nil
}

// loadGeoConfig parses all GEO_* environment variables.
func loadGeoConfig() (GeoConfig, error) {
	var (
		g   GeoConfig
		err error
	)

	g.Enabled, err = parseBoolEnv(contract.EnvGeo, false)
	if err != nil {
		return g, err
	}

	g.Redownload, err = parseBoolEnv(contract.EnvGeoRedownload, false)
	if err != nil {
		return g, err
	}

	g.AutoUpdate, err = parseBoolEnv(contract.EnvGeoAutoUpdate, false)
	if err != nil {
		return g, err
	}

	g.URLs = GeoURLs{
		GeoIP:   getEnv(contract.EnvGeoURLGeoIP, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"),
		GeoSite: getEnv(contract.EnvGeoURLGeoSite, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
		MMDB:    getEnv(contract.EnvGeoURLMMDB, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"),
		ASN:     getEnv(contract.EnvGeoURLASN, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"),
	}

	for name, u := range map[string]string{
		contract.EnvGeoURLGeoIP:   g.URLs.GeoIP,
		contract.EnvGeoURLGeoSite: g.URLs.GeoSite,
		contract.EnvGeoURLMMDB:    g.URLs.MMDB,
		contract.EnvGeoURLASN:     g.URLs.ASN,
	} {
		if err := validateGeoURL(name, u); err != nil {
			return g, err
		}
	}

	g.AuthUser = getEnv(contract.EnvGeoAuthUser, "")
	g.AuthPass = getEnv(contract.EnvGeoAuthSecret, "")

	// Both or neither — a partial credential pair is a misconfiguration.
	if (g.AuthUser == "") != (g.AuthPass == "") {
		return g, errors.New(contract.EnvGeoAuthUser + " and " + contract.EnvGeoAuthSecret + " must both be set or both be empty")
	}

	if g.AuthUser != "" {
		if err := validateGeoCredential(contract.EnvGeoAuthUser, g.AuthUser); err != nil {
			return g, err
		}
		if err := validateGeoCredential(contract.EnvGeoAuthSecret, g.AuthPass); err != nil {
			return g, err
		}
	}

	return g, nil
}

// loadWarpConfig parses all WARP_* environment variables.
func loadWarpConfig() (WarpConfig, error) {
	var w WarpConfig

	enabled, err := parseBoolEnv(contract.EnvUseWarpConfig, true)
	if err != nil {
		return w, err
	}
	w.Enabled = enabled

	regenerate, err := parseBoolEnv(contract.EnvWarpRegenerate, false)
	if err != nil {
		return w, err
	}
	w.Regenerate = regenerate

	w.PlusKey = getEnv(contract.EnvWarpPlusKey, "")
	if w.PlusKey != "" {
		err = validateWarpPlusKey(w.PlusKey)
		if err != nil {
			return w, err
		}
	}

	w.Endpoint = getEnv(contract.EnvWarpEndpoint, "engage.cloudflareclient.com:500")
	err = validateWarpEndpoint(w.Endpoint)
	if err != nil {
		return w, err
	}

	dns, err := parseDNSList(getEnv(contract.EnvWarpDNS, "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"))
	if err != nil {
		return w, err
	}
	w.DNS = dns

	amnezia, err := loadAmneziaConfig()
	if err != nil {
		return w, err
	}
	w.Amnezia = amnezia

	return w, nil
}

// loadAmneziaConfig parses all WARP_AMNEZIA_* environment variables.
func loadAmneziaConfig() (AmneziaConfig, error) {
	var (
		a   AmneziaConfig
		err error
	)

	a.Enabled, err = parseBoolEnv(contract.EnvWarpAmnezia, false)
	if err != nil {
		return a, err
	}

	if !a.Enabled {
		return a, nil
	}

	a.JC, err = parseIntEnv(contract.EnvWarpAmneziaJC, "0", 0, 128)
	if err != nil {
		return a, err
	}

	a.JMin, err = parseIntEnv(contract.EnvWarpAmneziaJMin, "0", 0, 1280)
	if err != nil {
		return a, err
	}

	a.JMax, err = parseIntEnv(contract.EnvWarpAmneziaJMax, "0", 0, 1280)
	if err != nil {
		return a, err
	}

	// Cross-field constraint: jmin must be strictly less than jmax.
	if a.JMin >= a.JMax {
		return a, fmt.Errorf("%s (%d) must be less than %s (%d)", contract.EnvWarpAmneziaJMin, a.JMin, contract.EnvWarpAmneziaJMax, a.JMax)
	}

	for i := range a.I {
		name := fmt.Sprintf("%s%d", contract.EnvWarpAmneziaIPrefix, i+1)
		a.I[i] = getEnv(name, "")
	}

	for i, val := range a.I {
		name := fmt.Sprintf("%s%d", contract.EnvWarpAmneziaIPrefix, i+1)
		if err := validate.AmneziaIParam(name, val); err != nil {
			return a, fmt.Errorf("%s: %w", name, err)
		}
	}

	return a, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseBoolEnv(key string, def bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return def, nil
	}

	normalized := strings.ToLower(strings.TrimSpace(raw))
	if isTrueBoolEnvValue(normalized) {
		return true, nil
	}
	if isFalseBoolEnvValue(normalized) {
		return false, nil
	}
	return false, fmt.Errorf("%s: invalid boolean value %q (accepted: true/false/1/0/yes/no/on/off)", key, raw)
}

func isTrueBoolEnvValue(v string) bool {
	return v == "true" || v == "1" || v == "yes" || v == "on"
}

func isFalseBoolEnvValue(v string) bool {
	return v == "false" || v == "0" || v == "no" || v == "off"
}

func parseUint32Env(key, def string, minVal, maxVal uint32) (uint32, error) {
	raw := getEnv(key, def)
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer value %q", key, raw)
	}
	if v > math.MaxUint32 || v < uint64(minVal) || v > uint64(maxVal) {
		return 0, fmt.Errorf("%s: value %d out of range [%d, %d]", key, v, minVal, maxVal)
	}
	return uint32(v), nil
}

func parseUint16Env(key, def string, minVal, maxVal uint16) (uint16, error) {
	raw := getEnv(key, def)
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer value %q", key, raw)
	}
	if v > math.MaxUint16 || v < uint64(minVal) || v > uint64(maxVal) {
		return 0, fmt.Errorf("%s: value %d out of range [%d, %d]", key, v, minVal, maxVal)
	}
	return uint16(v), nil
}

func parseIntEnv(key, def string, minVal, maxVal int) (int, error) {
	raw := getEnv(key, def)
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer value %q", key, raw)
	}
	if v < minVal || v > maxVal {
		return 0, fmt.Errorf("%s: value %d out of range [%d, %d]", key, v, minVal, maxVal)
	}
	return v, nil
}

func validateScriptLogLevel(v string) error {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case contract.LogLevelDebug, contract.LogLevelInfo, contract.LogLevelWarn, contract.LogLevelError:
		return nil
	default:
		return fmt.Errorf("%s: invalid value %q (accepted: %s, %s, %s, %s)",
			contract.EnvScriptLogLevel,
			v,
			contract.LogLevelDebug,
			contract.LogLevelInfo,
			contract.LogLevelWarn,
			contract.LogLevelError,
		)
	}
}

func validateProxyLogLevel(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "silent", "error", "warning", "info", "debug":
		return nil
	default:
		return fmt.Errorf("%s: invalid value %q (accepted: silent, error, warning, info, debug)", contract.EnvProxyLogLevel, v)
	}
}

// validateCredentialPair enforces that both PROXY_USER and PROXY_PASS are
// always set. An unauthenticated proxy is a security risk — anonymous access
// is not permitted regardless of network topology.
func validateCredentialPair(user, pass string) error {
	userSet := user != ""
	passSet := pass != ""

	if !userSet && !passSet {
		return errors.New(contract.EnvProxyUser + " and " + contract.EnvProxyPass + " are required — an open unauthenticated proxy is a security risk; " +
			"generate credentials with: pwgen -s 64 1 && pwgen -s 128 1")
	}
	if userSet && !passSet {
		return errors.New(contract.EnvProxyPass + " must be set when " + contract.EnvProxyUser + " is provided")
	}
	if !userSet && passSet {
		return errors.New(contract.EnvProxyUser + " must be set when " + contract.EnvProxyPass + " is provided")
	}

	if err := validateMinLength(contract.EnvProxyUser, user, 8); err != nil {
		return err
	}
	if err := validateMinLength(contract.EnvProxyPass, pass, 32); err != nil {
		return err
	}
	if err := validateCredential(contract.EnvProxyUser, user, 64); err != nil {
		return err
	}
	if err := validateCredential(contract.EnvProxyPass, pass, 128); err != nil {
		return err
	}
	return validatePasswordComplexity(pass)
}

// validateMinLength enforces a minimum length for proxy credentials.
// Short credentials are trivially brute-forced; 32 characters for the
// password matches the minimum output of `pwgen -s 32 1`.
func validateMinLength(name, value string, minVal int) error {
	if len(value) < minVal {
		return fmt.Errorf("%s: minimum length is %d characters, got %d", name, minVal, len(value))
	}
	return nil
}

// validateCredential enforces length and character constraints on a single
// credential string. The colon restriction exists because HTTP Basic Auth
// encodes credentials as "user:pass" — a colon in the username would
// corrupt the boundary. Shell metacharacters and spaces are rejected to ensure
// safe interpolation in the Docker healthcheck CMD-SHELL — pwgen -s never
// produces these characters so legitimate credentials are unaffected.
func validateCredential(name, value string, maxLen int) error { //nolint:gocyclo // flat logic, splitting reduces readability
	if len(value) > maxLen {
		return fmt.Errorf("%s: value too long (max %d characters, got %d)", name, maxLen, len(value))
	}
	for i, r := range value {
		switch {
		case r == ':':
			return fmt.Errorf("%s: colon not allowed (position %d)", name, i)
		case r == '$' || r == '`' || r == '"' || r == '\'' || r == '\\' ||
			r == '!' || r == '&' || r == ';' || r == '|' || r == '<' || r == '>' || r == ' ':
			return fmt.Errorf("%s: shell metacharacter or space %q not allowed (position %d)", name, r, i)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%s: control character not allowed (position %d, value 0x%02x)", name, i, r)
		case r == 0x00:
			return fmt.Errorf("%s: null byte not allowed (position %d)", name, i)
		}
	}
	return nil
}

// passwordRequirements is the human-readable description of all PROXY_PASS
// constraints. Shown in full on any complexity failure so the user knows
// exactly what is required rather than discovering rules one by one.
const passwordRequirements = contract.EnvProxyPass + " requirements: " +
	"min 32 characters; " +
	"at least one uppercase letter (A-Z); " +
	"at least one lowercase letter (a-z); " +
	"at least one digit (0-9); " +
	"no run of more than 3 identical consecutive characters; " +
	"at least 12 distinct characters; " +
	`no spaces or shell metacharacters ($, ` + "`" + `, ", ', \, !, &, ;, |, <, >). ` +
	"Generate with: pwgen -s 128 1"

// validatePasswordComplexity enforces strength requirements for PROXY_PASS.
// All rules are evaluated together and a single message listing every
// requirement is returned on failure — the user is never left guessing which
// rule they violated.
//
// Rules (compatible with `pwgen -s` output):
//   - At least one uppercase letter (A-Z)
//   - At least one lowercase letter (a-z)
//   - At least one decimal digit (0-9)
//   - No run of more than 3 identical consecutive characters
//   - At least 12 distinct characters (prevents e.g. aaaa...A1)
func validatePasswordComplexity(pass string) error { //nolint:gocyclo // linear validation, splitting reduces readability
	var hasUpper, hasLower, hasDigit bool
	unique := make(map[rune]struct{})

	runes := []rune(pass)
	for i, r := range runes {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
		unique[r] = struct{}{}

		// Run detection: 4 or more identical consecutive characters.
		if i >= 3 && runes[i] == runes[i-1] && runes[i] == runes[i-2] && runes[i] == runes[i-3] {
			return fmt.Errorf("%s", passwordRequirements)
		}
	}

	if !hasUpper || !hasLower || !hasDigit || len(unique) < 12 {
		return fmt.Errorf("%s", passwordRequirements)
	}
	return nil
}

// validateWarpEndpoint checks that the endpoint is "engage.cloudflareclient.com:PORT"
// where PORT is one of the four UDP ports supported by Cloudflare WARP.
// Restricting to a single hostname prevents the WARP credentials from being
// sent to an attacker-controlled endpoint.
func validateWarpEndpoint(endpoint string) error {
	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon < 0 {
		return fmt.Errorf("%s: missing port in %q", contract.EnvWarpEndpoint, endpoint)
	}
	host := endpoint[:lastColon]
	port := endpoint[lastColon+1:]

	const warpEndpointRequirements = contract.EnvWarpEndpoint + " requirements: host must be engage.cloudflareclient.com; port must be one of: 2408, 500, 1701, 4500"

	validPort := port == "2408" || port == "500" || port == "1701" || port == "4500"
	validHost := host == "engage.cloudflareclient.com"

	if !validHost || !validPort {
		return fmt.Errorf("%s — got host %q port %q", warpEndpointRequirements, host, port)
	}
	return nil
}

// parseDNSList splits a comma-separated DNS string and validates each entry.
func parseDNSList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New(contract.EnvWarpDNS + ": must not be empty")
	}

	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))

	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			continue
		}
		if !isValidDNSEntry(entry) {
			return nil, fmt.Errorf("%s: invalid entry %q (accepted: IPv4, IPv6, tls://, https://, quic://)", contract.EnvWarpDNS, entry)
		}
		result = append(result, entry)
	}

	if len(result) == 0 {
		return nil, errors.New(contract.EnvWarpDNS + ": no valid entries found")
	}
	if len(result) > 8 {
		return nil, fmt.Errorf("%s: too many entries (max 8, got %d)", contract.EnvWarpDNS, len(result))
	}

	return result, nil
}

// isValidDNSEntry returns true for IPv4 addresses, IPv6 addresses, and the
// encrypted DNS URI schemes supported by mihomo (DoT, DoH, DoQ).
func isValidDNSEntry(s string) bool {
	switch {
	case strings.HasPrefix(s, "tls://"):
		return true
	case strings.HasPrefix(s, "https://"):
		return true
	case strings.HasPrefix(s, "quic://"):
		return true
	case strings.Contains(s, ":"):
		for _, r := range s {
			if !isHexOrColon(r) {
				return false
			}
		}
		return true
	default:
		return isIPv4(s)
	}
}

func isHexOrColon(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') ||
		(r >= 'A' && r <= 'F') || r == ':'
}

// isIPv4 performs a strict four-octet validation without using net.ParseIP so
// that the config package has no dependency on the network stack.
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func validateTZ(tz string) error {
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("%s: invalid timezone %q: %w", contract.EnvTZ, tz, err)
	}
	return nil
}

// warpPlusKeyRe matches the Cloudflare WARP+ license key format:
// four groups of 8 hex characters separated by hyphens.
var warpPlusKeyRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}$`)

func validateWarpPlusKey(key string) error {
	if !warpPlusKeyRe.MatchString(key) {
		return fmt.Errorf("%s: invalid format %q (expected: xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx where x is a hex digit)", contract.EnvWarpPlusKey, key)
	}
	return nil
}

func validateGeoURL(name, rawURL string) error {
	if !strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		return fmt.Errorf("%s: only HTTPS URLs are allowed, got %q", name, rawURL)
	}
	return nil
}

// validateGeoCredential enforces character constraints on GEO auth credentials.
// Prevents injection via HTTP Basic Auth headers and URL embedding.
func validateGeoCredential(name, value string) error {
	if len(value) > 256 {
		return fmt.Errorf("%s: value too long (max 256 characters, got %d)", name, len(value))
	}
	for i, r := range value {
		switch {
		case r == ':' || r == '@':
			return fmt.Errorf("%s: character %q not allowed (position %d)", name, r, i)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%s: control character not allowed (position %d)", name, i)
		case r == 0x00:
			return fmt.Errorf("%s: null byte not allowed (position %d)", name, i)
		case r == ' ':
			return fmt.Errorf("%s: whitespace not allowed (position %d)", name, i)
		}
	}
	return nil
}

// FilterEnviron removes sensitive credentials from the environment slice
// before passing it to subprocesses (wgcf, mihomo). This prevents credential
// leakage through process listing or accidental logging by child processes.
func FilterEnviron(environ []string) []string {
	clean := make([]string, 0, len(environ))
	for _, e := range environ {
		if key, _, ok := strings.Cut(e, "="); ok {
			switch key {
			// Proxy credentials, WARP+ license key, and geo auth must never
			// reach child processes — they have no need for these values and
			// exposing them would increase the attack surface.
			case contract.EnvProxyPass, contract.EnvGeoAuthUser, contract.EnvGeoAuthSecret, contract.EnvWarpPlusKey:
				continue
			}
		}
		clean = append(clean, e)
	}
	return clean
}

// validatePaths ensures all core filesystem locations pass security boundaries,
// providing defense-in-depth if these paths ever become user-configurable.
func validatePaths(p *Paths) error {
	paths := []struct {
		name string
		path string
	}{
		{"MihomoData", p.MihomoData},
		{"MihomoConfigFile", p.MihomoConfigFile},
		{"WgcfData", p.WgcfData},
		{"WgcfAccountFile", p.WgcfAccountFile},
		{"WgcfProfileFile", p.WgcfProfileFile},
		{"MihomoBin", p.MihomoBin},
		{"WgcfBin", p.WgcfBin},
		{"SuExecBin", p.SuExecBin},
		{"VersionFile", p.VersionFile},
	}
	for _, target := range paths {
		if err := validate.Path(target.path, target.name); err != nil {
			return fmt.Errorf("path validation: %w", err)
		}
	}
	return nil
}
