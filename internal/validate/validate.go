// Package validate provides input validation functions used across the
// entrypoint. Each function is pure (no side effects, no I/O) so the full
// validation suite can be exercised in unit tests without a live environment.
package validate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// Path validates that p is safe to use as a filesystem path in this container.
// It rejects relative paths, directory traversal, control characters, and
// paths that resolve into kernel or container-runtime pseudo-filesystems.
// realpath-style canonicalisation is intentionally avoided here — callers that
// need symlink resolution must do so explicitly before calling this function.
func Path(p, name string) error {
	if p == "" {
		return fmt.Errorf("%s: path must not be empty", name)
	}

	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s: path must be absolute, got %q", name, p)
	}

	// Null bytes terminate C strings and bypass many path checks in the kernel.
	if strings.ContainsRune(p, 0x00) {
		return fmt.Errorf("%s: path contains null byte", name)
	}

	// Control characters other than null are equally dangerous in paths.
	for i, r := range p {
		if r < 0x20 && r != 0x00 {
			return fmt.Errorf("%s: path contains control character at position %d (0x%02x)", name, i, r)
		}
	}

	// filepath.Clean resolves ".." components. If the cleaned path differs from
	// the input only by a trailing slash, that is harmless; any other difference
	// means traversal sequences were present.
	cleaned := filepath.Clean(p)
	if cleaned != p && cleaned+"/" != p {
		return fmt.Errorf("%s: path contains traversal sequences: %q -> %q", name, p, cleaned)
	}

	// Whitespace in paths causes silent split bugs in any code that passes
	// paths as space-delimited strings (e.g. to external tools).
	if strings.ContainsAny(p, " \t\r\n") {
		return fmt.Errorf("%s: path contains whitespace: %q", name, p)
	}

	if len(p) > 4096 {
		return fmt.Errorf("%s: path exceeds maximum length (4096), got %d", name, len(p))
	}

	// Block paths into pseudo-filesystems and container runtime sockets.
	// Access to these from within the container entrypoint is never legitimate.
	restricted := []string{
		"/proc", "/sys", "/dev",
		"/run",
		"/var/run/docker.sock",
		"/var/run/containerd",
		"/.dockerenv",
	}
	for _, rPath := range restricted {
		if cleaned == rPath || strings.HasPrefix(cleaned, rPath+"/") {
			return fmt.Errorf("%s: path targets restricted location: %q", name, cleaned)
		}
	}

	return nil
}

// IsRestrictedIP returns true when ip must not be contacted from this process.
// Uses standard library methods as the primary gate, with manual checks only
// for ranges intentionally excluded from the Go standard library.
func IsRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// IsPrivate covers RFC 1918 (IPv4) and RFC 4193 (IPv6 ULA fc00::/7).
	// !IsGlobalUnicast covers everything else that is not a routable public
	// address: loopback, link-local, multicast, unspecified, broadcast.
	if ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return true
	}

	// CGNAT 100.64.0.0/10 — intentionally excluded from net.IP.IsPrivate()
	// by the Go standard library; must be checked manually.
	// ip.To4() unwraps IPv4-mapped IPv6 addresses automatically.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}

	// fec0::/10 deprecated IPv6 site-local — not reliably caught by
	// !IsGlobalUnicast() across all Go versions; explicit check required.
	if ip16 := ip.To16(); ip16 != nil && ip16[0] == 0xfe && ip16[1]&0xc0 == 0xc0 {
		return true
	}

	return false
}

// ResolveAndValidate resolves hostname to IP addresses and verifies that none
// of the results map to a restricted range. It is called before every outbound
// HTTP connection to prevent SSRF via DNS rebinding or internal hostname tricks.
// An empty result set (NXDOMAIN or no A/AAAA records) is treated as an error
// because proceeding with an unresolvable host would silently skip the check.
func ResolveAndValidate(hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %q: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses resolved for %q", hostname)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("DNS returned unparseable address %q for %q", addr, hostname)
		}
		if IsRestrictedIP(ip) {
			return fmt.Errorf("hostname %q resolves to restricted IP %s", hostname, addr)
		}
	}
	return nil
}

// AmneziaIParam validates the AmneziaWG v2 init-packet template syntax used
// in WARP_AMNEZIA_I1–I5. The format is a sequence of typed tags; any
// unrecognised token or out-of-range numeric is rejected to prevent garbage
// values from being written into the mihomo config.
//
// Accepted tags:
//
//	<b 0xHEX>   static bytes (arbitrary hex length)
//	<c>         32-bit packet counter (network byte order)
//	<t>         32-bit Unix timestamp (network byte order)
//	<r N>       N random bytes, 0 <= N <= 1000
//	<wt N>      wait N ms, 0 <= N <= 5000
func AmneziaIParam(name, val string) error {
	if val == "" {
		return nil
	}
	if len(val) > 10000 {
		return fmt.Errorf("%s: value too long (%d characters, max 10000)", name, len(val))
	}

	rest := val
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "<b 0x"):
			end := strings.Index(rest, ">")
			if end < 0 {
				return fmt.Errorf("%s: unclosed <b> tag in %q", name, truncate(rest))
			}
			hex := rest[len("<b 0x"):end]
			if err := validateHex(hex); err != nil {
				return fmt.Errorf("%s: <b> tag: %w", name, err)
			}
			rest = rest[end+1:]

		case strings.HasPrefix(rest, "<c>"):
			rest = rest[len("<c>"):]

		case strings.HasPrefix(rest, "<t>"):
			rest = rest[len("<t>"):]

		case strings.HasPrefix(rest, "<r "):
			tail, err := parseTagNumeric(rest, "<r ", 0, 1000)
			if err != nil {
				return fmt.Errorf("%s: <r> tag: %w", name, err)
			}
			rest = tail

		case strings.HasPrefix(rest, "<wt "):
			tail, err := parseTagNumeric(rest, "<wt ", 0, 5000)
			if err != nil {
				return fmt.Errorf("%s: <wt> tag: %w", name, err)
			}
			rest = tail

		default:
			return fmt.Errorf("%s: unrecognised token at %q", name, truncate(rest))
		}
	}
	return nil
}

// parseTagNumeric parses a tag of the form "<prefix N>". It validates the
// numeric value and returns the remaining string after the closing ">".
func parseTagNumeric(s, prefix string, minVal, maxVal int) (tail string, err error) {
	inner, tail, ok := strings.Cut(s[len(prefix):], ">")
	if !ok {
		return "", fmt.Errorf("unclosed tag %q in %q", prefix, truncate(s))
	}
	_, err = parseTagInt(inner, minVal, maxVal)
	if err != nil {
		return "", err
	}
	return tail, nil
}

// parseTagInt converts a tag numeric argument string to int within [min, max].
func parseTagInt(s string, minVal, maxVal int) (int, error) {
	if s == "" {
		return 0, errors.New("missing numeric argument")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-numeric character %q in argument %q", r, s)
		}
		n = n*10 + int(r-'0')
	}
	if n < minVal || n > maxVal {
		return 0, fmt.Errorf("value %d out of range [%d, %d]", n, minVal, maxVal)
	}
	return n, nil
}

// validateHex checks that s contains only hexadecimal characters.
func validateHex(s string) error {
	if s == "" {
		return errors.New("empty hex value")
	}
	for i, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return fmt.Errorf("invalid hex character %q at position %d", r, i)
		}
	}
	return nil
}

// truncate returns at most 80 characters of s for use in error messages,
// preventing unbounded output when reporting on malformed user input.
func truncate(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
