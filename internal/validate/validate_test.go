package validate

import (
	"net"
	"testing"
)

// --- Path ---

func TestPath(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid app path", "/app/mihomo", false},
		{"valid nested path", "/app/mihomo/config.yaml", false},
		{"valid usr path", "/usr/local/bin/mihomo", false},
		{"empty", "", true},
		{"relative path", "app/mihomo", true},
		{"dot-dot traversal", "/app/../etc/passwd", true},
		{"embedded dot-dot", "/app/mihomo/../../etc", true},
		{"null byte", "/app/\x00mihomo", true},
		{"control char", "/app/\x01mihomo", true},
		{"whitespace", "/app/mi homo", true},
		{"tab in path", "/app/mi\thomo", true},
		{"proc pseudo-fs", "/proc/self/mem", true},
		{"sys pseudo-fs", "/sys/kernel", true},
		{"dev pseudo-fs", "/dev/null", true},
		{"docker socket", "/var/run/docker.sock", true},
		{"dockerenv", "/.dockerenv", true},
		{"run dir", "/run/secrets", true},
		{"path too long", "/" + string(make([]byte, 4097)), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Path(tc.input, "TEST_PATH")
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

// --- IsRestrictedIP ---

func TestIsRestrictedIP(t *testing.T) {
	restricted := []string{
		// loopback
		"127.0.0.1", "127.255.255.255",
		// RFC 1918
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		// CGNAT
		"100.64.0.1", "100.127.255.255",
		// link-local
		"169.254.0.1", "169.254.255.255",
		// unspecified
		"0.0.0.0",
		// IPv6 loopback
		"::1",
		// IPv6 link-local
		"fe80::1",
		// IPv6 ULA
		"fc00::1", "fd00::1",
		// IPv4-mapped IPv6 pointing at RFC1918
		"::ffff:192.168.1.1",
		"::ffff:10.0.0.1",
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"104.16.0.1",    // Cloudflare public range
		"162.159.200.1", // Cloudflare public range
		"2606:4700:4700::1111",
		"2001:4860:4860::8888", // Google public DNS
	}

	for _, addr := range restricted {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("test setup: cannot parse IP %q", addr)
		}
		if !IsRestrictedIP(ip) {
			t.Errorf("IsRestrictedIP(%q) = false, want true", addr)
		}
	}

	for _, addr := range allowed {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("test setup: cannot parse IP %q", addr)
		}
		if IsRestrictedIP(ip) {
			t.Errorf("IsRestrictedIP(%q) = true, want false", addr)
		}
	}
}

func TestIsRestrictedIPNil(t *testing.T) {
	if !IsRestrictedIP(nil) {
		t.Error("IsRestrictedIP(nil) = false, want true")
	}
}

// --- AmneziaIParam ---

func TestAmneziaIParam(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string accepted", "", false},
		{"single b tag", "<b 0xdeadbeef>", false},
		{"single c tag", "<c>", false},
		{"single t tag", "<t>", false},
		{"r tag min", "<r 0>", false},
		{"r tag max", "<r 1000>", false},
		{"wt tag min", "<wt 0>", false},
		{"wt tag max", "<wt 5000>", false},
		{"combined tags", "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10><wt 10>", false},
		{"combined tags 2", "<b 0xf6ab3267fa><r 100>", false},
		{"r above max", "<r 1001>", true},
		{"wt above max", "<wt 5001>", true},
		{"b tag invalid hex", "<b 0xZZZZ>", true},
		{"b tag empty hex", "<b 0x>", true},
		{"unclosed b tag", "<b 0xdeadbeef", true},
		{"unclosed r tag", "<r 10", true},
		{"unknown tag", "<x>", true},
		{"plain text", "hello", true},
		{"closing tag", "</b>", true},
		{"r non-numeric", "<r abc>", true},
		{"wt non-numeric", "<wt 1.5>", true},
		{"too long", string(make([]byte, 10001)), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AmneziaIParam("TEST_I1", tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

// --- validateHex ---

func TestValidateHex(t *testing.T) {
	valid := []string{"deadbeef", "DEADBEEF", "DeAdBeEf", "00", "ff", "0123456789abcdefABCDEF"}
	invalid := []string{"", "xyz", "dead beef", "0xdeadbeef", "gg"}

	for _, s := range valid {
		if err := validateHex(s); err != nil {
			t.Errorf("validateHex(%q) unexpected error: %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateHex(s); err == nil {
			t.Errorf("validateHex(%q) expected error, got nil", s)
		}
	}
}

// --- truncate ---

func TestTruncate(t *testing.T) {
	short := "hello"
	if truncate(short) != short {
		t.Errorf("truncate(%q) changed short string", short)
	}

	long := string(make([]byte, 100))
	result := truncate(long)
	if len([]rune(result)) > 82 { // 80 chars + ellipsis rune
		t.Errorf("truncate did not shorten long string, got length %d", len(result))
	}
}
