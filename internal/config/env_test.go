package config

import (
    "reflect"
	"strings"
	"testing"
)

// setEnv sets environment variables for the duration of a test and restores
// original values via t.Cleanup.
func setEnv(t *testing.T, pairs ...string) {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("setEnv requires an even number of arguments (key, value pairs)")
	}
	for i := 0; i < len(pairs); i += 2 {
		t.Setenv(pairs[i], pairs[i+1])
	}
}

// testCreds returns a valid credential pair that satisfies all constraints.
// user: 8 chars, mixed case + digit
// pass: 32 chars, mixed case + digit (compatible with pwgen -s output)
func testCreds() (user, pass string) {
	// user: 8 chars with upper + digit
	// pass: 32 chars, 12+ distinct chars, upper + lower + digit, no runs
	return "aaaaaaA1", "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
}

// --- parseBoolEnv ---

func TestParseBoolEnv(t *testing.T) {
	cases := []struct {
		key     string
		val     string
		def     string
		want    bool
		wantErr bool
	}{
		{"K", "true", "false", true, false},
		{"K", "True", "false", true, false},
		{"K", "TRUE", "false", true, false},
		{"K", "1", "false", true, false},
		{"K", "yes", "false", true, false},
		{"K", "on", "false", true, false},
		{"K", "false", "true", false, false},
		{"K", "0", "true", false, false},
		{"K", "no", "true", false, false},
		{"K", "off", "true", false, false},
		{"K", "", "true", true, false},
		{"K", "maybe", "false", false, true},
		{"K", "yes please", "false", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.val+"_default_"+tc.def, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			got, err := parseBoolEnv(tc.key, tc.def)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for value %q, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("parseBoolEnv(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// --- parseUint32Env ---

func TestParseUint32Env(t *testing.T) {
	cases := []struct {
		val     string
		min     uint32
		max     uint32
		want    uint32
		wantErr bool
	}{
		{"911", 0, 65535, 911, false},
		{"0", 0, 65535, 0, false},
		{"65535", 0, 65535, 65535, false},
		{"65536", 0, 65535, 0, true},
		{"", 0, 65535, 0, false},
		{"-1", 0, 65535, 0, true},
		{"abc", 0, 65535, 0, true},
		{"7890", 1, 65535, 7890, false},
		{"0", 1, 65535, 0, true},
	}

	for _, tc := range cases {
		t.Run("val_"+tc.val, func(t *testing.T) {
			t.Setenv("TEST_UINT", tc.val)
			got, err := parseUint32Env("TEST_UINT", "0", tc.min, tc.max)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for value %q, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// --- validatePasswordComplexity ---

func TestValidatePasswordComplexity(t *testing.T) {
	cases := []struct {
		name    string
		pass    string
		wantErr bool
	}{
		// valid — pwgen -s compatible
		{"pwgen-style 32", "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", false},
		{"pwgen-style 128", strings.Repeat("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV", 4), false},
		{"with allowed special chars", "aB3dEfGhIjKlMn!opQrStUvWxYz01234", false},
		// missing uppercase
		{"all lowercase + digit", strings.Repeat("abcdefghij", 3) + "12", true},
		// missing lowercase
		{"all uppercase + digit", strings.Repeat("ABCDEFGHIJ", 3) + "12", true},
		// missing digit
		{"upper + lower no digit", strings.Repeat("abcdefghij", 3) + "AB", true},
		// too few distinct chars (< 12)
		{"only 3 distinct chars", strings.Repeat("aA1", 11), true},
		{"only 11 distinct chars", "aAbBcCdDeEf" + strings.Repeat("a", 21), true},
		{"12 distinct chars ok", "aAbBcCdDeEfFgG1HiIjJkKlLmMnNoP2r", false},
		// run detection (4+ identical consecutive)
		{"run of 4 lowercase", "aBcDeFgHiJkLaaaa" + strings.Repeat("mN3", 6), true},
		{"run of 4 uppercase", "aBcDeFgHiJkLAAAA" + strings.Repeat("mn3", 6), true},
		{"run of 4 digits", "aBcDeFgHiJkL1111" + strings.Repeat("mn3", 6), true},
		{"run of 3 allowed", "aBcDeFgHiJkLaaa" + strings.Repeat("mN3", 6), false},
		// all same char
		{"32 identical lowercase", strings.Repeat("a", 32), true},
		{"32 identical uppercase", strings.Repeat("A", 32), true},
		{"32 identical digits", strings.Repeat("1", 32), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordComplexity(tc.pass)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil (pass=%q)", tc.pass)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// --- validateCredentialPair ---

func TestValidateCredentialPair(t *testing.T) {
	validUser, validPass := testCreds()

	cases := []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		// authentication is mandatory
		{"both empty — open proxy rejected", "", "", true},
		{"user only", validUser, "", true},
		{"pass only", "", validPass, true},
		// valid pair
		{"valid pair", validUser, validPass, false},
		{"max length user", strings.Repeat("a", 63) + "A", validPass, false},
		{"max length pass", validUser, strings.Repeat("aB3cD4eF5gH6", 10) + "iJ7kL8mN", false},
		// user length
		{"user too short (7)", "aaaAA12", validPass, true},
		{"user min length (8)", "aaaaaaA1", validPass, false},
		{"user too long (65)", strings.Repeat("a", 65), validPass, true},
		// pass length
		{"pass too short (31)", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234", true},
		{"pass min length (32)", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", false},
		{"pass too long (129)", validUser, strings.Repeat("aBcDeFgHiJkL", 10) + "mNoPq", true},
		// forbidden chars
		{"colon in user", validUser + ":", validPass, true},
		{"colon in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234:", true},
		{"control char in user", "aaaaaaA\x011", validPass, true},
		{"null byte in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123\x004", true},
		// complexity failures (length OK but weak)
		{"pass all lowercase", validUser, strings.Repeat("a", 32), true},
		{"pass all uppercase", validUser, strings.Repeat("A", 32), true},
		{"pass only digits", validUser, strings.Repeat("1", 32), true},
		{"pass upper+lower no digit", validUser, strings.Repeat("a", 30) + "AB", true},
		{"pass upper+digit no lower", validUser, strings.Repeat("1", 30) + "AA", true},
		{"pass lower+digit no upper", validUser, strings.Repeat("a", 30) + "11", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCredentialPair(tc.user, tc.pass)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// --- validateWarpEndpoint ---

func TestValidateWarpEndpoint(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"engage.cloudflareclient.com:2408", false},
		{"engage.cloudflareclient.com:500", false},
		{"engage.cloudflareclient.com:1701", false},
		{"engage.cloudflareclient.com:4500", false},
		{"engage.cloudflareclient.com:9999", true},
		{"evil.example.com:2408", true},
		{"engage.cloudflareclient.com", true},
		{"", true},
		{":2408", true},
		{"engage.cloudflareclient.com:0", true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			err := validateWarpEndpoint(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

// --- parseDNSList ---

func TestParseDNSList(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"ipv4 only", "1.1.1.1,1.0.0.1", 2, false},
		{"mixed ipv4 ipv6", "1.1.1.1,2606:4700:4700::1111", 2, false},
		{"dot resolver", "tls://1.1.1.1", 1, false},
		{"doh resolver", "https://dns.cloudflare.com/dns-query", 1, false},
		{"doq resolver", "quic://dns.cloudflare.com", 1, false},
		{"spaces trimmed", "1.1.1.1, 1.0.0.1", 2, false},
		{"max entries (8)", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8", 8, false},
		{"too many entries (9)", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9", 0, true},
		{"empty string", "", 0, true},
		{"invalid entry", "1.1.1.1,notadns", 0, true},
		{"invalid ipv4 octet", "256.0.0.1", 0, true},
		{"single valid", "8.8.8.8", 1, false},
		{"trailing comma", "1.1.1.1,", 1, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDNSList(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != tc.wantLen {
				t.Errorf("got %d entries, want %d", len(got), tc.wantLen)
			}
		})
	}
}

// --- isIPv4 ---

func TestIsIPv4(t *testing.T) {
	valid := []string{"1.1.1.1", "0.0.0.0", "255.255.255.255", "192.168.1.100"}
	invalid := []string{"", "256.0.0.1", "1.1.1", "1.1.1.1.1", "a.b.c.d", "1.1.1.-1"}

	for _, ip := range valid {
		if !isIPv4(ip) {
			t.Errorf("isIPv4(%q) = false, want true", ip)
		}
	}
	for _, ip := range invalid {
		if isIPv4(ip) {
			t.Errorf("isIPv4(%q) = true, want false", ip)
		}
	}
}

// --- Load integration ---

func TestLoadDefaults(t *testing.T) {
	user, pass := testCreds()
	for _, k := range []string{
		"TZ", "SCRIPT_LOG_LEVEL", "PROXY_LOG_LEVEL",
		"PROXY_UID", "PROXY_GID", "PROXY_PORT",
		"MULTI_USER_MODE", "USE_IP6",
		"GEO", "GEO_REDOWNLOAD",
		"GEO_URL_GEOIP", "GEO_URL_GEOSITE", "GEO_URL_MMDB", "GEO_URL_ASN",
		"GEO_AUTH_USER", "GEO_AUTH_PASS",
		"USE_WARP_CONFIG", "WARP_REGENERATE", "WARP_PLUS_KEY",
		"WARP_ENDPOINT", "WARP_DNS", "WARP_AMNEZIA",
	} {
		t.Setenv(k, "")
	}
	setEnv(t, "PROXY_USER", user, "PROXY_PASS", pass)

	cfg, err := Load("1.0.0")
	if err != nil {
		t.Fatalf("Load() with defaults failed: %v", err)
	}

	if cfg.ProxyUID != 911 {
		t.Errorf("ProxyUID: got %d, want 911", cfg.ProxyUID)
	}
	if cfg.ProxyGID != 911 {
		t.Errorf("ProxyGID: got %d, want 911", cfg.ProxyGID)
	}
	if cfg.ProxyPort != 7890 {
		t.Errorf("ProxyPort: got %d, want 7890", cfg.ProxyPort)
	}
	if !cfg.MultiUserMode {
		t.Error("MultiUserMode: got false, want true")
	}
	if !cfg.UseIP6 {
		t.Error("UseIP6: got false, want true")
	}
	if cfg.Geo.Enabled {
		t.Error("Geo.Enabled: got true, want false")
	}
	if cfg.Geo.Redownload {
		t.Error("Geo.Redownload: got true, want false")
	}
	if cfg.Geo.AutoUpdate {
		t.Error("Geo.AutoUpdate: got true, want false")
	}
	if !cfg.Warp.Enabled {
		t.Error("Warp.Enabled: got false, want true")
	}
	if cfg.Warp.Amnezia.Enabled {
		t.Error("Warp.Amnezia.Enabled: got true, want false")
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("Version: got %q, want %q", cfg.Version, "1.0.0")
	}
}

func TestLoadEmptyCredentialsRejected(t *testing.T) {
	setEnv(t, "PROXY_USER", "", "PROXY_PASS", "")
	_, err := Load("test")
	if err == nil {
		t.Error("expected error for empty credentials, got nil")
	}
}

func TestLoadAmneziaValidation(t *testing.T) {
	user, pass := testCreds()
	base := []string{
		"PROXY_USER", user, "PROXY_PASS", pass,
		"WARP_AMNEZIA", "true",
		"WARP_AMNEZIA_JC", "5",
	}

	t.Run("jmin >= jmax rejected", func(t *testing.T) {
		setEnv(t, append(base, "WARP_AMNEZIA_JMIN", "15", "WARP_AMNEZIA_JMAX", "15")...)
		_, err := Load("test")
		if err == nil {
			t.Error("expected error for jmin == jmax, got nil")
		}
	})

	t.Run("jmin > jmax rejected", func(t *testing.T) {
		setEnv(t, append(base, "WARP_AMNEZIA_JMIN", "20", "WARP_AMNEZIA_JMAX", "10")...)
		_, err := Load("test")
		if err == nil {
			t.Error("expected error for jmin > jmax, got nil")
		}
	})

	t.Run("valid amnezia params accepted", func(t *testing.T) {
		setEnv(t, append(base, "WARP_AMNEZIA_JMIN", "7", "WARP_AMNEZIA_JMAX", "15")...)
		cfg, err := Load("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Warp.Amnezia.JC != 5 {
			t.Errorf("JC: got %d, want 5", cfg.Warp.Amnezia.JC)
		}
		if cfg.Warp.Amnezia.JMin != 7 {
			t.Errorf("JMin: got %d, want 7", cfg.Warp.Amnezia.JMin)
		}
		if cfg.Warp.Amnezia.JMax != 15 {
			t.Errorf("JMax: got %d, want 15", cfg.Warp.Amnezia.JMax)
		}
	})
}

func TestLoadGeoAuthPartialCredentials(t *testing.T) {
	user, pass := testCreds()
	setEnv(t,
		"PROXY_USER", user, "PROXY_PASS", pass,
		"GEO_AUTH_USER", "user",
		"GEO_AUTH_PASS", "",
	)
	_, err := Load("test")
	if err == nil {
		t.Error("expected error for partial GEO auth credentials, got nil")
	}
}

func TestLoadInvalidProxyLogLevel(t *testing.T) {
	user, pass := testCreds()
	setEnv(t,
		"PROXY_USER", user, "PROXY_PASS", pass,
		"PROXY_LOG_LEVEL", "verbose",
	)
	_, err := Load("test")
	if err == nil {
		t.Error("expected error for invalid PROXY_LOG_LEVEL, got nil")
	}
}

func TestLoadProxyUIDGIDValidation(t *testing.T) {
	user, pass := testCreds()
	base := []string{"PROXY_USER", user, "PROXY_PASS", pass}

	cases := []struct {
		name    string
		uid     string
		gid     string
		wantErr bool
	}{
		{"default (911:911)", "", "", false},
		{"min allowed (1:1)", "1", "1", false},
		{"max allowed (65535:65535)", "65535", "65535", false},
		{"zero uid rejected", "0", "911", true},
		{"zero gid rejected", "911", "0", true},
		{"above max uid", "65536", "911", true},
		{"above max gid", "911", "65536", true},
		{"negative uid", "-1", "911", true},
		{"non-numeric uid", "abc", "911", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(base, "PROXY_UID", tc.uid, "PROXY_GID", tc.gid)
			setEnv(t, args...)
			_, err := Load("test")
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// --- FilterEnviron ---

func TestFilterEnviron(t *testing.T) {
	input := []string{
		"PATH=/usr/local/sbin:/usr/local/bin",
		"PROXY_USER=admin",
		"PROXY_PASS=supersecret32chars!!!",
		"GEO_AUTH_USER=alice",
		"GEO_AUTH_PASS=bob",
		"WARP_PLUS_KEY=1234-5678-90ab",
		"TZ=UTC",
		"INVALID_ENV_VAR",
	}
	want := []string{
		"PATH=/usr/local/sbin:/usr/local/bin",
		"PROXY_USER=admin",
		"TZ=UTC",
		"INVALID_ENV_VAR",
	}

	got := FilterEnviron(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterEnviron() = %v, want %v", got, want)
	}
}
