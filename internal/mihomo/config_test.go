//nolint:errcheck,forcetypeassert // Type assertions in tests safely panic on failure
package mihomo

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
	"github.com/underhax/mihomo-warp-proxy/internal/wgcf"
)

var (
	testProfile = &wgcf.Profile{
		PrivateKey: "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE=",
		PublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		IPv4:       "172.16.0.2",
		IPv6:       "2606:4700:110:8949:fed8:548c:4603:5b00",
	}
	testReserved = [3]byte{1, 2, 3}
	testLog      = logging.New(logging.LevelDebug, "test")
)

func testConfig(dir string) *config.Config {
	return &config.Config{
		ProxyPort:     7890,
		ProxyLogLevel: "info",
		ProxyUser:     "user",
		ProxyPass:     "pass",
		UseIP6:        true,
		Geo: config.GeoConfig{
			Enabled: true,
			URLs: config.GeoURLs{
				GeoIP:   "https://example.com/geoip.dat",
				GeoSite: "https://example.com/geosite.dat",
				MMDB:    "https://example.com/geoip.metadb",
				ASN:     "https://example.com/GeoLite2-ASN.mmdb",
			},
		},
		Warp: config.WarpConfig{
			Enabled:  true,
			Endpoint: "engage.cloudflareclient.com:2408",
			DNS:      []string{"1.1.1.1", "1.0.0.1"},
		},
		Paths: config.Paths{
			MihomoConfigFile: filepath.Join(dir, "config.yaml"),
			MihomoData:       dir,
		},
	}
}

// hasProxy returns true when the proxies slice (from readYAML) contains an
// entry with the given name. Works with map[string]any entries produced by
// yaml.Unmarshal into map[string]any.
func hasProxy(proxies []any, name string) bool {
	for _, p := range proxies {
		if m, ok := p.(map[string]any); ok {
			if n, ok := m["name"].(string); ok && n == name {
				return true
			}
		}
	}
	return false
}

// readYAML parses a YAML file into map[string]any for assertions.
func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		t.Fatalf("readYAML: %v", err)
	}
	doc := make(map[string]any)
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("readYAML unmarshal: %v", err)
	}
	return doc
}

// --- EnsureConfig: first run (no existing config) ---

func TestEnsureConfigCreatesTemplate(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	if doc["mixed-port"] == nil {
		t.Error("mixed-port missing from created config")
	}
	if doc["authentication"] == nil {
		t.Error("authentication missing from created config")
	}
	if doc["proxies"] == nil {
		t.Error("proxies missing from created config")
	}
	if doc["rules"] == nil {
		t.Error("rules missing from created config")
	}
}

func TestTemplateRulesWarp(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Enabled = true

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := doc["rules"].([]any)
	if len(rules) != 1 || rules[0].(string) != minimalTemplateWarpRule() {
		t.Errorf("template rules: got %v, want [%s]", rules, minimalTemplateWarpRule())
	}
}

func TestTemplateRulesDirect(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Enabled = false

	if err := EnsureConfig(cfg, nil, [3]byte{}, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := doc["rules"].([]any)
	if len(rules) != 1 || rules[0].(string) != minimalTemplateDirectRule() {
		t.Errorf("template rules: got %v, want [%s]", rules, minimalTemplateDirectRule())
	}
}

func TestEnsureConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(cfg.Paths.MihomoConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file permissions: got %04o, want 0o600", perm)
	}
}

// --- Owned fields are overwritten ---

func TestPatchOverwritesOwnedFields(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	cfg.ProxyPort = 8080
	cfg.ProxyLogLevel = "debug"
	cfg.UseIP6 = false

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	if port, ok := doc["mixed-port"].(int); !ok || port != 8080 {
		t.Errorf("mixed-port not updated: got %v", doc["mixed-port"])
	}
	if level, ok := doc["log-level"].(string); !ok || level != "debug" {
		t.Errorf("log-level not updated: got %v", doc["log-level"])
	}
	if ipv6, ok := doc["ipv6"].(bool); !ok || ipv6 != false {
		t.Errorf("ipv6 not updated: got %v", doc["ipv6"])
	}
}

// --- User-defined keys are preserved ---

func TestPatchPreservesUserKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	userConfig := `
mixed-port: 7890
log-level: info
ipv6: true
allow-lan: true
bind-address: "*"
authentication:
  - "user:pass"
listeners:
  - name: socks-in
    type: socks
    port: 1080
proxy-groups:
  - name: MyGroup
    type: select
    proxies:
      - warp
      - DIRECT
proxies:
  - name: warp
    type: wireguard
    server: engage.cloudflareclient.com
    port: 2408
    ip: 172.16.0.2
    ipv6: "2606:4700::1"
    public-key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    private-key: "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE="
    udp: true
    mtu: 1280
    dns:
      - 1.1.1.1
rules:
  - DOMAIN-SUFFIX,preserve.example.com,DIRECT
  - MATCH,PreserveGroup
`
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	// User-defined listener must survive.
	listeners, ok := doc["listeners"].([]any)
	if !ok || len(listeners) == 0 {
		t.Error("user-defined listeners were removed")
	}

	// User-defined proxy-groups must survive.
	groups, ok := doc["proxy-groups"].([]any)
	if !ok || len(groups) == 0 {
		t.Error("user-defined proxy-groups were removed")
	}

	// All user rules must survive unchanged — patch never modifies rules[].
	rules := doc["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("rules count changed: got %d, want 2", len(rules))
	}
	if rules[0].(string) != "DOMAIN-SUFFIX,preserve.example.com,DIRECT" {
		t.Errorf("user rule[0] changed: got %q", rules[0])
	}
	if rules[1].(string) != "MATCH,PreserveGroup" {
		t.Errorf("user rule[1] changed: got %q", rules[1])
	}
}

// --- patchWarpProxy appends when warp absent but other proxies exist ---

func TestPatchAppendsWarpWhenMissingWithOtherProxies(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	// User config with a custom proxy but no warp entry.
	userConfig := `
mixed-port: 7890
log-level: info
ipv6: true
allow-lan: true
bind-address: "*"
authentication: []
proxies:
  - name: my-vless
    type: vless
    server: example.com
    port: 443
rules:
  - DOMAIN-SUFFIX,append.example.com,DIRECT
  - MATCH,my-vless
`
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)

	// Both proxies must be present.
	proxies := doc["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}

	// warp must have been appended.
	if !hasProxy(proxies, "warp") {
		t.Error("warp proxy was not appended")
	}
	if !hasProxy(proxies, "my-vless") {
		t.Error("my-vless proxy was removed")
	}

	// Rules must be untouched — user manages them.
	rules := doc["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules count changed: got %d, want 2", len(rules))
	}
	if rules[1].(string) != "MATCH,my-vless" {
		t.Errorf("rules[1] changed: got %q", rules[1])
	}
}

// --- minimal template MATCH,DIRECT → MATCH,warp on warp enable ---

func TestPatchReplacesMatchDirectWhenMinimalTemplate(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Enabled = false

	// First run with warp disabled — creates minimal template with MATCH,DIRECT.
	if err := EnsureConfig(cfg, nil, [3]byte{}, testLog); err != nil {
		t.Fatal(err)
	}

	// Enable warp — MATCH,DIRECT must become MATCH,warp.
	cfg.Warp.Enabled = true
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := doc["rules"].([]any)
	if len(rules) != 1 || rules[0].(string) != minimalTemplateWarpRule() {
		t.Errorf("rules: got %v, want [%s]", rules, minimalTemplateWarpRule())
	}
	proxies := doc["proxies"].([]any)
	if !hasProxy(proxies, "warp") {
		t.Error("warp proxy not added")
	}
}

func TestPatchDoesNotReplaceMatchDirectWhenUserHasCustomRules(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	// User config with custom rules and no warp proxy.
	userConfig := `
mixed-port: 7890
log-level: info
ipv6: true
allow-lan: true
bind-address: "*"
authentication: []
proxies: []
rules:
  - DOMAIN-SUFFIX,custom.example.com,DIRECT
  - MATCH,DIRECT
`
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := doc["rules"].([]any)
	// 2 rules — not a minimal template, so rules must be untouched.
	if len(rules) != 2 {
		t.Fatalf("rules count changed: got %d, want 2", len(rules))
	}
	if rules[1].(string) != minimalTemplateDirectRule() {
		t.Errorf("rules[1] changed: got %q", rules[1])
	}
}

// --- rules[] are never modified on patch ---

func TestPatchDoesNotModifyRules(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	// First run — creates template with MATCH,warp.
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	// User manually edits rules.
	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	doc["rules"] = []any{
		"DOMAIN-SUFFIX,audit.example.com,DIRECT",
		"GEOIP,CN,DIRECT",
		"MATCH,AuditGroup",
	}
	data, _ := yaml.Marshal(doc) //nolint:errcheck // mock serialization
	if err := os.WriteFile(cfg.Paths.MihomoConfigFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Patch — rules must not change regardless of USE_WARP_CONFIG value.
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc = readYAML(t, cfg.Paths.MihomoConfigFile)
	rules := doc["rules"].([]any)

	if len(rules) != 3 {
		t.Fatalf("rules count changed: got %d, want 3", len(rules))
	}
	if rules[0].(string) != "DOMAIN-SUFFIX,audit.example.com,DIRECT" {
		t.Errorf("rules[0] changed: got %q", rules[0])
	}
	if rules[1].(string) != "GEOIP,CN,DIRECT" {
		t.Errorf("rules[1] changed: got %q", rules[1])
	}
	if rules[2].(string) != "MATCH,AuditGroup" {
		t.Errorf("rules[2] changed: got %q", rules[2])
	}
}

// --- Reserved bytes ---

func TestReservedWrittenWhenNonZero(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, [3]byte{10, 20, 30}, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies := doc["proxies"].([]any)
	proxy, _ := proxies[0].(map[string]any)

	if proxy["reserved"] == nil {
		t.Error("reserved not written when non-zero")
	}
}

func TestReservedNotWrittenWhenZero(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := EnsureConfig(cfg, testProfile, [3]byte{0, 0, 0}, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies := doc["proxies"].([]any)
	proxy, _ := proxies[0].(map[string]any)

	if proxy["reserved"] != nil {
		t.Errorf("reserved written for zero value: %v", proxy["reserved"])
	}
}

// --- Geo block ---

func TestGeoBlockRemovedWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Geo.Enabled = true

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	cfg.Geo.Enabled = false
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	for _, k := range []string{"geodata-mode", "geodata-loader", "geo-auto-update", "geox-url"} {
		if _, exists := doc[k]; exists {
			t.Errorf("geo key %q still present after GEO disabled", k)
		}
	}
}

// --- Amnezia ---

func TestAmneziaBlockAddedAndRemoved(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.Warp.Amnezia = config.AmneziaConfig{
		Enabled: true,
		JC:      5,
		JMin:    7,
		JMax:    15,
	}

	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc := readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies := doc["proxies"].([]any)
	proxy, _ := proxies[0].(map[string]any)

	if proxy["amnezia-wg-option"] == nil {
		t.Error("amnezia-wg-option not written when Amnezia enabled")
	}

	cfg.Warp.Amnezia.Enabled = false
	if err := EnsureConfig(cfg, testProfile, testReserved, testLog); err != nil {
		t.Fatal(err)
	}

	doc = readYAML(t, cfg.Paths.MihomoConfigFile)
	proxies = doc["proxies"].([]any)
	proxy, _ = proxies[0].(map[string]any)

	if proxy["amnezia-wg-option"] != nil {
		t.Error("amnezia-wg-option still present after Amnezia disabled")
	}
}

// --- splitEndpoint ---

func TestSplitEndpoint(t *testing.T) {
	cases := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"engage.cloudflareclient.com:2408", "engage.cloudflareclient.com", 2408},
		{"engage.cloudflareclient.com:500", "engage.cloudflareclient.com", 500},
		{"host:0", "host", 0},
		{"noport", "noport", 0},
	}

	for _, tc := range cases {
		host, port := splitEndpoint(tc.input)
		if host != tc.wantHost {
			t.Errorf("splitEndpoint(%q) host: got %q, want %q", tc.input, host, tc.wantHost)
		}
		if port != tc.wantPort {
			t.Errorf("splitEndpoint(%q) port: got %d, want %d", tc.input, port, tc.wantPort)
		}
	}
}

// --- findProxyByNameNode ---

func TestFindProxyByNameNode(t *testing.T) {
	makeNode := func(name string) *yaml.Node {
		return &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  yamlTagMap,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: "name"},
				{Kind: yaml.ScalarNode, Tag: yamlTagStr, Value: name},
			},
		}
	}
	seq := &yaml.Node{
		Kind:    yaml.SequenceNode,
		Tag:     yamlTagSeq,
		Content: []*yaml.Node{makeNode("direct"), makeNode("warp"), makeNode("vless")},
	}

	if idx := findProxyByNameNode(seq, "warp"); idx != 1 {
		t.Errorf("findProxyByNameNode warp: got %d, want 1", idx)
	}
	if idx := findProxyByNameNode(seq, "missing"); idx != -1 {
		t.Errorf("findProxyByNameNode missing: got %d, want -1", idx)
	}
	emptySeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: yamlTagSeq}
	if idx := findProxyByNameNode(emptySeq, "warp"); idx != -1 {
		t.Errorf("findProxyByNameNode empty: got %d, want -1", idx)
	}
}
