// Package mihomo manages the mihomo config.yaml lifecycle.
// The central design constraint is that config.yaml is user-owned: this
// package may only write fields it explicitly declares as its own. Every
// other key — custom listeners, proxy-groups, rule-providers, additional
// proxies, custom rules — must survive a patch cycle unmodified, including
// their original key order.
//
// Owned fields (always overwritten from Config):
//
//	Top-level:  mixed-port, log-level, ipv6, allow-lan, bind-address,
//	            authentication
//	Geo block:  geodata-mode, geodata-loader, geo-auto-update,
//	            geo-update-interval, geox-url.*  (added/removed per GEO flag)
//	proxies[]:  the single entry where .name == "warp" (only when
//	            USE_WARP_CONFIG=true; left untouched otherwise)
//
// rules[] and proxies[] (except the "warp" entry) are only written during
// first-run template creation. On subsequent patch cycles they are never
// touched — the user owns them entirely.
//
// Key order is preserved on patch by using yaml.Node for the full document
// round-trip. map[string]any is used only in createTemplate where there is
// no existing file to preserve.
//
// When USE_WARP_CONFIG=false the entire config is left as-is.
// proxies, rules and all other sections are not touched.
package mihomo

import (
	"fmt"
	"io"
	"strconv"
	"os"
	"path/filepath"
	"net"

	"gopkg.in/yaml.v3"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/config"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/wgcf"
)

const maxConfigSize = 1024 * 1024 // 1 MB limit to prevent YAML bomb DoS

// EnsureConfig creates config.yaml from a minimal template when it does not
// exist, then patches it with current environment values.
// When the file already exists only owned fields are updated.
func EnsureConfig(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte, log *logging.Logger) error {
	if _, err := os.Stat(cfg.Paths.MihomoConfigFile); os.IsNotExist(err) {
		log.Debug("mihomo: config not found, creating from template")
		if err := createTemplate(cfg, profile, reserved); err != nil {
			return fmt.Errorf("mihomo: create template: %w", err)
		}
		log.Debug("mihomo: config created from template")
		return nil
	}

	log.Debug("mihomo: patching existing config")
	if err := patchConfig(cfg, profile, reserved, log); err != nil {
		return err
	}
	log.Debug("mihomo: config patched successfully")
	return nil
}

// createTemplate writes a minimal but fully functional config.yaml.
// Called only on first run when no prior config exists.
// Uses map[string]any — key order is not critical for a fresh file.
func createTemplate(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte) error {
	doc := make(map[string]any)
	applyOwnedFieldsMap(doc, cfg)

	if cfg.Geo.Enabled {
		applyGeoFieldsMap(doc, cfg)
	}

	if cfg.Warp.Enabled && profile != nil {
		doc["proxies"] = []any{buildWarpProxy(cfg, profile, reserved)}
		doc["rules"] = []any{"MATCH,warp"}
	} else {
		doc["rules"] = []any{"MATCH,DIRECT"}
	}

	return writeConfigMap(cfg.Paths.MihomoConfigFile, doc)
}

// patchConfig reads the existing config.yaml as a yaml.Node tree (preserving
// key order and comments), updates only owned fields in place, and writes the
// result back atomically.
func patchConfig(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte, log *logging.Logger) error {
	f, err := os.Open(cfg.Paths.MihomoConfigFile)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if len(raw) > maxConfigSize {
		return fmt.Errorf("config file exceeds max allowed size of %d bytes", maxConfigSize)
	}

	// Unmarshal into yaml.Node to preserve key order, comments and style.
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	// yaml.Unmarshal wraps the document in a DocumentNode.
	doc := docMapping(&root)
	if doc == nil {
		return fmt.Errorf("config is not a YAML mapping")
	}

	applyOwnedFieldsNode(doc, cfg)

	if cfg.Geo.Enabled {
		applyGeoFieldsNode(doc, cfg)
	} else {
		removeGeoFieldsNode(doc)
	}

	if cfg.Warp.Enabled && profile != nil {
		if err := patchWarpProxy(doc, cfg, profile, reserved, log); err != nil {
			return err
		}
	}
	// When USE_WARP_CONFIG=false proxies and rules are left completely untouched.

	return writeConfigNode(cfg.Paths.MihomoConfigFile, &root)
}

// ── owned fields (yaml.Node path) ────────────────────────────────────────────

// applyOwnedFieldsNode updates the top-level managed scalar fields in place.
func applyOwnedFieldsNode(doc *yaml.Node, cfg *config.Config) {
	setNodeScalar(doc, "mixed-port", "!!int", fmt.Sprintf("%d", cfg.ProxyPort))
	setNodeScalar(doc, "log-level", "!!str", cfg.ProxyLogLevel)
	setNodeScalar(doc, "ipv6", "!!bool", boolStr(cfg.UseIP6))
	setNodeScalar(doc, "allow-lan", "!!bool", "true")
	setNodeScalar(doc, "bind-address", "!!str", "*")

	authSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if cfg.ProxyUser != "" && cfg.ProxyPass != "" {
		authSeq.Content = append(authSeq.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: cfg.ProxyUser + ":" + cfg.ProxyPass})
	}
	setNodeValue(doc, "authentication", authSeq)
}

// applyGeoFieldsNode writes or updates the geodata block.
func applyGeoFieldsNode(doc *yaml.Node, cfg *config.Config) {
	setNodeScalar(doc, "geodata-mode", "!!bool", "true")
	setNodeScalar(doc, "geodata-loader", "!!str", "memconservative")
	setNodeScalar(doc, "geo-auto-update", "!!bool", boolStr(cfg.Geo.AutoUpdate))
	setNodeScalar(doc, "geo-update-interval", "!!int", "24")

	geoMap := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, kv := range [][2]string{
		{"geoip", cfg.Geo.URLs.GeoIP},
		{"geosite", cfg.Geo.URLs.GeoSite},
		{"mmdb", cfg.Geo.URLs.MMDB},
		{"asn", cfg.Geo.URLs.ASN},
	} {
		geoMap.Content = append(geoMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv[0]},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv[1]},
		)
	}
	setNodeValue(doc, "geox-url", geoMap)
}

// removeGeoFieldsNode deletes geodata keys from the mapping node.
func removeGeoFieldsNode(doc *yaml.Node) {
	for _, k := range []string{
		"geodata-mode", "geodata-loader", "geo-auto-update",
		"geo-update-interval", "geox-url",
	} {
		deleteNodeKey(doc, k)
	}
}

// ── warp proxy (yaml.Node path) ───────────────────────────────────────────────

// patchWarpProxy finds or appends the warp proxy in the document's proxies
// sequence. All other proxies and all rules are left untouched.
func patchWarpProxy(doc *yaml.Node, cfg *config.Config, profile *wgcf.Profile, reserved [3]byte, log *logging.Logger) error {
	warpNode := buildWarpProxy(cfg, profile, reserved)

	proxiesNode := getMappingValue(doc, "proxies")
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		// No proxies section — create one.
		proxiesNode = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setNodeValue(doc, "proxies", proxiesNode)
	}

	idx := findProxyByNameNode(proxiesNode, "warp")
	if idx < 0 {
		log.Debug("mihomo: warp proxy not found — appending to proxies list")

		// Special case: proxies is empty and the sole rule is MATCH,DIRECT —
		// this is exactly the minimal template from USE_WARP_CONFIG=false.
		if len(proxiesNode.Content) == 0 && isMinimalTemplateNode(doc) {
			rulesNode := getMappingValue(doc, "rules")
			if rulesNode != nil && len(rulesNode.Content) == 1 {
				rulesNode.Content[0].Value = "MATCH,warp"
				log.Debug("mihomo: replaced MATCH,DIRECT with MATCH,warp in minimal template config")
			}
		}

		proxiesNode.Content = append(proxiesNode.Content, warpNode)
		return nil
	}

	// Replace the existing warp entry in-place — consistent key order.
	proxiesNode.Content[idx] = warpNode
	return nil
}

// isMinimalTemplateNode returns true when the document has no proxies and
// exactly one rule "MATCH,DIRECT" — the exact shape produced by createTemplate
// with USE_WARP_CONFIG=false.
func isMinimalTemplateNode(doc *yaml.Node) bool {
	proxiesNode := getMappingValue(doc, "proxies")
	if proxiesNode != nil && len(proxiesNode.Content) != 0 {
		return false
	}
	rulesNode := getMappingValue(doc, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode || len(rulesNode.Content) != 1 {
		return false
	}
	return rulesNode.Content[0].Value == "MATCH,DIRECT"
}

// ── warp proxy builder ────────────────────────────────────────────────────────

// buildWarpProxy constructs the warp proxy as a *yaml.Node with an explicit
// key order so the serialised config is easy to read:
//
//	name → type → server → port → ip → ipv6 → public-key → private-key →
//	reserved → udp → mtu → remote-dns-resolve → dns →
//	refresh-server-ip-interval → amnezia-wg-option
func buildWarpProxy(cfg *config.Config, profile *wgcf.Profile, reserved [3]byte) *yaml.Node {
	server, port := splitEndpoint(cfg.Warp.Endpoint)
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addStr := func(k, v string) {
		n.Content = append(n.Content, strNode(k), strNode(v))
	}
	addInt := func(k string, v int) {
		n.Content = append(n.Content, strNode(k), intNode(v))
	}
	addBool := func(k string, v bool) {
		n.Content = append(n.Content, strNode(k), boolNode(v))
	}

	addStr("name", "warp")
	addStr("type", "wireguard")
	addStr("client-fingerprint", "chrome")
	addStr("server", server)
	addInt("port", port)
	addStr("ip", profile.IPv4)
	addStr("ipv6", profile.IPv6)
	addStr("public-key", profile.PublicKey)
	addStr("private-key", profile.PrivateKey)

	if reserved != [3]byte{0, 0, 0} {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, b := range reserved {
			seq.Content = append(seq.Content, intNode(int(b)))
		}
		n.Content = append(n.Content, strNode("reserved"), seq)
	}

	addBool("udp", true)
	addInt("mtu", 1280)
	addBool("remote-dns-resolve", true)

	dnsSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, d := range cfg.Warp.DNS {
		dnsSeq.Content = append(dnsSeq.Content, strNode(d))
	}
	n.Content = append(n.Content, strNode("dns"), dnsSeq)
	addInt("refresh-server-ip-interval", 60)

	if cfg.Warp.Amnezia.Enabled {
		n.Content = append(n.Content, strNode("amnezia-wg-option"), buildAmneziaNode(cfg))
	}

	return n
}

// buildAmneziaNode constructs the amnezia-wg-option as a *yaml.Node with
// explicit key order: jc → jmin → jmax → s1 → s2 → h1…h4 → i1…i5.
func buildAmneziaNode(cfg *config.Config) *yaml.Node {
	a := cfg.Warp.Amnezia
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addInt := func(k string, v int) {
		n.Content = append(n.Content, strNode(k), intNode(v))
	}
	addStr := func(k, v string) {
		n.Content = append(n.Content, strNode(k), strNode(v))
	}

	addInt("jc", a.JC)
	addInt("jmin", a.JMin)
	addInt("jmax", a.JMax)
	addInt("s1", 0)
	addInt("s2", 0)
	addInt("h1", 1)
	addInt("h2", 2)
	addInt("h3", 3)
	addInt("h4", 4)
	for i, val := range a.I {
		if val != "" {
			addStr(fmt.Sprintf("i%d", i+1), val)
		}
	}
	return n
}

// ── yaml.Node helpers ─────────────────────────────────────────────────────────

// docMapping unwraps a DocumentNode and returns the root MappingNode.
func docMapping(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		if root.Content[0].Kind == yaml.MappingNode {
			return root.Content[0]
		}
	}
	if root.Kind == yaml.MappingNode {
		return root
	}
	return nil
}

// getMappingValue returns the value node for the given key, or nil.
func getMappingValue(doc *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			return doc.Content[i+1]
		}
	}
	return nil
}

// setNodeScalar sets key=value (scalar) in the mapping, updating in place or
// appending if the key does not exist.
func setNodeScalar(doc *yaml.Node, key, tag, value string) {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			doc.Content[i+1].Kind = yaml.ScalarNode
			doc.Content[i+1].Tag = tag
			doc.Content[i+1].Value = value
			doc.Content[i+1].Content = nil
			return
		}
	}
	doc.Content = append(doc.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
	)
}

// setNodeValue sets key=node in the mapping, updating in place or appending.
func setNodeValue(doc *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			doc.Content[i+1] = val
			return
		}
	}
	doc.Content = append(doc.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val,
	)
}

// deleteNodeKey removes a key-value pair from the mapping.
func deleteNodeKey(doc *yaml.Node, key string) {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			doc.Content = append(doc.Content[:i], doc.Content[i+2:]...)
			return
		}
	}
}

// findProxyByNameNode returns the index of the first element in a sequence
// node whose "name" field equals name, or -1 if not found.
func findProxyByNameNode(seq *yaml.Node, name string) int {
	for i, item := range seq.Content {
		if item.Kind == yaml.MappingNode && yamlNodeName(item) == name {
			return i
		}
	}
	return -1
}

// yamlNodeName extracts the value of the "name" key from a YAML mapping node.
func yamlNodeName(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "name" {
			return n.Content[i+1].Value
		}
	}
	return ""
}

// ── scalar node constructors ─────────────────────────────────────────────────

func strNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func intNode(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("%d", v)}
}

func boolNode(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: boolStr(v)}
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// ── map[string]any helpers (createTemplate only) ─────────────────────────────

func applyOwnedFieldsMap(doc map[string]any, cfg *config.Config) {
	doc["mixed-port"] = int(cfg.ProxyPort)
	doc["log-level"] = cfg.ProxyLogLevel
	doc["ipv6"] = cfg.UseIP6
	doc["allow-lan"] = true
	doc["bind-address"] = "*"

	if cfg.ProxyUser != "" && cfg.ProxyPass != "" {
		doc["authentication"] = []any{cfg.ProxyUser + ":" + cfg.ProxyPass}
	} else {
		doc["authentication"] = []any{}
	}
}

func applyGeoFieldsMap(doc map[string]any, cfg *config.Config) {
	doc["geodata-mode"] = true
	doc["geodata-loader"] = "memconservative"
	doc["geo-auto-update"] = cfg.Geo.AutoUpdate
	doc["geo-update-interval"] = 24
	doc["geox-url"] = map[string]any{
		"geoip":   cfg.Geo.URLs.GeoIP,
		"geosite": cfg.Geo.URLs.GeoSite,
		"mmdb":    cfg.Geo.URLs.MMDB,
		"asn":     cfg.Geo.URLs.ASN,
	}
}

// ── endpoint helper ───────────────────────────────────────────────────────────

// splitEndpoint splits "host:port" into host string and port int.
// Uses net.SplitHostPort for robustness; endpoint is pre-validated by validateWarpEndpoint.
func splitEndpoint(endpoint string) (string, int) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}

// ── write helpers ─────────────────────────────────────────────────────────────

// writeConfigNode marshals a yaml.Node tree and atomically writes it to path.
func writeConfigNode(path string, root *yaml.Node) error {
	data, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return atomicWrite(path, data)
}

// writeConfigMap marshals a map[string]any and atomically writes it to path.
// Used only by createTemplate where order is not critical.
func writeConfigMap(path string, doc map[string]any) error {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return atomicWrite(path, data)
}

// atomicWrite writes data to path via a temp file rename.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config_write_*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpName, path)
}
