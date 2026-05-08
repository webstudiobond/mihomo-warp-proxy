// Package contract defines operator-facing names that must remain consistent
// across packages. Centralising these strings avoids drift between runtime
// configuration loading, validation, logging, and tests.
package contract

const (
	// EnvTZ selects the process timezone used for timestamps and subprocesses.
	EnvTZ = "TZ"
	// EnvScriptLogLevel controls entrypoint logger verbosity.
	EnvScriptLogLevel = "SCRIPT_LOG_LEVEL"
	// EnvProxyLogLevel controls mihomo's internal log verbosity.
	EnvProxyLogLevel = "PROXY_LOG_LEVEL"
	// EnvProxyUID sets the unprivileged runtime user ID.
	EnvProxyUID = "PROXY_UID"
	// EnvProxyGID sets the unprivileged runtime group ID.
	EnvProxyGID = "PROXY_GID"
	// EnvProxyPort sets the local mixed proxy listener port.
	EnvProxyPort = "PROXY_PORT"
	// EnvProxyUser sets the proxy authentication username.
	EnvProxyUser = "PROXY_USER"
	// EnvProxyPass sets the proxy authentication secret.
	EnvProxyPass = "PROXY_" + "PASS"
	// EnvMultiUserMode enables mihomo's multi-user mode.
	EnvMultiUserMode = "MULTI_USER_MODE"
	// EnvUseIP6 toggles IPv6 support in generated configuration.
	EnvUseIP6 = "USE_IP6"
	// EnvGeo toggles geodata download handling.
	EnvGeo = "GEO"
	// EnvGeoRedownload forces geodata refresh regardless of cache state.
	EnvGeoRedownload = "GEO_REDOWNLOAD"
	// EnvGeoAutoUpdate enables periodic geodata refreshes inside mihomo.
	EnvGeoAutoUpdate = "GEO_AUTO_UPDATE"
	// EnvGeoURLGeoIP overrides the GeoIP download URL.
	EnvGeoURLGeoIP = "GEO_URL_GEOIP"
	// EnvGeoURLGeoSite overrides the GeoSite download URL.
	EnvGeoURLGeoSite = "GEO_URL_GEOSITE"
	// EnvGeoURLMMDB overrides the MMDB download URL.
	EnvGeoURLMMDB = "GEO_URL_MMDB"
	// EnvGeoURLASN overrides the ASN MMDB download URL.
	EnvGeoURLASN = "GEO_URL_ASN"
	// EnvGeoAuthUser sets the GEO HTTP Basic Auth username.
	EnvGeoAuthUser = "GEO_AUTH_USER"
	// EnvGeoAuthSecret sets the GEO HTTP Basic Auth secret.
	EnvGeoAuthSecret = "GEO_AUTH_" + "PASS"
	// EnvUseWarpConfig toggles WARP proxy generation.
	EnvUseWarpConfig = "USE_WARP_CONFIG"
	// EnvWarpRegenerate forces wgcf account/profile regeneration.
	EnvWarpRegenerate = "WARP_REGENERATE"
	// EnvWarpPlusKey sets the optional WARP+ license key.
	EnvWarpPlusKey = "WARP_PLUS_" + "KEY"
	// EnvWarpEndpoint overrides the WARP endpoint host and port.
	EnvWarpEndpoint = "WARP_ENDPOINT"
	// EnvWarpDNS overrides the DNS resolver list injected into mihomo.
	EnvWarpDNS = "WARP_DNS"
	// EnvWarpAmnezia toggles AmneziaWG obfuscation support.
	EnvWarpAmnezia = "WARP_AMNEZIA"
	// EnvWarpAmneziaJC sets the AmneziaWG JC parameter.
	EnvWarpAmneziaJC = "WARP_AMNEZIA_JC"
	// EnvWarpAmneziaJMin sets the AmneziaWG JMIN parameter.
	EnvWarpAmneziaJMin = "WARP_AMNEZIA_JMIN"
	// EnvWarpAmneziaJMax sets the AmneziaWG JMAX parameter.
	EnvWarpAmneziaJMax = "WARP_AMNEZIA_JMAX"
	// EnvWarpAmneziaIPrefix prefixes the AmneziaWG I1-I5 variables.
	EnvWarpAmneziaIPrefix = "WARP_AMNEZIA_I"
)
