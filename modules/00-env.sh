# shellcheck shell=sh
# Guard, чтобы не подгружать модуль повторно
[ -n "${MWP_ENV_SH_LOADED:-}" ] && return 0
MWP_ENV_SH_LOADED=1

# Hard environment settings
set -eu
set -o pipefail 2>/dev/null || true

# Basic environment variables
SCRIPT_PID=$$
SCRIPT_VERSION_FILE="/app/script_version.sh"
SCRIPT_LOG_LEVEL=${SCRIPT_LOG_LEVEL:-WARN}

# Hard PATH and other hardening
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
unset CDPATH || true
umask 077

# Load the script version if available
[ -r "$SCRIPT_VERSION_FILE" ] && . "$SCRIPT_VERSION_FILE"

TZ=${TZ:-UTC}
TEMP_FILES=""
SHUTDOWN_REQUESTED=false
CHILD_PIDS_DIR=""
SIGNAL_RECEIVED=""
MULTI_USER_MODE=${MULTI_USER_MODE:-true}

# Mihomo (clash meta)
MIHOMO_BIN="/usr/local/bin/mihomo"
MIHOMO_DATA="/app/mihomo"
MIHOMO_CONFIG_FILE="$MIHOMO_DATA/config.yaml"

PROXY_UID_ENV=${PROXY_UID:-}
PROXY_GID_ENV=${PROXY_GID:-}

PROXY_LOG_LEVEL=${PROXY_LOG_LEVEL:-info}

PROXY_PORT=${PROXY_PORT:-7890}
PROXY_USER=${PROXY_USER:-}
PROXY_PASS=${PROXY_PASS:-}

# GEO data
GEO=${GEO:-true}
GEO_REDOWNLOAD=${GEO_REDOWNLOAD:-false}
GEO_AUTH_USER=${GEO_AUTH_USER:-}
GEO_AUTH_PASS=${GEO_AUTH_PASS:-}
readonly GEO_BASE_URL="https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest"
readonly GEO_URL_GEOIP=${GEO_URL_GEOIP:-"$GEO_BASE_URL/geoip.dat"}
readonly GEO_URL_GEOSITE=${GEO_URL_GEOSITE:-"$GEO_BASE_URL/geosite.dat"}
readonly GEO_URL_MMDB=${GEO_URL_MMDB:-"$GEO_BASE_URL/geoip.metadb"}
readonly GEO_URL_ASN=${GEO_URL_ASN:-"$GEO_BASE_URL/GeoLite2-ASN.mmdb"}

# ip6
USE_IP6=${USE_IP6:-true}

# WARP wgcf
WGCF_DATA="/app/wgcf"
WGCF_BIN="/usr/local/bin/wgcf"
WGCF_ACCOUNT_FILE="$WGCF_DATA/wgcf-account.toml"
WGCF_PROFILE_FILE="$WGCF_DATA/wgcf-profile.conf"

USE_WARP_CONFIG=${USE_WARP_CONFIG:-true}
WARP_PLUS_KEY=${WARP_PLUS_KEY:-}
WARP_REGENERATE=${WARP_REGENERATE:-false}

WARP_ENDPOINT=${WARP_ENDPOINT:-engage.cloudflareclient.com:2408}
WARP_DNS=${WARP_DNS:-1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001}

WARP_AMNEZIA=${WARP_AMNEZIA:-false}
WARP_AMNEZIA_JC=${WARP_AMNEZIA_JC:-}
WARP_AMNEZIA_JMIN=${WARP_AMNEZIA_JMIN:-}
WARP_AMNEZIA_JMAX=${WARP_AMNEZIA_JMAX:-}
WARP_AMNEZIA_I1=${WARP_AMNEZIA_I1:-}
WARP_AMNEZIA_I2=${WARP_AMNEZIA_I2:-}
WARP_AMNEZIA_I3=${WARP_AMNEZIA_I3:-}
WARP_AMNEZIA_I4=${WARP_AMNEZIA_I4:-}
WARP_AMNEZIA_I5=${WARP_AMNEZIA_I5:-}
WARP_AMNEZIA_J1=${WARP_AMNEZIA_J1:-}
WARP_AMNEZIA_J2=${WARP_AMNEZIA_J2:-}
WARP_AMNEZIA_J3=${WARP_AMNEZIA_J3:-}
WARP_AMNEZIA_ITIME=${WARP_AMNEZIA_ITIME:-}

# exit trap - will be defined in other modules.
trap '' TERM INT HUP
