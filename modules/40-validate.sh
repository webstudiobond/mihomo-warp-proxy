# shellcheck shell=sh
# Guard
[ -n "${MWP_VALIDATE_SH_LOADED:-}" ] && return 0
MWP_VALIDATE_SH_LOADED=1

# Helper function to validate file paths
validate_path() {
  local path="$1"
  local var_name="$2"
  local clean_path parent_path
  
  # Basic validation: must be non-empty and absolute path
  [ -n "$path" ] || err_exit "$var_name cannot be empty"
  case "$path" in
    /*) ;;
    *) err_exit "$var_name must be an absolute path: $path" ;;
  esac
  
  # Check for null bytes and control characters (most critical security check)
  if printf '%s' "$path" | od -An -tx1 | grep -qE '(^| )(00|0[1-9a-f]|1[0-9a-f]|7f)( |$)'; then
    err_exit "$var_name contains null bytes or control characters"
  fi
  
  # Comprehensive directory traversal protection
  case "$path" in
    # Standard traversal patterns
    */../*|*/..*|../*|*/..) 
      err_exit "$var_name contains directory traversal: $path" ;;
    # Hidden traversal and malformed paths  
    */./*|*/.|.*/*|*//*)
      err_exit "$var_name contains malformed path components: $path" ;;
    # Whitespace and dangerous characters
    *[[:space:]]*|*'
'*|*' '*)
      err_exit "$var_name contains whitespace or newlines: $path" ;;
  esac
  
  # Block access to sensitive system directories
  case "$path" in
    /dev/*|/proc/*|/sys/*|/run/*|/tmp/..*)
      err_exit "$var_name points to restricted system location: $path" ;;
    # Block potential container escapes
    /var/run/docker.sock|/var/run/containerd/*|/.dockerenv)
      err_exit "$var_name points to container runtime files: $path" ;;
  esac
  
  # Path length validation (prevent buffer overflows)
  if [ ${#path} -gt 4096 ]; then
    err_exit "$var_name exceeds maximum path length (4096): ${#path}"
  fi
  
  # Validate individual path components
  clean_path="$path"
  while [ "$clean_path" != "/" ]; do
    component=$(basename "$clean_path")
    # Check component length
    if [ ${#component} -gt 255 ]; then
      err_exit "$var_name contains component longer than 255 characters: $component"
    fi
    # Check for dangerous component patterns
    case "$component" in
      .*..* | *..* | *..*) 
        err_exit "$var_name contains dangerous component: $component" ;;
    esac
    clean_path=$(dirname "$clean_path")
  done
  
  # Optional additional validation with realpath (non-critical)
  # Only attempt if we have permission to read parent directories
  if command -v realpath >/dev/null 2>&1; then
    parent_path=$(dirname "$path")
    # Only validate if parent is readable to avoid permission errors
    if [ -r "$parent_path" ] 2>/dev/null; then
      canonical_path=$(realpath -m "$path" 2>/dev/null || true)
      if [ -n "$canonical_path" ]; then
        case "$canonical_path" in
          /dev/*|/proc/*|/sys/*|/run/*)
            err_exit "$var_name canonically resolves to restricted location: $canonical_path"
            ;;
        esac
      fi
    fi
  fi
  
  return 0
}

# Helper function to validate numeric environment variables
validate_numeric_env() {
  local var_name="$1"
  local value="$2"
  local min="$3"
  local max="$4"
  
  case "$value" in
    ''|*[!0-9]*) err_exit "$var_name must be a valid number: $value" ;;
  esac
  
  if [ "$value" -lt "$min" ] || [ "$value" -gt "$max" ]; then
    err_exit "$var_name must be between $min-$max: $value"
  fi
}

# Helper function to validate DNS entry format
is_valid_dns() {
  local dns="$1"
  case "$dns" in
    # IPv4 address
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) return 0 ;;
    # IPv6 address (simplified check)
    *:*) return 0 ;;
    # DoT (DNS over TLS)
    tls://*) return 0 ;;
    # DoH (DNS over HTTPS)  
    https://*) return 0 ;;
    # DoQ (DNS over QUIC)
    quic://*) return 0 ;;
    # Invalid format
    *) return 1 ;;
  esac
}

# Helper function to validate proxy credentials
validate_proxy_credentials() {
  local user="$1"
  local pass="$2"
  
  # Check for empty credentials
  [ -n "$user" ] || err_exit "PROXY_USER cannot be empty"
  [ -n "$pass" ] || err_exit "PROXY_PASS cannot be empty"
  
  # Length validation (reasonable limits)
  if [ ${#user} -gt 64 ]; then
    err_exit "PROXY_USER too long (max 64 characters): ${#user}"
  fi
  if [ ${#pass} -gt 128 ]; then
    err_exit "PROXY_PASS too long (max 128 characters): ${#pass}"
  fi
  
  # Character validation for username
  case "$PROXY_USER" in
    *:*) err_exit "PROXY_USER cannot contain colon characters" ;;
    *[\"\'\\$\`]*) err_exit "PROXY_USER cannot contain quotes, backslashes, dollar signs, or backticks" ;;
    *[[:space:]]*) err_exit "PROXY_USER cannot contain whitespace characters" ;;
    *[[:cntrl:]]*) err_exit "PROXY_USER cannot contain control characters" ;;
  esac
  
  # Character validation for password
  case "$PROXY_PASS" in
    *:*) err_exit "PROXY_PASS cannot contain colon characters" ;;
    *[\"\'\\$\`]*) err_exit "PROXY_PASS cannot contain quotes, backslashes, dollar signs, or backticks" ;;
    *[[:cntrl:]]*) err_exit "PROXY_PASS cannot contain control characters" ;;
  esac
  
  # Additional security: check for null bytes using od
  if printf '%s' "$user" | od -An -tx1 | grep -qE '(^| )00( |$)'; then
    err_exit "PROXY_USER contains null bytes"
  fi
  if printf '%s' "$pass" | od -An -tx1 | grep -qE '(^| )00( |$)'; then
    err_exit "PROXY_PASS contains null bytes"
  fi
}

# Helper function to validate warp endpoint (server:port)
validate_warp_endpoint() {
    endpoint="$1"

    # host:port
    host="${endpoint%:*}"
    port="${endpoint##*:}"

    # port
    case "$port" in
        2408|500|1701|4500) ;;
        *) err_exit "Invalid WARP endpoint port: $port (allowed: 2408, 500, 1701, 2408, 4500)" ;;
    esac

    # engage.cloudflareclient.com — ок
    if [ "$host" = "engage.cloudflareclient.com" ]; then
        return 0
    fi

    # Everything else is prohibited.
    err_exit "Invalid WARP endpoint host: $host (only engage.cloudflareclient.com allowed)"
}

# Helper function to validate DNS string
validate_dns_string() {
  local dns_string="$1"
  local dns_entry dns_count
  
  [ -n "$dns_string" ] || err_exit "WARP_DNS cannot be empty"
  
  # Count DNS entries and validate each
  dns_count=0
  oldIFS=$IFS
  IFS=','
  for dns_entry in $dns_string; do
    dns_entry=$(printf '%s' "$dns_entry" | tr -d ' \t\r\n')
    [ -n "$dns_entry" ] || continue
    
    dns_count=$((dns_count + 1))
    if [ "$dns_count" -gt 8 ]; then
      err_exit "Too many DNS entries (max 8): $dns_count"
    fi
    
    if ! is_valid_dns "$dns_entry"; then
      err_exit "Invalid DNS entry: $dns_entry"
    fi
  done
  IFS=$oldIFS
  
  if [ "$dns_count" -eq 0 ]; then
    err_exit "No valid DNS entries found in WARP_DNS"
  fi
}

# Helper function to get Amnezia parameters 
get_amnezia_var() {
  name=$1
  case "$name" in
    WARP_AMNEZIA)    printf '%s' "$WARP_AMNEZIA"; return 0 ;;
    WARP_AMNEZIA_JC) printf '%s' "$WARP_AMNEZIA_JC"; return 0 ;;
    WARP_AMNEZIA_JMIN) printf '%s' "$WARP_AMNEZIA_JMIN"; return 0 ;;
    WARP_AMNEZIA_JMAX) printf '%s' "$WARP_AMNEZIA_JMAX"; return 0 ;;
    WARP_AMNEZIA_I1) printf '%s' "$WARP_AMNEZIA_I1"; return 0 ;;
    WARP_AMNEZIA_I2) printf '%s' "$WARP_AMNEZIA_I2"; return 0 ;;
    WARP_AMNEZIA_I3) printf '%s' "$WARP_AMNEZIA_I3"; return 0 ;;
    WARP_AMNEZIA_I4) printf '%s' "$WARP_AMNEZIA_I4"; return 0 ;;
    WARP_AMNEZIA_I5) printf '%s' "$WARP_AMNEZIA_I5"; return 0 ;;
    WARP_AMNEZIA_J1) printf '%s' "$WARP_AMNEZIA_J1"; return 0 ;;
    WARP_AMNEZIA_J2) printf '%s' "$WARP_AMNEZIA_J2"; return 0 ;;
    WARP_AMNEZIA_J3) printf '%s' "$WARP_AMNEZIA_J3"; return 0 ;;
    WARP_AMNEZIA_ITIME) printf '%s' "$WARP_AMNEZIA_ITIME"; return 0 ;;
    *) return 1 ;;
  esac
}

# Helper function to validate Amnezia numeric parameters 
validate_amnezia_num_params() {
  for param_name in WARP_AMNEZIA_JC WARP_AMNEZIA_JMIN WARP_AMNEZIA_JMAX WARP_AMNEZIA_ITIME; do
    param_value=$(get_amnezia_var "$param_name" || true)

    # Log input for debugging
    # log "DEBUG" "$param_name value: $(printf '%s' "$param_value" | cut -c1-50)"

    case "$param_value" in
      ''|*[!0-9]*) err_exit "$param_name must be numeric: $param_value" ;;
      *)
        case "$param_name" in
          WARP_AMNEZIA_JC)
            if [ "$param_value" -lt 0 ] || [ "$param_value" -gt 128 ]; then
              err_exit "Out of valid range (0 <= jc <= 128), $param_name: $param_value"
            fi
            ;;
          WARP_AMNEZIA_JMIN)
            if [ "$param_value" -lt 0 ] || [ "$param_value" -ge "$WARP_AMNEZIA_JMAX" ]; then
              err_exit "Out of valid range (0 <= jmin < jmax <= 1280), $param_name: $param_value, WARP_AMNEZIA_JMAX: $WARP_AMNEZIA_JMAX"
            fi
            ;;
          WARP_AMNEZIA_JMAX)
            if [ "$param_value" -le "$WARP_AMNEZIA_JMIN" ] || [ "$param_value" -gt 1280 ]; then
              err_exit "Out of valid range (0 <= jmin < jmax <= 1280), WARP_AMNEZIA_JMIN: $WARP_AMNEZIA_JMIN, $param_name: $param_value"
            fi
            ;;
          WARP_AMNEZIA_ITIME)
            if [ "$param_value" -lt 0 ] || [ "$param_value" -gt 120 ]; then
              err_exit "Out of valid range (0 <= itime <= 120), $param_name: $param_value"
            fi
            ;;
        esac
        ;;
    esac
  done
}

# Helper function to validate Amnezia string parameters 
validate_amnezia_string_params() {
  for param_name in WARP_AMNEZIA_I1 WARP_AMNEZIA_I2 WARP_AMNEZIA_I3 WARP_AMNEZIA_I4 WARP_AMNEZIA_I5 \
                   WARP_AMNEZIA_J1 WARP_AMNEZIA_J2 WARP_AMNEZIA_J3; do
    param_value=$(get_amnezia_var "$param_name" || true)
    if [ -n "$param_value" ]; then
      # Check total length
      param_length=${#param_value}
      if [ "$param_length" -gt 10000 ]; then
        err_exit "$param_name too long (max 10000 characters): $param_length"
      fi

      # Log input for debugging
      # log "DEBUG" "$param_name value: $(printf '%s' "$param_value" | cut -c1-50)"

      # Parse tags sequentially
      temp_value="$param_value"
      pos=0
      value_length=${#temp_value}
      while [ $pos -lt $value_length ]; do
        case "$temp_value" in
          "<b 0x"*)
            hex_part="${temp_value#<b 0x}"
            hex_part="${hex_part%%>*}"
            case "$hex_part" in
              *[!0-9a-fA-F]*)
                log "ERROR" "Invalid hex in <b> tag for $param_name: $(printf '%s' "$hex_part" | cut -c1-50)"
                err_exit "$param_name has invalid hex format in <b> tag"
                ;;
            esac
            tag="<b 0x$hex_part>"
            if [ "${temp_value#"$tag"}" = "$temp_value" ]; then
              log "ERROR" "Invalid <b> tag structure for $param_name: $(printf '%s' "$temp_value" | cut -c1-50)"
              err_exit "$param_name has invalid hex format in <b> tag"
            fi
            temp_value="${temp_value#"$tag"}"
            ;;
          "<c>"*)
            temp_value="${temp_value#<c>}"
            ;;
          "<t>"*)
            temp_value="${temp_value#<t>}"
            ;;
          "<r "[0-9]*">"*)
            num_part="${temp_value#<r }"
            num_part="${num_part%%>*}"
            case "$num_part" in
              *[!0-9]*)
                log "ERROR" "Invalid number in <r> tag for $param_name: $num_part"
                err_exit "$param_name has invalid <r> tag format"
                ;;
            esac
            r_length="$num_part"
            if [ "$r_length" -lt 0 ] || [ "$r_length" -gt 1000 ]; then
              log "ERROR" "Invalid length in <r> tag for $param_name: $r_length"
              err_exit "$param_name has invalid length in <r> tag (must be 0 to 1000)"
            fi
            tag="<r $r_length>"
            temp_value="${temp_value#"$tag"}"
            ;;
          "<wt "[0-9]*">"*)
            num_part="${temp_value#<wt }"
            num_part="${num_part%%>*}"
            case "$num_part" in
              *[!0-9]*)
                log "ERROR" "Invalid number in <wt> tag for $param_name: $num_part"
                err_exit "$param_name has invalid <wt> tag format"
                ;;
            esac
            wt_length="$num_part"
            if [ "$wt_length" -lt 0 ] || [ "$wt_length" -gt 5000 ]; then
              log "ERROR" "Invalid length in <wt> tag for $param_name: $wt_length"
              err_exit "$param_name has invalid length in <wt> tag (must be 0 to 5000)"
            fi
            tag="<wt $wt_length>"
            temp_value="${temp_value#"$tag"}"
            ;;
          *"</"*)
            log "ERROR" "Closing tags not allowed for $param_name: $(printf '%s' "$temp_value" | cut -c1-50)"
            err_exit "$param_name contains closing tags"
            ;;
          *)
            log "ERROR" "Invalid tag structure for $param_name: $(printf '%s' "$temp_value" | cut -c1-50)"
            err_exit "$param_name contains invalid characters or tag structure"
            ;;
        esac
        # Update position to avoid infinite loop
        new_length=${#temp_value}
        if [ "$new_length" -eq "$value_length" ] && [ -n "$temp_value" ]; then
          log "ERROR" "No progress in parsing $param_name: $(printf '%s' "$temp_value" | cut -c1-50)"
          err_exit "$param_name contains unparseable content"
        fi
        value_length="$new_length"
      done
    fi
  done
}

# Helper function to validate Amnezia parameters 
validate_amnezia_params() {
  local param_name param_value

  validate_amnezia_num_params
  
  validate_amnezia_string_params
}

# Helper function to resolve hostname to IP addresses
resolve_hostname() {
  local hostname="$1"
  local resolved_ips tmpf
  # Prefer getent, then dig (A/AAAA separately), then nslookup fallback.
  if command -v getent >/dev/null 2>&1; then
    resolved_ips=$(getent ahosts "$hostname" 2>/dev/null | awk '{ print $1 }' | sort -u)
  else
    resolved_ips=""
    if command -v dig >/dev/null 2>&1; then
      A=$(dig +short A "$hostname" 2>/dev/null || true)
      AAAA=$(dig +short AAAA "$hostname" 2>/dev/null || true)
      resolved_ips=$(printf '%s\n%s\n' "$A" "$AAAA" | sed '/^$/d' | sort -u)
    elif command -v nslookup >/dev/null 2>&1; then
      resolved_ips=$(nslookup "$hostname" 2>/dev/null | awk '/^Address:/{print $2}' | sort -u)
    fi
  fi

  # Return unique addresses (A/AAAA). Actual security checks are in validate_resolved_ips().
  printf '%s\n' "$resolved_ips" | sed '/^$/d' | sort -u | head -100
}

# Helper function to check if IP is in restricted range
is_restricted_ip() {
  local ip="$1"
  # Return 0 = restricted/blocked, 1 = allowed.
  case "$ip" in
    # Unspecified / loopback / localhost
    0.0.0.0|127.*|::1) return 0 ;;
    # RFC1918 private ranges
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    # Carrier-grade NAT (100.64.0.0/10)
    100.6[4-9].*|100.7[0-9].*|100.8[0-9].*|100.9[0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 0 ;;
    # Link-local and metadata
    169.254.*|fe80:*|fe80:*) return 0 ;;
    # IPv6 unique local and deprecated site-local
    fc00:*|fd00:*|fec0:* ) return 0 ;;
    # IPv4-mapped IPv6 addresses: ::ffff:a.b.c.d
    ::ffff:* ) 
      # extract trailing IPv4 and re-check
      tail=$(printf '%s' "$ip" | sed -n 's/^::ffff:\(.*\)$/\1/p')
      case "$tail" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*|0.0.0.0|169.254.*) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    *) return 1 ;; # Default: allowed
  esac
}

# Helper function to validate resolved IPs
validate_resolved_ips() {
  local hostname="$1"
  local resolved_ips tmpf ip

  resolved_ips=$(resolve_hostname "$hostname")
  if [ -z "$resolved_ips" ]; then
    err_exit "No IPs resolved for hostname: $hostname — refusing (only external addresses allowed)"
  fi

  # iterate without using a pipeline (so `return` works)
  tmpf=$(mktemp) || return 1
  printf '%s\n' "$resolved_ips" | sed '/^$/d' > "$tmpf"
  if [ ! -s "$tmpf" ]; then
    rm -f "$tmpf"
    err_exit "No IPs available after resolution for $hostname"
  fi

  while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    if is_restricted_ip "$ip"; then
      rm -f "$tmpf"
      err_exit "Hostname $hostname resolves to restricted IP: $ip"
    fi
  done < "$tmpf"
  rm -f "$tmpf"
  return 0
}

# Helper function to validate IPv4 address
validate_ipv4() {
  local ip="$1"
  case "$ip" in
    '') err_exit "IPv4 address is empty" ;;
    *.*.*.*) 
      local IFS='.'
      set -- $ip
      [ $# -eq 4 ] || err_exit "Invalid IPv4 format: $ip"
      for octet in "$@"; do
        case "$octet" in
          ''|*[!0-9]*) err_exit "Invalid IPv4 octet: $octet in $ip" ;;
          *) [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || err_exit "IPv4 octet out of range: $octet in $ip" ;;
        esac
      done
      ;;
    *) err_exit "Invalid IPv4 format: $ip" ;;
  esac
}

# Helper function to validate IPv6 address (basic validation)
validate_ipv6() {
  local ip="$1"
  case "$ip" in
    '') err_exit "IPv6 address is empty" ;;
    *:*) 
      # Basic IPv6 format check - contains colons and valid hex characters
      case "$ip" in
        *[^0-9a-fA-F:]*) err_exit "Invalid IPv6 characters: $ip" ;;
        ::*|*::*|*::) ;;  # Allow double colon notation
        *:::*) err_exit "Invalid IPv6 format (triple colon): $ip" ;;
      esac
      ;;
    *) err_exit "Invalid IPv6 format: $ip" ;;
  esac
}

# Helper function to validate warp profile KEYs & IPs
validate_warp_profile_params() {
    log "DEBUG" "Validate WARP Private KEY"
    # Проверка ключей
    case "$WARP_PRIVATE_KEY" in
        [A-Za-z0-9+/=]*) [ "${#WARP_PRIVATE_KEY}" -eq 44 ] || err_exit "Invalid WARP_PRIVATE_KEY length" ;;
        *) err_exit "Invalid WARP_PRIVATE_KEY format" ;;
    esac

    log "DEBUG" "Validate WARP Public KEY"
    case "$WARP_PUBLIC_KEY" in
        [A-Za-z0-9+/=]*) [ "${#WARP_PUBLIC_KEY}" -eq 44 ] || err_exit "Invalid WARP_PUBLIC_KEY length" ;;
        *) err_exit "Invalid WARP_PUBLIC_KEY format" ;;
    esac

    log "DEBUG" "Validate WARP IPv4"
    if [ -n "$WARP_IPV4" ]; then
        validate_ipv4 "$WARP_IPV4" || err_exit "Invalid WARP_IPV4: $WARP_IPV4"
    fi

    log "DEBUG" "Validate WARP IPv6"
    if [ -n "$WARP_IPV6" ]; then
        validate_ipv6 "$WARP_IPV6" || err_exit "Invalid WARP_IPV6: $WARP_IPV6"
    fi
}

# Helper function to validate environment variables
validate_environment() {
  log "DEBUG" "Validate environment variables"

  # Validate file paths for directory traversal
  validate_path "$MIHOMO_DATA" "MIHOMO_DATA"
  validate_path "$MIHOMO_CONFIG_FILE" "MIHOMO_CONFIG_FILE"
  validate_path "$WGCF_DATA" "WGCF_DATA"

  # Validate credentials only if both are provided
  log "DEBUG" "Validate PROXY_USER & PROXY_PASS"
  if [ -n "$PROXY_USER" ] && [ -n "$PROXY_PASS" ]; then
    validate_proxy_credentials "$PROXY_USER" "$PROXY_PASS"
  elif [ -n "$PROXY_USER" ] && [ -z "$PROXY_PASS" ]; then
    err_exit "PROXY_PASS must be set when PROXY_USER is provided"
  elif [ -z "$PROXY_USER" ] && [ -n "$PROXY_PASS" ]; then
    err_exit "PROXY_USER must be set when PROXY_PASS is provided"
  fi
  
  # Validate DNS configuration
  log "DEBUG" "Validate WARP_DNS"
  if [ -n "$WARP_DNS" ]; then
    validate_dns_string "$WARP_DNS"
  fi
  
  # Validate numeric environment variables: port, uid, gid
  log "DEBUG" "Validate PROXY_PORT"
  validate_numeric_env "PROXY_PORT" "$PROXY_PORT" 1 65535

  if [ -n "$PROXY_UID_ENV" ]; then
    log "DEBUG" "Validate PROXY_UID"
    validate_numeric_env "PROXY_UID" "$PROXY_UID_ENV" 0 65535
  fi

  if [ -n "$PROXY_GID_ENV" ]; then
    log "DEBUG" "Validate PROXY_GID"
    validate_numeric_env "PROXY_GID" "$PROXY_GID_ENV" 0 65535
  fi
  
  # Validate WARP endpoint
  log "DEBUG" "Validate WARP_ENDPOINT"
  if [ -n "$WARP_ENDPOINT" ]; then
    validate_warp_endpoint "$WARP_ENDPOINT"
  fi
  
  # Validate Amnezia parameters if enabled
  if [ -n "$WARP_AMNEZIA" ]; then
    log "DEBUG" "Validate WARP_AMNEZIA"
    if is_true "$WARP_AMNEZIA"; then
      validate_amnezia_params
    fi
  fi
}
