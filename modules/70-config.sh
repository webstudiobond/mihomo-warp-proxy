# shellcheck shell=sh
# Guard
[ -n "${MWP_CONFIG_SH_LOADED:-}" ] && return 0
MWP_CONFIG_SH_LOADED=1

# Helper function to convert DNS string to YAML array format
dns_to_yaml_array() {
  local dns_string="$1"
  [ -n "$dns_string" ] || return 1
  local result=""
  local oldIFS=$IFS
  IFS=','
  for dns in $dns_string; do
    dns=$(echo "$dns" | tr -d ' \t\r\n')
    [ -n "$dns" ] || continue
    if ! is_valid_dns "$dns"; then
      log "WARN" "Invalid DNS format: $dns (supported: IPv4, IPv6, tls://, https://, quic://)"
      continue
    fi
    if [ -z "$result" ]; then
      result="\"$dns\""
    else
      result="$result, \"$dns\""
    fi
  done
  IFS=$oldIFS
  [ -n "$result" ] || { log "ERROR" "No valid DNS entries found in: $dns_string"; return 1; }
  echo "$result"
}

# Helper function to escape values for yq
escape_for_yq() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# WARP configuration functions
setup_warp_config() {
  if [ -x "/usr/local/bin/wgcf.sh" ]; then
    log "DEBUG" "Running WARP account setup"
    export MIHOMO_DATA MIHOMO_CONFIG_FILE SCRIPT_VERSION
    timeout 30 /usr/local/bin/wgcf.sh || err_exit "WARP account setup failed"
  else
    log "WARN" "WARP enabled but wgcf.sh not found or not executable"
    return
  fi
  
  # Update mihomo config with WARP settings
  update_mihomo_config_for_warp
}

update_mihomo_config_for_warp() {
  local PROFILE_FILE="$WGCF_DATA/wgcf-profile.conf"
  
  if [ ! -f "$PROFILE_FILE" ]; then
    log "WARN" "WARP profile not found, skipping config update"
    return
  fi
  
  if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then
    log "DEBUG" "Creating mihomo config template for WARP"
    create_mihomo_template_config
  fi
  
  log "DEBUG" "Updating mihomo config with WARP parameters"
  parse_warp_profile_and_update_config
}

create_mihomo_template_config() {
  mkdir -p "$(dirname "$MIHOMO_CONFIG_FILE")"
  
  cat > "$MIHOMO_CONFIG_FILE" << EOF
mode: rule
ipv6: true
bind-address: "*"
mixed-port: $PROXY_PORT
allow-lan: true
log-level: $PROXY_LOG_LEVEL
authentication:
- "$PROXY_USER:$PROXY_PASS"
secret: ""
keep-alive-interval: 25
global-client-fingerprint: chrome
EOF

  if is_true "$GEO"; then
    cat >> "$MIHOMO_CONFIG_FILE" <<EOF
geodata-mode: true
geodata-loader: memconservative
geo-auto-update: false
geo-update-interval: 24
geox-url:
  geoip: "${GEO_URL_GEOIP:-https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat}"
  geosite: "${GEO_URL_GEOSITE:-https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat}"
  mmdb: "${GEO_URL_MMDB:-https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb}"
  asn: "${GEO_URL_ASN:-https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb}"
EOF
  fi

  if is_true "$USE_WARP_CONFIG"; then
    DNS_YAML="[$(dns_to_yaml_array "$WARP_DNS")]"
    [ -n "$(dns_to_yaml_array "$WARP_DNS")" ] || err_exit "Invalid DNS configuration: $WARP_DNS"
  
    cat >> "$MIHOMO_CONFIG_FILE" <<EOF
proxies:
  - name: "warp"
    type: wireguard
    server: PLACEHOLDER_SERVER
    port: PLACEHOLDER_PORT
    ip: PLACEHOLDER_IP
    ipv6: PLACEHOLDER_IPV6
    public-key: "PLACEHOLDER_PUBLIC_KEY"
    private-key: "PLACEHOLDER_PRIVATE_KEY"
    udp: true
    mtu: 1280
    remote-dns-resolve: true
    dns: $DNS_YAML
EOF

  if is_true "$WARP_AMNEZIA"; then
    cat >> "$MIHOMO_CONFIG_FILE" <<EOF
    amnezia-wg-option:
      jc: $WARP_AMNEZIA_JC
      jmin: $WARP_AMNEZIA_JMIN
      jmax: $WARP_AMNEZIA_JMAX
      s1: 0
      s2: 0
      h1: 1
      h2: 2
      h3: 3
      h4: 4
      i1: $WARP_AMNEZIA_I1
      i2: $WARP_AMNEZIA_I2
      i3: $WARP_AMNEZIA_I3
      i4: $WARP_AMNEZIA_I4
      i5: $WARP_AMNEZIA_I5
      j1: $WARP_AMNEZIA_J1
      j2: $WARP_AMNEZIA_J2
      j3: $WARP_AMNEZIA_J3
      itime: $WARP_AMNEZIA_ITIME
EOF
  fi
  
  cat >> "$MIHOMO_CONFIG_FILE" <<EOF
rules:
  - MATCH,warp
EOF
else
  cat >> "$MIHOMO_CONFIG_FILE" <<EOF
rules:
  - MATCH,DIRECT
EOF
fi
}

parse_warp_profile_and_update_config() {
  local PROFILE_FILE="$WGCF_DATA/wgcf-profile.conf"

  if [ -f "$PROFILE_FILE" ]; then
    # Create temporary copy for safe processing
    profile_copy=$(create_secure_temp_file "$(dirname "$PROFILE_FILE")" "profile_copy") || {
      log "ERROR" "Failed to create temp copy of profile"
      return 1
    }
    cp "$PROFILE_FILE" "$profile_copy" || {
      remove_temp_file "$profile_copy"
      log "ERROR" "Failed to copy profile file"
      return 1
    }
    
    if grep -q '[`$();|&<>]' "$profile_copy"; then
      remove_temp_file "$profile_copy"
      err_exit "WARP profile contains potentially dangerous characters"
    fi
    PROFILE_FILE="$profile_copy"
  fi

  if [ ! -f "$PROFILE_FILE" ]; then
    log "ERROR" "WARP profile not found: $PROFILE_FILE"
    return 1
  fi

  # Validate profile file permissions and ownership
  local file_perms=$(stat -c '%a' "$PROFILE_FILE" 2>/dev/null || stat -f '%Lp' "$PROFILE_FILE" 2>/dev/null || echo "000")
  case "$file_perms" in
    600|400) ;;  # Acceptable permissions
    *) log "WARN" "WARP profile has potentially unsafe permissions: $file_perms" ;;
  esac

  # Parse WARP profile
  kv() {
    # Validate config key to prevent injection
    case "$1" in
      *[^a-zA-Z0-9_-]*) log "ERROR" "Invalid config key: $1"; return 1 ;;
    esac
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$PROFILE_FILE" | head -n1
  }

  WARP_PRIVATE_KEY="$(kv PrivateKey | tr -d '\r\n')"
  WARP_PUBLIC_KEY="$(kv PublicKey | tr -d '\r\n')"
  WARP_ADDRESS="$(kv Address | tr -d ' \t\r\n')"

  # Additional validation for WireGuard key formats
  if [ "${#WARP_PRIVATE_KEY}" -ne 44 ]; then
    err_exit "Invalid PrivateKey length: expected 44 chars, got ${#WARP_PRIVATE_KEY}"
  fi
  if [ "${#WARP_PUBLIC_KEY}" -ne 44 ]; then
    err_exit "Invalid PublicKey length: expected 44 chars, got ${#WARP_PUBLIC_KEY}"
  fi

  # Validate extracted keys format
  case "$WARP_PRIVATE_KEY" in
    *[^A-Za-z0-9+/=]*) err_exit "Invalid PrivateKey format" ;;
    '') err_exit "PrivateKey is empty" ;;
  esac
  case "$WARP_PUBLIC_KEY" in
    *[^A-Za-z0-9+/=]*) err_exit "Invalid PublicKey format" ;;
    '') err_exit "PublicKey is empty" ;;
  esac

  WARP_IPV4=$(printf '%s' "$WARP_ADDRESS" | cut -d',' -f1 | cut -d'/' -f1 | tr -d ' \t\r\n')
  WARP_IPV6=$(printf '%s' "$WARP_ADDRESS" | cut -d',' -f2 | cut -d'/' -f1 | tr -d ' \t\r\n')

  # Validate IP addresses format
  validate_ipv4 "$WARP_IPV4"
  validate_ipv6 "$WARP_IPV6"
 
  WARP_SERVER=$(printf '%s' "$WARP_ENDPOINT" | cut -d':' -f1)
  WARP_PORT=$(printf '%s' "$WARP_ENDPOINT" | cut -d':' -f2)

  # Ensure all required variables are set before updating config
  [ -n "$WARP_SERVER" ] || { log "ERROR" "Could not extract server from WARP_ENDPOINT: $WARP_ENDPOINT"; return 1; }
  [ -n "$WARP_PORT" ] || { log "ERROR" "Could not extract port from WARP_ENDPOINT: $WARP_ENDPOINT"; return 1; }
  
  # Validate port number
  case "$WARP_PORT" in
    ''|*[!0-9]*) log "ERROR" "Invalid port in WARP_ENDPOINT: $WARP_PORT"; return 1 ;;
    *) [ "$WARP_PORT" -ge 1 ] && [ "$WARP_PORT" -le 65535 ] || { log "ERROR" "Port out of range in WARP_ENDPOINT: $WARP_PORT"; return 1; } ;;
  esac
  
  [ -n "$WARP_PRIVATE_KEY" ] || { log "ERROR" "Could not extract PrivateKey from wgcf profile"; return 1; }
  [ -n "$WARP_PUBLIC_KEY" ] || { log "ERROR" "Could not extract PublicKey from wgcf profile"; return 1; }
  [ -n "$WARP_IPV4" ] || { log "ERROR" "Could not extract IPv4 address from wgcf profile"; return 1; }
  [ -n "$WARP_IPV6" ] || { log "ERROR" "Could not extract IPv6 address from wgcf profile"; return 1; }
  
  remove_temp_file "$profile_copy"
  
  # Update mihomo config
  update_mihomo_config_with_environment
}

update_mihomo_config_with_environment() {
  if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then
    log "WARN" "Mihomo config file not found: $MIHOMO_CONFIG_FILE"
    return
  fi

  # Skip update if config was just recreated to avoid recursion
  if [ "${CONFIG_RECREATED:-false}" = "true" ]; then
     return
  fi
  
  # Use yq for robust YAML manipulation
  update_config_with_yq
}

# Update basic mihomo configuration fields
update_basic_config_fields() {
  local config_file="$1"
  local temp_dir temp_auth_file_secure
  
  temp_dir=$(dirname "$config_file")
  
  # Validate and escape input values
  local escaped_log_level escaped_user escaped_pass
  escaped_log_level=$(escape_for_yq "$PROXY_LOG_LEVEL")
  escaped_user=$(escape_for_yq "$PROXY_USER")
  escaped_pass=$(escape_for_yq "$PROXY_PASS")
  
  # Create secure temp file for authentication
  temp_auth_file_secure=$(create_secure_temp_file "$temp_dir" "auth") || return 1
  
  # Additional security check
  if [ -L "$temp_auth_file_secure" ]; then
    log "ERROR" "Auth temp file is a symlink: $temp_auth_file_secure"
    remove_temp_file "$temp_auth_file_secure"
    return 1
  fi
  temp_auth_file="$temp_auth_file_secure"
  
  # Create authentication data safely
  printf 'auth_user: "%s"\nauth_pass: "%s"\n' "$escaped_user" "$escaped_pass" > "$temp_auth_file" || {
    remove_temp_file "$temp_auth_file"
    log "ERROR" "Failed to create auth temp file"
    return 1
  }
  
  # Update basic fields atomically
  if ! (timeout 30 yq -i ".log-level = \"$escaped_log_level\" | .mixed-port = $PROXY_PORT" "$config_file"); then
    remove_temp_file "$temp_auth_file"
    log "ERROR" "Failed to update basic config fields"
    return 1
  fi
  
  # Update authentication atomically
  if ! (timeout 30 yq -i ".authentication = [(load(\"$temp_auth_file\") | .auth_user + \":\" + .auth_pass)]" "$config_file"); then
    rm -f "$temp_auth_file"
    log "ERROR" "Failed to update authentication"
    return 1
  fi
  
  rm -f "$temp_auth_file"
  return 0
}

# Update GEO configuration settings
update_geo_config() {
  local config_file="$1"
  
  if is_true "$GEO"; then
    log "DEBUG" "Enabling GEO configuration"
    # if ! yq -i ".geodata-mode = true |
    if ! (timeout 30 yq -i ".geodata-mode = true |
           .geodata-loader = \"memconservative\" |
           .geo-auto-update = false |
           .geo-update-interval = 24 |
           .geox-url.geoip = \"$GEO_URL_GEOIP\" |
           .geox-url.geosite = \"$GEO_URL_GEOSITE\" |
           .geox-url.mmdb = \"$GEO_URL_MMDB\" |
           .geox-url.asn = \"$GEO_URL_ASN\"" "$config_file"); then
      log "ERROR" "Failed to update GEO config fields"
      return 1
    fi
  else
    log "DEBUG" "Disabling GEO configuration"
    # Remove GEO fields cleanly
    if ! yq -i 'del(.geodata-mode, .geodata-loader, .geo-auto-update, .geo-update-interval, .geox-url)' "$config_file"; then
      log "ERROR" "Failed to remove GEO configuration"
      return 1
    fi
  fi
  
  return 0
}

# Update WARP proxy configuration
update_warp_config() {
  local config_file="$1"
  local dns_array
  
  # Validate WARP parameters first
  validate_warp_params || return 1
  
  # Prepare DNS array safely
  dns_array=$(dns_to_yaml_array "$WARP_DNS") || {
    log "ERROR" "Failed to parse WARP DNS configuration"
    return 1
  }
  
  # Check if warp proxy exists
  if ! yq '.proxies[]? | select(.name == "warp") | .name' "$config_file" >/dev/null 2>&1; then
    log "ERROR" "WARP proxy configuration not found in config file"
    return 1
  fi
  
  # Escape all WARP values for safe YAML insertion
  local escaped_server escaped_ipv4 escaped_ipv6 escaped_pub_key escaped_priv_key
  escaped_server=$(escape_for_yq "$WARP_SERVER")
  escaped_ipv4=$(escape_for_yq "$WARP_IPV4")
  escaped_ipv6=$(escape_for_yq "$WARP_IPV6")
  escaped_pub_key=$(escape_for_yq "$WARP_PUBLIC_KEY")
  escaped_priv_key=$(escape_for_yq "$WARP_PRIVATE_KEY")
  
  # Update WARP proxy settings atomically
  if ! (timeout 30 yq -i "(.proxies[]? | select(.name == \"warp\")) |= (
          .server = \"$escaped_server\" |
          .port = $WARP_PORT |
          .ip = \"$escaped_ipv4\" |
          .ipv6 = \"$escaped_ipv6\" |
          .public-key = \"$escaped_pub_key\" |
          .private-key = \"$escaped_priv_key\" |
          .dns = [$dns_array]
        )" "$config_file"); then
    log "ERROR" "Failed to update WARP proxy configuration"
    return 1
  fi
  
  return 0
}

# Update Amnezia WireGuard options
update_amnezia_config() {
  local config_file="$1"
  
  if is_true "$WARP_AMNEZIA"; then
    log "DEBUG" "Enabling Amnezia WireGuard options"
    
    # Escape all Amnezia values
    local escaped_i1 escaped_i2 escaped_i3 escaped_i4 escaped_i5
    local escaped_j1 escaped_j2 escaped_j3
    escaped_i1=$(escape_for_yq "$WARP_AMNEZIA_I1")
    escaped_i2=$(escape_for_yq "$WARP_AMNEZIA_I2")
    escaped_i3=$(escape_for_yq "$WARP_AMNEZIA_I3")
    escaped_i4=$(escape_for_yq "$WARP_AMNEZIA_I4")
    escaped_i5=$(escape_for_yq "$WARP_AMNEZIA_I5")
    escaped_j1=$(escape_for_yq "$WARP_AMNEZIA_J1")
    escaped_j2=$(escape_for_yq "$WARP_AMNEZIA_J2")
    escaped_j3=$(escape_for_yq "$WARP_AMNEZIA_J3")
    
    # Validate numeric parameters
    for param_name in WARP_AMNEZIA_JC WARP_AMNEZIA_JMIN WARP_AMNEZIA_JMAX WARP_AMNEZIA_ITIME; do
      param_value=$(get_amnezia_var "$param_name" || true)
      if [ -n "$param_value" ]; then
        case "$param_value" in
          ''|*[!0-9]*) log "ERROR" "Invalid $param: $value"; return 1 ;;
        esac
      fi
    done
    
    # Update Amnezia configuration atomically
    if ! (timeout 30 yq -i "(.proxies[]? | select(.name == \"warp\")).\"amnezia-wg-option\" = {
            \"jc\": $WARP_AMNEZIA_JC,
            \"jmin\": $WARP_AMNEZIA_JMIN,
            \"jmax\": $WARP_AMNEZIA_JMAX,
            \"s1\": 0,
            \"s2\": 0,
            \"h1\": 1,
            \"h2\": 2,
            \"h3\": 3,
            \"h4\": 4,
            \"i1\": \"$escaped_i1\",
            \"i2\": \"$escaped_i2\",
            \"i3\": \"$escaped_i3\",
            \"i4\": \"$escaped_i4\",
            \"i5\": \"$escaped_i5\",
            \"j1\": \"$escaped_j1\",
            \"j2\": \"$escaped_j2\",
            \"j3\": \"$escaped_j3\",
            \"itime\": $WARP_AMNEZIA_ITIME
          }" "$config_file"); then
      log "ERROR" "Failed to update Amnezia configuration"
      return 1
    fi
  else
    log "DEBUG" "Disabling Amnezia WireGuard options"
    if ! yq -i 'del((.proxies[]? | select(.name == "warp"))."amnezia-wg-option")' "$config_file"; then
      log "ERROR" "Failed to remove Amnezia configuration"
      return 1
    fi
  fi
  
  return 0
}

# Handle template placeholders safely
handle_placeholders() {
  local config_file="$1"
  local temp_dir temp_sed_script temp_config_secure
  
  # Check if placeholders exist
  if ! grep -q "PLACEHOLDER_" "$config_file"; then
    return 0
  fi
  
  log "DEBUG" "Processing template placeholders"
  
  # Validate required WARP variables for placeholder replacement
  validate_warp_params || {
    log "ERROR" "Cannot replace placeholders without valid WARP configuration"
    return 1
  }
  
  temp_dir=$(dirname "$config_file")
  temp_sed_script=$(create_secure_temp_file "$temp_dir" "sed_script") || return 1
  
  # Additional security check for sed script
  if [ -L "$temp_sed_script" ]; then
    log "ERROR" "Sed script temp file is a symlink: $temp_sed_script"
    remove_temp_file "$temp_sed_script"
    return 1
  fi

  # Create safe sed script with escaped values
  {
    printf 's|PLACEHOLDER_SERVER|%s|g\n' "$(printf '%s' "$WARP_SERVER" | sed 's/[[\.*^$()+?{|]/\\&/g')"
    printf 's|PLACEHOLDER_PORT|%s|g\n' "$WARP_PORT"
    printf 's|PLACEHOLDER_IP|%s|g\n' "$(printf '%s' "$WARP_IPV4" | sed 's/[[\.*^$()+?{|]/\\&/g')"
    printf 's|PLACEHOLDER_IPV6|%s|g\n' "$(printf '%s' "$WARP_IPV6" | sed 's/[[\.*^$()+?{|]/\\&/g')"
    printf 's|PLACEHOLDER_PUBLIC_KEY|%s|g\n' "$(printf '%s' "$WARP_PUBLIC_KEY" | sed 's/[[\.*^$()+?{|]/\\&/g')"
    printf 's|PLACEHOLDER_PRIVATE_KEY|%s|g\n' "$(printf '%s' "$WARP_PRIVATE_KEY" | sed 's/[[\.*^$()+?{|]/\\&/g')"
  } > "$temp_sed_script" || {
    rm -f "$temp_sed_script"
    log "ERROR" "Failed to create sed script"
    return 1
  }
  
  # Create temporary file for sed output
  local temp_config
  temp_config_secure=$(create_secure_temp_file "$temp_dir" "config_sed") || {
    rm -f "$temp_sed_script"
    return 1
  }

  # Check that temp_config is not symlink
  if [ -L "$temp_config_secure" ]; then
    log "ERROR" "Config temp file is a symlink: $temp_config_secure"
    remove_temp_file "$temp_sed_script"
    remove_temp_file "$temp_config_secure"
    return 1
  fi
  temp_config="$temp_config_secure"
  
  # Apply replacements safely
  if [ -f "$config_file" ] && [ ! -L "$config_file" ] && sed -f "$temp_sed_script" "$config_file" > "$temp_config"; then
    if mv "$temp_config" "$config_file"; then
      remove_temp_file "$temp_sed_script"
      remove_temp_file "$temp_config"
    else
      log "ERROR" "Failed to move updated config"
      remove_temp_file "$temp_sed_script"
      remove_temp_file "$temp_config"
      return 1
    fi
  else
    log "ERROR" "Failed to apply placeholder replacements"
      remove_temp_file "$temp_sed_script"
      remove_temp_file "$temp_config"
    return 1
  fi
  
  # Verify all placeholders were replaced
  if grep -q "PLACEHOLDER_" "$config_file"; then
    log "ERROR" "Some placeholders remain unreplaced in config"
    return 1
  fi
  
  return 0
}

update_config_with_yq() {
  log "DEBUG" "Updating mihomo config using yq"
  local file="$MIHOMO_CONFIG_FILE"
  
  # Update configuration components in sequence
  update_basic_config_fields "$file" || return 1
  
  update_geo_config "$file" || return 1

  if is_true "$USE_WARP_CONFIG"; then
    # Check if proxies section exists and has warp proxy
    log "DEBUG" "Check if proxies section exists and has warp proxy"
    warp_proxy_check=$(yq '.proxies[]? | select(.name == "warp") | .name' "$file" 2>/dev/null || echo "")
    if [ -z "$warp_proxy_check" ]; then
      log "WARN" "Missing Warp proxy configuration. Rebuilding config.yaml from scratch. Check your config.yaml.back"
      rm -f "$file" || { log "WARN" "Failed to remove config file: $temp_file"; }
      run_common_tasks
      export CONFIG_RECREATED=true
      return 0 
    fi
    
    update_warp_config "$file" || return 1
    update_amnezia_config "$file" || return 1
  fi

  # Handle any remaining template placeholders
  handle_placeholders "$file" || return 1
 
  # Set secure permissions
  chmod 0600 "$file" || log "WARN" "Failed to set permissions on $file"
  log "DEBUG" "Configuration updated successfully"
}
