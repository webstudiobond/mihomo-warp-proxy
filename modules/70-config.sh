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
  [ -n "$result" ] || err_exit "No valid DNS entries found in: $dns_string"
  echo "$result"
}

create_mihomo_template_config() {

  mkdir -p "$(dirname "$MIHOMO_CONFIG_FILE")" || err_exit "Failed to create config directory"
  
  cat > "$MIHOMO_CONFIG_FILE" << EOF
mode: rule
ipv6: $USE_IP6
bind-address: "*"
mixed-port: $PROXY_PORT
allow-lan: true
log-level: $PROXY_LOG_LEVEL
authentication:
- "$PROXY_USER:$PROXY_PASS"
secret: ""
disable-keep-alive: false
keep-alive-idle: 15
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

    DNS_YAML="$(dns_to_yaml_array "$WARP_DNS")"
    [ -n "$DNS_YAML" ] || err_exit "Invalid DNS configuration: $WARP_DNS"
    DNS_YAML="[$DNS_YAML]"
  
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
    refresh-server-ip-interval: 60
EOF
    if is_true "$WARP_AMNEZIA"; then

      cat >> "$MIHOMO_CONFIG_FILE" <<EOF
    amnezia-wg-option:
      jc: $WARP_AMNEZIA_JC
      jmin: $WARP_AMNEZIA_JMIN
      jmax: $WARP_AMNEZIA_JMAX
      s1: 0
      s2: 0
      s3: 0
      s4: 0
      h1: 1
      h2: 2
      h3: 3
      h4: 4
      i1: $WARP_AMNEZIA_I1
      i2: $WARP_AMNEZIA_I2
      i3: $WARP_AMNEZIA_I3
      i4: $WARP_AMNEZIA_I4
      i5: $WARP_AMNEZIA_I5
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

# Helper function to escape values for yq
escape_for_yq() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}


parse_warp_profile() {
    PROFILE_FILE="$WGCF_PROFILE_FILE"

    log "DEBUG" "Parse warp profile: $PROFILE_FILE"

    [ -f "$PROFILE_FILE" ] || err_exit "WARP profile not found: $PROFILE_FILE"

    perms=$(stat_safe '%a' "$PROFILE_FILE" 2>/dev/null || echo "")
    case "$perms" in
        600|400) ;; 
        *) err_exit "Unsafe permissions on WARP profile: $perms (expected 600 or 400)" ;;
    esac

    # Extract value from INI file taking into account sections
    extract_ini_value() {
        section="$1"
        key="$2"
        
        # Input parameter validation - only safe characters
        case "$section" in
            *[^a-zA-Z0-9_-]*) err_exit "Invalid section name: $section" ;;
        esac
        case "$key" in
            *[^a-zA-Z0-9_-]*) err_exit "Invalid key name: $key" ;;
        esac
        
        # Escaping special characters for sed
        escaped_section=$(printf '%s' "$section" | sed 's/[[\.*^$()+?{|]/\\&/g')
        escaped_key=$(printf '%s' "$key" | sed 's/[[\.*^$()+?{|]/\\&/g')
        
        # Extracting value only from the required section
        sed -n "
            /^\[$escaped_section\]/,/^\[.*\]/{
                /^\[$escaped_section\]/d
                /^\[.*\]/d
                s/^[[:space:]]*$escaped_key[[:space:]]*=[[:space:]]*//p
            }
        " "$PROFILE_FILE" | head -n1
    }

    # One-time reading and parsing of all required values
    WARP_PRIVATE_KEY=$(extract_ini_value "Interface" "PrivateKey")
    WARP_PUBLIC_KEY=$(extract_ini_value "Peer" "PublicKey") 
    WARP_ADDRESS=$(extract_ini_value "Interface" "Address")

    # Safe cleanup of control characters only (keep base64 padding)
    WARP_PRIVATE_KEY=$(printf '%s' "$WARP_PRIVATE_KEY" | tr -d '\r\n\t')
    WARP_PUBLIC_KEY=$(printf '%s' "$WARP_PUBLIC_KEY" | tr -d '\r\n\t')
    WARP_ADDRESS=$(printf '%s' "$WARP_ADDRESS" | tr -d ' \t\r\n')

    # Extract IPv4 and IPv6 from Address using parameter expansion where possible
    # Remove spaces and separate by comma
    addr_clean="$WARP_ADDRESS"
    
    # Extract IPv4 (up to the first comma)
    WARP_IPV4="${addr_clean%%,*}"
    WARP_IPV4="${WARP_IPV4%%/*}"  # Remove the CIDR mask
    
    # Extract IPv6 (after the first comma)
    addr_remaining="${addr_clean#*,}"
    WARP_IPV6="${addr_remaining%%/*}"  # Remove the CIDR mask

    # Parsing endpoint (already validated)
    WARP_SERVER="${WARP_ENDPOINT%:*}"
    WARP_PORT="${WARP_ENDPOINT##*:}"

    # Checking the availability of mandatory data
    [ -n "$WARP_PRIVATE_KEY" ] || err_exit "WARP_PRIVATE_KEY not found in profile: $PROFILE_FILE"
    [ -n "$WARP_PUBLIC_KEY" ] || err_exit "WARP_PUBLIC_KEY not found in profile: $PROFILE_FILE"
    [ -n "$WARP_IPV4" ] || err_exit "Could not extract IPv4 address from wgcf profile: $PROFILE_FILE"
    [ -n "$WARP_IPV6" ] || err_exit "Could not extract IPv6 address from wgcf profile: $PROFILE_FILE"
    [ -n "$WARP_SERVER" ] || err_exit "Could not extract server from WARP_ENDPOINT: $WARP_ENDPOINT"
    [ -n "$WARP_PORT" ] || err_exit "Could not extract port from WARP_ENDPOINT: $WARP_ENDPOINT"

    log "DEBUG" "Warp profile is parsed"
}

# Update basic mihomo configuration fields
update_basic_config_fields() {
  local config_file="$1"
  local temp_dir temp_auth_file_secure
  
  temp_dir=$(dirname "$config_file")
  
  # Validate and escape input values
  local escaped_log_level escaped_user escaped_pass escaped_use_ip6
  escaped_log_level=$(escape_for_yq "$PROXY_LOG_LEVEL")
  escaped_user=$(escape_for_yq "$PROXY_USER")
  escaped_pass=$(escape_for_yq "$PROXY_PASS")
  escaped_use_ip6=$(escape_for_yq "$USE_IP6")
  
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
    err_exit "Failed to create auth temp file"
  }
  
  # Update basic fields atomically
  if ! (timeout 30 yq -i ".ipv6 = $escaped_use_ip6 | .log-level = \"$escaped_log_level\" | .mixed-port = $PROXY_PORT" "$config_file"); then
    remove_temp_file "$temp_auth_file"
    err_exit "Failed to update basic config fields"
  fi
  
  # Update authentication atomically
  if ! (timeout 30 yq -i ".authentication = [(load(\"$temp_auth_file\") | .auth_user + \":\" + .auth_pass)]" "$config_file"); then
    rm -f "$temp_auth_file"
    err_exit "Failed to update authentication"
  fi
  
  rm -f "$temp_auth_file"
  return 0
}

# Update GEO configuration settings
update_geo_config() {
  local config_file="$1"
  
  if is_true "$GEO"; then
    log "DEBUG" "Enabling GEO configuration"
    if ! (timeout 30 yq -i ".geodata-mode = true |
           .geodata-loader = \"memconservative\" |
           .geo-auto-update = false |
           .geo-update-interval = 24 |
           .geox-url.geoip = \"$GEO_URL_GEOIP\" |
           .geox-url.geosite = \"$GEO_URL_GEOSITE\" |
           .geox-url.mmdb = \"$GEO_URL_MMDB\" |
           .geox-url.asn = \"$GEO_URL_ASN\"" "$config_file"); then
      err_exit "Failed to update GEO config fields"
    fi
  else
    log "DEBUG" "Disabling GEO configuration"
    # Remove GEO fields cleanly
    if ! yq -i 'del(.geodata-mode, .geodata-loader, .geo-auto-update, .geo-update-interval, .geox-url)' "$config_file"; then
      err_exit "Failed to remove GEO configuration"
    fi
  fi
  
  return 0
}

# Update WARP proxy configuration
update_warp_config() {
  local config_file="$1"
  local dns_array
  
  # Validate WARP parameters first
  validate_warp_profile_params || return 1
  
  # Prepare DNS array safely
  dns_array=$(dns_to_yaml_array "$WARP_DNS") || {
    err_exit "Failed to parse WARP DNS configuration"
  }
  
  # Check if warp proxy exists
  if ! yq '.proxies[]? | select(.name == "warp") | .name' "$config_file" >/dev/null 2>&1; then
    err_exit "WARP proxy configuration not found in config file"
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
    err_exit "Failed to update WARP proxy configuration"
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
    escaped_i1=$(escape_for_yq "$WARP_AMNEZIA_I1")
    escaped_i2=$(escape_for_yq "$WARP_AMNEZIA_I2")
    escaped_i3=$(escape_for_yq "$WARP_AMNEZIA_I3")
    escaped_i4=$(escape_for_yq "$WARP_AMNEZIA_I4")
    escaped_i5=$(escape_for_yq "$WARP_AMNEZIA_I5")
    
    # Validate numeric parameters
    for param_name in WARP_AMNEZIA_JC WARP_AMNEZIA_JMIN WARP_AMNEZIA_JMAX; do
      param_value=$(get_amnezia_var "$param_name" || true)
      if [ -n "$param_value" ]; then
        case "$param_value" in
          ''|*[!0-9]*) err_exit "Invalid $param: $value" ;;
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
            \"i5\": \"$escaped_i5\"
          }" "$config_file"); then
      err_exit "Failed to update Amnezia configuration"
    fi
  else
    log "DEBUG" "Disabling Amnezia WireGuard options"
    if ! yq -i 'del((.proxies[]? | select(.name == "warp"))."amnezia-wg-option")' "$config_file"; then
      err_exit "Failed to remove Amnezia configuration"
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
  validate_warp_profile_params || {
    err_exit "Cannot replace placeholders without valid WARP configuration"
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
    err_exit "Failed to create sed script"
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
    err_exit "Some placeholders remain unreplaced in config"
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

    log "DEBUG" "Integrate WARP reserved"

    . /usr/local/bin/modules/95-warp-reserved.sh
  
    # Try to integrate reserved values
    if [ -n "${MWP_WARP_RESERVED_SH_LOADED:-}" ]; then
      integrate_warp_reserved_values
    fi
  fi

  # Handle any remaining template placeholders
  handle_placeholders "$file" || return 1
 
  # Set secure permissions
  chmod 0600 "$file" || log "WARN" "Failed to set permissions on $file"
  log "DEBUG" "Configuration updated successfully"
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

update_mihomo_config_for_warp() {
  local PROFILE_FILE="$WGCF_PROFILE_FILE"
  
  if [ ! -f "$PROFILE_FILE" ]; then
    log "WARN" "WARP profile not found, skipping config update"
    return
  fi
  
  if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then
    log "DEBUG" "Creating mihomo config template for WARP"
    create_mihomo_template_config
  fi
  
  log "DEBUG" "Updating mihomo config with WARP parameters"
  parse_warp_profile
  update_mihomo_config_with_environment
}
