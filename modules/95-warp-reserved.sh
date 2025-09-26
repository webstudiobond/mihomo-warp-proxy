# shellcheck shell=sh
# Guard
[ -n "${MWP_WARP_RESERVED_SH_LOADED:-}" ] && return 0
MWP_WARP_RESERVED_SH_LOADED=1

# Helper function to fetch device info from WARP API
fetch_warp_device_info() {
    local access_token="$1"
    local device_id="$2"
    
    log "DEBUG" "Fetching WARP device information for device: $device_id"
    
    local response
    response=$(timeout 30 curl -s -X GET \
        "https://api.cloudflareclient.com/v0a2158/reg/${device_id}" \
        -H "CF-Client-Version: a-6.10-2158" \
        -H "User-Agent: okhttp/3.12.1" \
        -H "Authorization: Bearer ${access_token}" \
        -H "Content-Type: application/json" 2>/dev/null)
    
    local curl_exit_code=$?
    if [ $curl_exit_code -ne 0 ]; then
        log "WARN" "cURL failed to fetch WARP device info (exit code: $curl_exit_code)"
        return 1
    fi
    
    if [ -z "$response" ]; then
        log "WARN" "Empty response from WARP API"
        return 1
    fi
    
    # Validate JSON response
    if ! printf '%s\n' "$response" | jq . >/dev/null 2>&1; then
        log "WARN" "Invalid JSON response from WARP API. Response: $response"
        return 1
    fi
    
    # Check for API errors
    local error_message
    error_message=$(printf '%s\n' "$response" | jq -r '.error // empty' 2>/dev/null)
    if [ -n "$error_message" ]; then
        log "WARN" "WARP API returned error: $error_message"
        return 1
    fi
    
    printf '%s\n' "$response"
    return 0
}

# Helper function to calculate reserved values from client_id
calculate_warp_reserved() {
    local client_id="$1"
    
    if [ -z "$client_id" ]; then
        log "WARN" "client_id is empty"
        return 1
    fi
    
    log "DEBUG" "Calculating reserved values from client_id: $client_id"
    
    # Decode base64 and convert to hex
    local decoded_hex
    decoded_hex=$(printf '%s\n' "$client_id" | base64 -d 2>/dev/null | xxd -p -c 256 2>/dev/null)
    
    if [ -z "$decoded_hex" ]; then
        log "WARN" "Failed to decode client_id base64"
        return 1
    fi
    
    log "DEBUG" "Decoded hex: $decoded_hex (${#decoded_hex} hex chars = $((${#decoded_hex}/2)) bytes)"
    
    # Convert hex pairs to decimal values
    local reserved_array=""
    local i=0
    
    while [ $i -lt ${#decoded_hex} ]; do
        if [ $((i + 1)) -lt ${#decoded_hex} ]; then
            local hex_byte="${decoded_hex:$i:2}"
            local dec_value=$((0x$hex_byte))
            
            if [ -n "$reserved_array" ]; then
                reserved_array="$reserved_array, $dec_value"
            else
                reserved_array="$dec_value"
            fi
        fi
        i=$((i + 2))
    done
    
    if [ -z "$reserved_array" ]; then
        log "WARN" "Failed to calculate reserved values"
        return 1
    fi
    
    printf '[%s]\n' "$reserved_array"
    return 0
}

# Main function to fetch and calculate WARP reserved values
fetch_warp_reserved_values() {
    local account_file="$WGCF_DATA/wgcf-account.toml"
    
    log "DEBUG" "Starting WARP reserved values extraction"
    
    # Validate account file
    if ! validate_warp_account_file "$account_file"; then
        return 1
    fi
    
    # Parse credentials from account file
    local access_token device_id license_key
    access_token=$(parse_toml_value "$account_file" "access_token")
    device_id=$(parse_toml_value "$account_file" "device_id")
    license_key=$(parse_toml_value "$account_file" "license_key")
    
    log "DEBUG" "WARP Account Info:"
    log "DEBUG" "  - Device ID: $device_id"
    log "DEBUG" "  - License: ${license_key:-'N/A'}"
    
    # Fetch device information from API
    local device_info
    device_info=$(fetch_warp_device_info "$access_token" "$device_id")
    
    if [ $? -ne 0 ]; then
        log "WARN" "Failed to fetch WARP device information"
        return 1
    fi
    
    # Extract client_id from API response
    local client_id
    client_id=$(printf '%s\n' "$device_info" | jq -r '.config.client_id // empty' 2>/dev/null)
    
    if [ -z "$client_id" ]; then
        log "WARN" "client_id not found in WARP API response"
        return 1
    fi
    
    log "DEBUG" "Extracted client_id: $client_id (${#client_id} chars)"
    
    # Calculate reserved values
    local reserved_values
    reserved_values=$(calculate_warp_reserved "$client_id")
    
    if [ $? -ne 0 ]; then
        log "WARN" "Failed to calculate reserved values"
        return 1
    fi
    
    log "DEBUG" "Calculated reserved values: $reserved_values"
    
    # Store reserved values for use in config update
    WARP_RESERVED_VALUES="$reserved_values"
    export WARP_RESERVED_VALUES
    
    return 0
}

# Helper function to update mihomo config with reserved values
update_mihomo_config_with_reserved() {
    if [ -z "$WARP_RESERVED_VALUES" ]; then
        log "WARN" "WARP_RESERVED_VALUES not set, skipping reserved configuration"
        return 0
    fi
    
    if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then
        log "WARN" "Mihomo config file not found: $MIHOMO_CONFIG_FILE"
        return 1
    fi
    
    log "DEBUG" "Adding reserved values to mihomo WARP proxy configuration"
    
    # Check if warp proxy exists in config
    local warp_proxy_check
    warp_proxy_check=$(yq '.proxies[]? | select(.name == "warp") | .name' "$MIHOMO_CONFIG_FILE" 2>/dev/null || echo "")
    
    if [ -z "$warp_proxy_check" ]; then
        log "WARN" "WARP proxy not found in mihomo config, skipping reserved update"
        return 0
    fi
    
    # Parse reserved array for yq format
    local reserved_for_yq
    # Convert [1, 2, 3] to proper yq array format
    reserved_for_yq=$(printf '%s\n' "$WARP_RESERVED_VALUES" | sed 's/\[//; s/\]//' | tr ',' '\n' | while read -r num; do
        printf '%s\n' "$num" | tr -d ' '
    done | paste -sd ',' -)
    
    if [ -z "$reserved_for_yq" ]; then
        log "WARN" "Failed to parse reserved values for yq"
        return 1
    fi
    
    # Update WARP proxy with reserved values using yq
    local temp_config
    temp_config=$(create_secure_temp_file "$(dirname "$MIHOMO_CONFIG_FILE")" "config_reserved") || {
        log "WARN" "Failed to create temp file for reserved update"
        return 1
    }
    
    # Apply reserved values update atomically
    if ! (timeout 30 yq "(.proxies[]? | select(.name == \"warp\")).reserved = [$reserved_for_yq]" "$MIHOMO_CONFIG_FILE" > "$temp_config" 2>/dev/null); then
        remove_temp_file "$temp_config"
        log "WARN" "Failed to update mihomo config with reserved values"
        return 1
    fi

    # Convert reserved array to flow style (compact format)
    if ! (timeout 30 yq '(.proxies[]? | select(.name == "warp").reserved) style="flow"' "$temp_config" > "${temp_config}.flow" 2>/dev/null); then
        log "WARN" "Failed to apply compact format, keeping default array style"
        # Continue with original temp_config
    else
        mv "${temp_config}.flow" "$temp_config"
    fi
    
    # Validate the updated config
    if ! yq . "$temp_config" >/dev/null 2>&1; then
        remove_temp_file "$temp_config"
        log "WARN" "Updated config with reserved values is invalid YAML"
        return 1
    fi
    
    # Atomically replace the original config
    if ! mv "$temp_config" "$MIHOMO_CONFIG_FILE"; then
        remove_temp_file "$temp_config"
        log "WARN" "Failed to replace mihomo config with reserved values"
        return 1
    fi
    
    # Set secure permissions
    chmod 0600 "$MIHOMO_CONFIG_FILE" 2>/dev/null || log "WARN" "Failed to set permissions on $MIHOMO_CONFIG_FILE"
    
    log "DEBUG" "Successfully added reserved values to mihomo WARP configuration"
    return 0
}

# Function to integrate reserved values into existing WARP config
integrate_warp_reserved_values() {
    if ! is_true "$USE_WARP_CONFIG"; then
        log "DEBUG" "WARP not enabled, skipping reserved values integration"
        return 0
    fi
    
    if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then
        log "DEBUG" "Mihomo config not found, skipping reserved integration"
        return 0
    fi
    
    # Check if WARP proxy exists in config
    local warp_proxy_check
    warp_proxy_check=$(yq '.proxies[]? | select(.name == "warp") | .name' "$MIHOMO_CONFIG_FILE" 2>/dev/null || echo "")
    
    if [ -z "$warp_proxy_check" ]; then
        log "DEBUG" "WARP proxy not found in config, skipping reserved integration"
        return 0
    fi
    
    # Fetch reserved values
    if fetch_warp_reserved_values; then
        log "DEBUG" "Successfully fetched reserved values: $WARP_RESERVED_VALUES"
        
        # Apply reserved values to config
        if update_mihomo_config_with_reserved; then
            log "DEBUG" "Successfully integrated reserved values into WARP configuration"
        else
            log "WARN" "Failed to integrate reserved values into configuration"
        fi
    else
        log "WARN" "Could not fetch reserved values from WARP API"
        return 0
    fi
}
