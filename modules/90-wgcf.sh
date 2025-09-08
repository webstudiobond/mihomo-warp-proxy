# shellcheck shell=sh
# Guard
[ -n "${MWP_WGCF_SH_LOADED:-}" ] && return 0
MWP_WGCF_SH_LOADED=1

# Helper function to register/update wgcf account
register_account() {
    log "DEBUG" "Registering new wgcf account"
    if ! "$WGCF_BIN" register --accept-tos >/dev/null 2>&1; then
        err_exit "Failed to register wgcf account"
    fi
    
    if [ -n "$WARP_PLUS_KEY" ]; then
        log "DEBUG" "Updating account with WARP+ key"
        if ! "$WGCF_BIN" update --license-key "$WARP_PLUS_KEY" >/dev/null 2>&1; then
            log "WARN" "Failed to update account with WARP+ key, continuing with free account"
        fi
    fi
}

# Helper function to update existing account with WARP+ key
update_account() {
    if [ -n "$WARP_PLUS_KEY" ]; then
        log "DEBUG" "Checking and updating account with WARP+ key"
        # Check current account status
        current_license=$("$WGCF_BIN" status 2>/dev/null | grep -i "license" | head -1 || echo "")
        if echo "$current_license" | grep -q "unlimited"; then
            log "DEBUG" "Account already has WARP+ license"
        else
            log "DEBUG" "Updating account with WARP+ key"
            if ! "$WGCF_BIN" update --license-key "$WARP_PLUS_KEY" >/dev/null 2>&1; then
                log "WARN" "Failed to update account with WARP+ key"
            fi
        fi
    fi
}

# Helper function to generate profile
generate_profile() {
    log "DEBUG" "Generating wgcf profile"
    if ! "$WGCF_BIN" generate >/dev/null 2>&1; then
        err_exit "Failed to generate wgcf profile"
    fi
    
    if [ ! -f "$PROFILE_FILE" ]; then
        err_exit "Profile file not created: $PROFILE_FILE"
    fi
}

log "DEBUG" "Running wgcf WARP setup"

[ -x "$WGCF_BIN" ] || err_exit "wgcf binary not found or not executable: $WGCF_BIN"
[ -d "$WGCF_DATA" ] || mkdir -p "$WGCF_DATA" || err_exit "Cannot create wgcf directory: $WGCF_DATA"

# Check write access to WGCF_DATA before proceeding
if ! can_write_dir "$WGCF_DATA" "wgcf_write_check"; then
    err_exit "No write access to $WGCF_DATA"
fi

# Change to wgcf data directory for operations
cd "$WGCF_DATA" || err_exit "Cannot change to wgcf directory: $WGCF_DATA"

# Main logic for handling different scenarios
account_exists=$([ -f "$ACCOUNT_FILE" ] && echo "true" || echo "false")
profile_exists=$([ -f "$PROFILE_FILE" ] && echo "true" || echo "false")

log "DEBUG" "WARP enabled, checking configuration..."
log "DEBUG" "Account file exists: $account_exists"
log "DEBUG" "Profile file exists: $profile_exists"

# Scenario analysis
if [ "$account_exists" = "true" ] && [ "$profile_exists" = "true" ]; then
    # Both files exist
    if is_true "$WARP_REGENERATE"; then
        log "DEBUG" "WARP_REGENERATE=true, regenerating account and profile"
        rm -f "$ACCOUNT_FILE" "$PROFILE_FILE"
        register_account
        generate_profile
    else
        log "DEBUG" "Both account and profile exist, checking for WARP+ key update"
        update_account
        # Regenerate profile if WARP+ key was provided (to ensure updated config)
        if [ -n "$WARP_PLUS_KEY" ]; then
            generate_profile
        fi
    fi
elif [ "$account_exists" = "true" ] && [ "$profile_exists" = "false" ]; then
    # Only account exists
    log "DEBUG" "Account exists but profile missing, updating account and generating profile"
    update_account
    generate_profile
elif [ "$account_exists" = "false" ]; then
    # No account (with or without profile)
    log "DEBUG" "No account file found, registering new account"
    register_account
    generate_profile
fi

# Verify final state
if [ ! -f "$ACCOUNT_FILE" ] || [ ! -f "$PROFILE_FILE" ]; then
    err_exit "Failed to create required wgcf files"
fi

log "DEBUG" "wgcf configuration completed successfully"

# Set appropriate permissions for generated files
chmod 0600 "$ACCOUNT_FILE" "$PROFILE_FILE" 2>/dev/null || { log "WARN" "Failed to chmod files: $ACCOUNT_FILE and $PROFILE_FILE"; }

update_mihomo_config_for_warp
