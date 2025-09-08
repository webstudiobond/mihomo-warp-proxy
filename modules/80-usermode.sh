# shellcheck shell=sh
# Guard
[ -n "${MWP_USERMODE_SH_LOADED:-}" ] && return 0
MWP_USERMODE_SH_LOADED=1

root_branch() {
  get_current_user_info
  determine_proxy_ids

  log "DEBUG" "Running as root, will drop to ${PROXY_UID}:${PROXY_GID}"
  
  if ! getent group "$PROXY_GID" >/dev/null 2>&1; then
    addgroup -g "$PROXY_GID" -S mihomo-proxy 2>/dev/null || { log "WARN" "Failed to addgroup: $PROXY_GID"; }
  fi
  if ! getent passwd "$PROXY_UID" >/dev/null 2>&1; then
    adduser -u "$PROXY_UID" -D -S -G mihomo-proxy mihomo-proxy 2>/dev/null || { log "WARN" "Failed to adduser: $PROXY_UID"; }
  fi

  # Ensure directories exist with correct ownership from the start
  mkdir -p "$MIHOMO_DATA" || { log "WARN" "Failed to mkdir: $MIHOMO_DATA"; }
  mkdir -p "$WGCF_DATA" || { log "WARN" "Failed to mkdir: $WGCF_DATA"; }
  chmod 0750 "$MIHOMO_DATA" "$WGCF_DATA" || { log "WARN" "Failed to chmod 0750: $MIHOMO_DATA and $WGCF_DATA"; }
  chown -R "${PROXY_UID}:${PROXY_GID}" "$MIHOMO_DATA" "$WGCF_DATA" || { log "WARN" "Failed to chown: $MIHOMO_DATA and $WGCF_DATA"; }

  # Determine if MIHOMO_DATA is mounted from host by checking if owner matches PROXY_UID:PROXY_GID.
  # If MIHOMO_DATA is owned by PROXY_UID:PROXY_GID already => assume mapped/prepared; do not chown.
  if is_mounted_dir_owned_by "$MIHOMO_DATA" "$PROXY_UID" "$PROXY_GID"; then
    log "DEBUG" "$MIHOMO_DATA already owned by ${PROXY_UID}:${PROXY_GID} — assuming mounted/prepared. Will drop to that user and download as unprivileged user."
    exec su-exec "${PROXY_UID}:${PROXY_GID}" "$0" "--run-as-user"
  fi

  # If MIHOMO_DATA not owned by PROXY_UID:PROXY_GID:
  # - If PROXY_UID:PROXY_GID != 911:911 -> chown image dirs to PROXY_UID:PROXY_GID (image-local)
  # - If PROXY == 911:911 -> assume Dockerfile already prepared ownership to 911:911; do not change
  # Additional ownership setup for any remaining files
  if ! is_mounted_dir_owned_by "$MIHOMO_DATA" "$PROXY_UID" "$PROXY_GID"; then
    log "DEBUG" "MIHOMO_DATA not mounted as ${PROXY_UID}:${PROXY_GID}. Changing ownership of image directories to ${PROXY_UID}:${PROXY_GID}."
    chown_image_dirs_to_proxy
  fi

  # Now drop privileges to proxy user and run downloads as unprivileged user.
  log "DEBUG" "Dropping to ${PROXY_UID}:${PROXY_GID} and starting mihomo (will perform GEO downloads as unprivileged user if enabled)."
  exec su-exec "${PROXY_UID}:${PROXY_GID}" "$0" "--run-as-user"
}

non_root_branch_multi_user_mode() {
  get_current_user_info
  log "DEBUG" "Multi-user mode enabled, running as ${CURRENT_UID}:${CURRENT_GID}"
  
  # Ensure required directories exist (should have been created during image build)
  [ -d "$MIHOMO_DATA" ] || err_exit "MIHOMO_DATA directory not found: $MIHOMO_DATA. For image-internal usage with arbitrary --user, run as root first to initialize directories."
  
  [ -d "$WGCF_DATA" ] || err_exit "WGCF_DATA directory not found: $WGCF_DATA. For image-internal usage with arbitrary --user, run as root first to initialize directories."
  
  # Check write access
  if ! can_write_dir "$MIHOMO_DATA"; then
    err_exit "No write access to $MIHOMO_DATA. If you don't mount $MIHOMO_DATA via volumes, use --user=911:911 or run as root"
  fi
  if ! can_write_dir "$WGCF_DATA"; then
    err_exit "No write access to $WGCF_DATA. If you don't mount $WGCF_DATA via volumes, use --user=911:911 or run as root"
  fi
  
  # Use current user IDs for proxy operations
  PROXY_UID=$CURRENT_UID  
  PROXY_GID=$CURRENT_GID
}

non_root_branch_legacy_mode() {
  get_current_user_info
  # Legacy mode: strict 911:911 only
  readonly ALLOWED_UID=911
  readonly ALLOWED_GID=911

  if [ "$CURRENT_UID" -ne "$ALLOWED_UID" ] || [ "$CURRENT_GID" -ne "$ALLOWED_GID" ]; then
    log "ERROR" "Container started as non-root ${CURRENT_UID}:${CURRENT_GID} which is not allowed."
    log "ERROR" "Allowed options to start the container:"
    log "ERROR" "  1) Start container as root (no --user) – script will create proxy user/group and drop privileges"
    log "ERROR" "  2) Start container as non-root with --user=911:911 (files/dirs must be pre-owned by 911:911)."
    log "ERROR" "  3) Set MULTI_USER_MODE=true to enable multi-user support"
    exit 1
  fi
  log "DEBUG" "Running as allowed non-root ${CURRENT_UID}:${CURRENT_GID} (911:911). PROXY_UID/PROXY_GID ignored in this mode."
}
