# shellcheck shell=sh
# Guard
[ -n "${MWP_UTILS_SH_LOADED:-}" ] && return 0
MWP_UTILS_SH_LOADED=1

# Portable stat wrapper: usage stat_safe '<format>' path
# Tries GNU stat -c, then BSD stat -f; prints result on stdout and returns 0 on success, 1 on failure.
stat_safe() {
    fmt=$1; shift
    # Try GNU stat
    if stat -c "$fmt" "$@" >/dev/null 2>&1; then
        stat -c "$fmt" "$@" 2>/dev/null || return 1
        return 0
    fi
    # Try BSD stat
    if stat -f "$fmt" "$@" >/dev/null 2>&1; then
        stat -f "$fmt" "$@" 2>/dev/null || return 1
        return 0
    fi
    return 1
}

# Portable chown wrapper: tries 'chown -h' to affect symlink, falls back to 'chown'
chown_safe() {
    # Pass through all args to chown variants
    if chown -h "$@" >/dev/null 2>&1; then
        return 0
    fi
    if chown "$@" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Helper: function to check prerequisites
check_prerequisites() {
  [ -x "$MIHOMO_BIN" ] || err_exit "mihomo binary not found or not executable: $MIHOMO_BIN"
  [ -f "$MIHOMO_CONFIG_FILE" ] || log "WARN" "config file not found at $MIHOMO_CONFIG_FILE — mihomo may run with defaults or fail"
}

# Helper: get current user info for multi-user mode
get_current_user_info() {
  CURRENT_UID=$(id -u)
  CURRENT_GID=$(id -g)
}

# Helper: function to determine effective PROXY_UID/GID (env > defaults)
determine_proxy_ids() {
  if [ -n "$PROXY_UID_ENV" ] && [ -n "$PROXY_GID_ENV" ]; then
    PROXY_UID="$PROXY_UID_ENV"
    PROXY_GID="$PROXY_GID_ENV"
    return
  fi
  PROXY_UID=${PROXY_UID_ENV:-911}
  PROXY_GID=${PROXY_GID_ENV:-911}
}

# Helper: function to check if value represents true
is_true() {
  case "${1:-false}" in
    true|1|yes|on|True|TRUE) return 0 ;;
    *) return 1 ;;
  esac
}

# Helper: can write directory
can_write_dir() {
  local testdir="$1"
  local prefix="${2:-mihomo_write_check}"
  tmpf=$(umask 077; mktemp "$testdir/.$prefix.XXXXXX" 2>/dev/null)
  if [ $? -ne 0 ] || [ -z "$tmpf" ]; then
    return 1
  fi

  if : > "$tmpf" 2>/dev/null; then
    rm -f "$tmpf" >/dev/null 2>&1 || { log "WARN" "Failed to remove temp file: $tmpf"; }
    return 0
  fi
  rm -f "$tmpf" >/dev/null 2>&1 || { log "WARN" "Failed to remove temp file: $tmpf"; }
  return 1
}

# Helper: who owned mounted directory
is_mounted_dir_owned_by() {
  log "DEBUG" "Check who owned mounted directory"
  # returns 0 if filesystem owner of directory equals given uid:gid (approximate check via stat)
  dir="$1"
  uid="$2"
  gid="$3"
  if [ ! -e "$dir" ]; then
    return 1
  fi
  
  stat_output=$(stat_safe '%u %g' "$dir" 2>/dev/null || echo "")
  st_uid=$(echo "$stat_output" | cut -d' ' -f1)
  st_gid=$(echo "$stat_output" | cut -d' ' -f2)
  [ "$st_uid" = "$uid" ] && [ "$st_gid" = "$gid" ]
}

# Helper: ensure directory exists and is writable by current user
ensure_writable_dir() {
  dir="$1"
  mkdir -p "$dir" 2>/dev/null || { log "WARN" "Failed to mkdir: $dir"; }
  
  # Try to fix ownership if directory exists but not writable
  if [ -d "$dir" ] && ! can_write_dir "$dir"; then
    current_uid=$(id -u)
    current_gid=$(id -g)
    chown "${current_uid}:${current_gid}" "$dir" 2>/dev/null || { log "WARN" "Failed to chown: $dir"; }
  fi
}

# Helper: attempt to chown MIHOMO_DATA and bundled files to PROXY_UID:PROXY_GID (only when MIHOMO_DATA not mounted)
chown_image_dirs_to_proxy() {
  # Set ownership for internal files and directories
  log "DEBUG" "Setting ownership of internal directories and files to ${PROXY_UID}:${PROXY_GID}"

  if [ -d "$MIHOMO_DATA" ]; then

    chown_safe "${PROXY_UID}:${PROXY_GID}" "$MIHOMO_DATA" || err_exit "Failed to chown: $MIHOMO_DATA"

    if [ "$(stat_safe '%u:%g' "$MIHOMO_DATA" 2>/dev/null || echo "")" != "${PROXY_UID}:${PROXY_GID}" ]; then
      err_exit "Ownership verification failed for $MIHOMO_DATA"
    fi

    for file in cache.db config.yaml config.yaml.back geoip.dat geoip.metadb GeoLite2-ASN.mmdb geosite.dat; do
      if [ -f "$MIHOMO_DATA/$file" ]; then
        chown_safe "${PROXY_UID}:${PROXY_GID}" "$MIHOMO_DATA/$file" || err_exit "Failed to chown: $MIHOMO_DATA/$file"
        if [ "$(stat_safe '%u:%g' "$MIHOMO_DATA/$file" 2>/dev/null || echo "")" != "${PROXY_UID}:${PROXY_GID}" ]; then
          err_exit "Ownership verification failed for $MIHOMO_DATA/$file"
        fi
        log "DEBUG" "Successfully set ownership of $MIHOMO_DATA/$file to ${PROXY_UID}:${PROXY_GID}"
      fi
    done

    log "DEBUG" "Successfully set ownership of $MIHOMO_DATA to ${PROXY_UID}:${PROXY_GID}"
  else
    log "WARN" "Directory $MIHOMO_DATA does not exist"
  fi
  
  # Ensure wgcf directory exists and has correct ownership
  mkdir -p "$WGCF_DATA" 2>/dev/null || { log "WARN" "Failed to mkdir: $WGCF_DATA"; }
  if [ -d "$WGCF_DATA" ]; then
    chown_safe "${PROXY_UID}:${PROXY_GID}" "$WGCF_DATA" || err_exit "Failed to chown: $WGCF_DATA"
    if [ "$(stat_safe '%u:%g' "$WGCF_DATA" 2>/dev/null || echo "")" != "${PROXY_UID}:${PROXY_GID}" ]; then
      err_exit "Ownership verification failed for $WGCF_DATA"
    fi
    for file in wgcf-account.toml wgcf-profile.conf; do
      if [ -f "$WGCF_DATA/$file" ]; then
        chown_safe "${PROXY_UID}:${PROXY_GID}" "$WGCF_DATA/$file" || err_exit "Failed to chown: $WGCF_DATA/$file"
        if [ "$(stat_safe '%u:%g' "$WGCF_DATA/$file" 2>/dev/null || echo "")" != "${PROXY_UID}:${PROXY_GID}" ]; then
          err_exit "Ownership verification failed for $WGCF_DATA/$file"
        fi
        log "DEBUG" "Successfully set ownership of $WGCF_DATA/$file to ${PROXY_UID}:${PROXY_GID}"
      fi
    done
    log "DEBUG" "Successfully set ownership of $WGCF_DATA to ${PROXY_UID}:${PROXY_GID}"
  else
    log "WARN" "Directory $WGCF_DATA does not exist"
  fi
  
  # Only chown config file if it's not in a mounted directory
  if [ -f "$MIHOMO_CONFIG_FILE" ] && can_write_dir "$(dirname "$MIHOMO_CONFIG_FILE")"; then
    if [ "$MIHOMO_CONFIG_FILE" != "$MIHOMO_DATA/config.yaml" ]; then
      chown_safe "${PROXY_UID}:${PROXY_GID}" "$MIHOMO_CONFIG_FILE" || err_exit "Failed to chown: $MIHOMO_CONFIG_FILE"
      if [ "$(stat_safe '%u:%g' "$MIHOMO_CONFIG_FILE" 2>/dev/null || echo "")" != "${PROXY_UID}:${PROXY_GID}" ]; then
        err_exit "Ownership verification failed for $MIHOMO_CONFIG_FILE"
      fi
      log "DEBUG" "Successfully set ownership of $MIHOMO_CONFIG_FILE to ${PROXY_UID}:${PROXY_GID}"
    fi
  fi
}

# Helper: create secure temporary file with proper cleanup
create_secure_temp_file() {
  local base_dir="$1"
  local prefix="${2:-mihomo_temp}"
  local temp_file old_umask max_attempts counter
  
  # Validate base directory
  [ -d "$base_dir" ] || err_exit "Base directory does not exist: $base_dir"
  
  old_umask=$(umask)
  umask 077
  
  # Race condition protection - multiple attempts to create
  max_attempts=10
  counter=0
  while [ $counter -lt $max_attempts ]; do
    temp_file=$(mktemp "$base_dir/.$prefix.XXXXXX" 2>/dev/null) || temp_file=""
    if [ -n "$temp_file" ] && [ -f "$temp_file" ] && [ ! -L "$temp_file" ]; then
      # We check that the file was actually created by us
      if [ -O "$temp_file" ] 2>/dev/null || true; then
        break
      else
        rm -f "$temp_file" 2>/dev/null || true
        temp_file=""
      fi
    fi
    counter=$((counter + 1))
    # A small delay to prevent busy loop
    sleep 0.1
  done
  
  if [ -z "$temp_file" ] || [ ! -f "$temp_file" ]; then
    umask "$old_umask"
    err_exit "Failed to create secure temp file in $base_dir after $max_attempts attempts"
  fi
  
  umask "$old_umask"

  # Ensure permissions are secure
  chmod 0600 "$temp_file" || {
    rm -f "$temp_file" 2>/dev/null
    err_exit "Failed to set permissions on temp file"
  }
  
  # Verify ownership and permissions
  current_uid=$(id -u)
  current_gid=$(id -g)

  file_uid=$(stat_safe %u "$temp_file" 2>/dev/null || echo "")
  file_gid=$(stat_safe %g "$temp_file" 2>/dev/null || echo "")
  file_mode=$(stat_safe %a "$temp_file" 2>/dev/null || echo "")
  
  if [ "$file_uid" != "$current_uid" ] || [ "$file_gid" != "$current_gid" ] || [ "$file_mode" != "600" ]; then
    rm -f "$temp_file" 2>/dev/null
    err_exit "Temp file has unexpected ownership or permissions"
  fi

  # Verify temp file is regular file (not symlink)
  if [ ! -f "$temp_file" ] || [ -L "$temp_file" ]; then
    rm -f "$temp_file" 2>/dev/null
    err_exit "Temp file creation resulted in non-regular file"
  fi

  # Register temp file for cleanup
  TEMP_FILES="$TEMP_FILES $temp_file"
  
  printf '%s' "$temp_file"
}

# Helper: safe removal of temporary file with logging
remove_temp_file() {
  local temp_file="$1"
  if [ -n "$temp_file" ] && [ -f "$temp_file" ] && [ ! -L "$temp_file" ]; then
    if rm -f "$temp_file" 2>/dev/null && [ ! -e "$temp_file" ]; then
      # Remove from TEMP_FILES list
      TEMP_FILES=$(printf '%s' "$TEMP_FILES" | sed "s| $temp_file||g" | sed "s|$temp_file ||g" | sed "s|$temp_file$||")
    else
      log "WARN" "Failed to remove temp file: $temp_file"
    fi
  fi
}

# Helper: cleanup function for temporary files
cleanup_temp_files() {
  local temp_item temp_realpath

  if [ -n "$TEMP_FILES" ]; then
    log "DEBUG" "Cleaning up temporary files"
    for temp_item in $TEMP_FILES; do
      # Защита от symlink атак - проверяем что это обычный файл/каталог
      if [ -f "$temp_item" ] && [ ! -L "$temp_item" ]; then
        # Дополнительная проверка realpath если доступна
        if command -v realpath >/dev/null 2>&1; then
          temp_realpath=$(realpath "$temp_item" 2>/dev/null) || temp_realpath="$temp_item"
          case "$temp_realpath" in
            /tmp/*|*/tmp/*) rm -f "$temp_item" 2>/dev/null || log "WARN" "Failed to remove temp file: $temp_item" ;;
            *) log "WARN" "Suspicious temp file path: $temp_item -> $temp_realpath" ;;
          esac
        else
          rm -f "$temp_item" 2>/dev/null || log "WARN" "Failed to remove temp file: $temp_item"
        fi
      elif [ -d "$temp_item" ] && [ ! -L "$temp_item" ]; then
        # Аналогичная проверка для каталогов
        if command -v realpath >/dev/null 2>&1; then
          temp_realpath=$(realpath "$temp_item" 2>/dev/null) || temp_realpath="$temp_item"
          case "$temp_realpath" in
            /tmp/*|*/tmp/*) rm -rf "$temp_item" 2>/dev/null || log "WARN" "Failed to remove temp directory: $temp_item" ;;
            *) log "WARN" "Suspicious temp directory path: $temp_item -> $temp_realpath" ;;
          esac
        else
          rm -rf "$temp_item" 2>/dev/null || log "WARN" "Failed to remove temp directory: $temp_item"
        fi
      else
       log "WARN" "Skipping cleanup of suspicious item (symlink or non-existent): $temp_item"
     fi
    done
    TEMP_FILES=""
  fi
 
  # Clean up child PIDs directory
  if [ -n "$CHILD_PIDS_DIR" ] && [ -d "$CHILD_PIDS_DIR" ]; then
    rm -rf "$CHILD_PIDS_DIR" 2>/dev/null || log "WARN" "Failed to remove PIDs directory: $CHILD_PIDS_DIR"
    CHILD_PIDS_DIR=""
  fi
}

# Helper: run common tasks
run_common_tasks() {
  if is_true "${GEO}"; then
    if ! can_write_dir "$MIHOMO_DATA"; then
      err_exit "No write access to $MIHOMO_DATA"
    fi
    prepare_geo_files
  fi
  
  if is_true "${USE_WARP_CONFIG:-false}"; then
    # setup wgcf warp configuration
    . /usr/local/bin/modules/90-wgcf.sh
  else
    log "DEBUG" "WARP disabled, skipping wgcf configuration"
    update_mihomo_config_with_environment
    if [ ! -f "$MIHOMO_CONFIG_FILE" ]; then
      log "DEBUG" "Creating mihomo config"
      create_mihomo_template_config
    fi
  fi
}
