# shellcheck shell=sh
# Guard
[ -n "${MWP_BACKUP_SH_LOADED:-}" ] && return 0
MWP_BACKUP_SH_LOADED=1

backup_mihomo_config_if_mounted() {
  local config_file="$MIHOMO_CONFIG_FILE"
  local backup_file="${config_file}.back"
  local config_dir=$(dirname "$config_file")
  local old_umask=$(umask)
  
  umask 077

  if [ -f "$config_file" ] && [ -s "$config_file" ]; then
    if [ ! -r "$config_file" ]; then
      log "WARN" "Config file $config_file is not readable, skipping backup"
    elif can_write_dir "$config_dir"; then
      if [ -L "$config_file" ]; then
        log "DEBUG" "Config file is a symbolic link, copying content to $backup_file"
        if cat "$config_file" > "$backup_file" 2>/dev/null; then
          log "DEBUG" "Backup created: $backup_file"
        else
          log "WARN" "Failed to create backup of symbolic link content to $backup_file: $?"
        fi
      else
        log "DEBUG" "Copying config to $backup_file"
        if cp "$config_file" "$backup_file" 2>/dev/null; then
          log "DEBUG" "Backup created: $backup_file"
        else
          log "WARN" "Failed to create backup to $backup_file: $?"
        fi
      fi
    else
      log "WARN" "No write access to $config_dir for backup. Permissions: $(ls -ld "$config_dir" 2>/dev/null || echo 'unknown')"
    fi
  else
    log "DEBUG" "No config to backup at $config_file"
  fi
  umask "$old_umask"
  return 0
}
