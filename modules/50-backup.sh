# shellcheck shell=sh
# Guard
[ -n "${MWP_BACKUP_SH_LOADED:-}" ] && return 0
MWP_BACKUP_SH_LOADED=1

backup_mihomo_config_if_mounted() {
  local config_file="$MIHOMO_CONFIG_FILE"
  local backup_file="${config_file}.back"
  local config_dir=$(dirname "$config_file")
  local old_umask temp_backup
  
  old_umask=$(umask)

  umask 077

  if [ -f "$config_file" ] && [ -s "$config_file" ] && [ -r "$config_file" ] && can_write_dir "$config_dir"; then
    temp_backup="${backup_file}.tmp.$$"
    if [ -L "$config_file" ]; then
      log "DEBUG" "Config file is a symbolic link, copying content atomically"
      if cat "$config_file" > "$temp_backup" 2>/dev/null && mv "$temp_backup" "$backup_file" 2>/dev/null; then
        log "DEBUG" "Backup created: $backup_file"
      else
        rm -f "$temp_backup" 2>/dev/null
        log "WARN" "Failed to create backup of symbolic link content"
      fi
    else
      log "DEBUG" "Copying config atomically"
      if cp "$config_file" "$temp_backup" 2>/dev/null && mv "$temp_backup" "$backup_file" 2>/dev/null; then
        log "DEBUG" "Backup created: $backup_file"
      else
        rm -f "$temp_backup" 2>/dev/null
        log "WARN" "Failed to create backup"
      fi
    fi
  elif [ ! -f "$config_file" ]; then
    log "DEBUG" "No config to backup at $config_file"
  else
    log "WARN" "Cannot backup config - file not readable or no write access to $config_dir"
  fi

  umask "$old_umask"
  return 0
}
