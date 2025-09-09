#!/bin/ash

# Connect the basic environment module
. /usr/local/bin/modules/00-env.sh

# Connect the logging module
. /usr/local/bin/modules/10-logging.sh

# Connect the utils module
. /usr/local/bin/modules/20-utils.sh

# Connect the processes module
. /usr/local/bin/modules/30-processes.sh

# Connect the validate module
. /usr/local/bin/modules/40-validate.sh

# Connect the backup module
. /usr/local/bin/modules/50-backup.sh

# Connect the geo-download module
. /usr/local/bin/modules/60-geo-download.sh

# Connect the config module
. /usr/local/bin/modules/70-config.sh

# Connect the usermode module
. /usr/local/bin/modules/80-usermode.sh

## Start

# Set up signal handlers for cleanup
trap 'graceful_shutdown INT' INT
trap 'graceful_shutdown TERM' TERM  
trap 'graceful_shutdown HUP' HUP
trap 'cleanup_temp_files' EXIT

# Timezone
if [ -n "$TZ" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then
  export TZ
else
  log "WARN" "Invalid or unset TZ: $TZ. Using UTC."
  export TZ=UTC
fi

# Version
log "DEBUG" "Alpine Linux v$(cat /etc/os-release | grep VERSION_ID | cut -d "=" -f2)"
log "DEBUG" "$(busybox | grep 'BusyBox v')"
log "DEBUG" "$(mihomo -v | grep 'Mihomo Meta v')"
log "DEBUG" "$(yq --version)"
log "DEBUG" "$(curl --version | grep curl)"
log "DEBUG" "$(tini --version)"

log "DEBUG" "Starting entrypoint.sh"

# Validate
validate_environment

# Prerequisites
check_prerequisites

# UID:GID for Proxy
determine_proxy_ids

# Backup mihomo config
backup_mihomo_config_if_mounted

# ROOT branch
if [ "$(id -u)" -eq 0 ]; then
  root_branch
fi

if [ "$1" = "--run-as-user" ]; then
  run_common_tasks
  exec "$MIHOMO_BIN" -d "$MIHOMO_DATA" -f "$MIHOMO_CONFIG_FILE"
fi

# Non-root branch
if is_true "$MULTI_USER_MODE"; then
  non_root_branch_multi_user_mode
else
  non_root_branch_legacy_mode
fi

run_common_tasks

exec "$MIHOMO_BIN" -d "$MIHOMO_DATA" -f "$MIHOMO_CONFIG_FILE"
