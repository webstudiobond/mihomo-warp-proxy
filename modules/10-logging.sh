# shellcheck shell=sh
# Guard
[ -n "${MWP_LOGGING_SH_LOADED:-}" ] && return 0
MWP_LOGGING_SH_LOADED=1

log() { 
  local level="$1"
  local message="$2"
  local log_levels="DEBUG:1 INFO:2 WARN:3 ERROR:4"
  local script_level_num=2  # Default to INFO

  # Determine numeric value of SCRIPT_LOG_LEVEL
  case "$SCRIPT_LOG_LEVEL" in
    DEBUG) script_level_num=1 ;;
    INFO) script_level_num=2 ;;
    WARN) script_level_num=3 ;;
    ERROR) script_level_num=4 ;;
    *)
      printf '%s [WARN] [%s] Invalid SCRIPT_LOG_LEVEL: %s. Using INFO. Supported levels: DEBUG, INFO, WARN, ERROR\n' \
        "$(date +%Y-%m-%dT%H:%M:%SZ)" "$$" "$SCRIPT_LOG_LEVEL"
      script_level_num=2
      ;;
  esac

  # Determine numeric value of message level
  local message_level_num=0
  case "$level" in
    DEBUG) message_level_num=1 ;;
    INFO) message_level_num=2 ;;
    WARN) message_level_num=3 ;;
    ERROR) message_level_num=4 ;;
    *) message_level_num=2 ;;  # Treat unknown as INFO
  esac

  # Output message if its level is greater than or equal to SCRIPT_LOG_LEVEL
  if [ "$message_level_num" -ge "$script_level_num" ]; then
    logger -t "MWP" -s -p "user.$level" "$(date +%Y-%m-%dT%H:%M:%SZ) [$level] [$SCRIPT_PID] $message (v$SCRIPT_VERSION)"
  fi
}

err_exit() { log "ERROR" "$1"; exit 1; }
