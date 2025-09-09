# shellcheck shell=sh
# Guard
[ -n "${MWP_PROCESSES_SH_LOADED:-}" ] && return 0
MWP_PROCESSES_SH_LOADED=1

# Helper: initialize lock for child process management
init_child_pids_dir() {
  if [ -z "$CHILD_PIDS_DIR" ]; then
    CHILD_PIDS_DIR=$(mktemp -d "/tmp/mihomo_pids.XXXXXX") || err_exit "Failed to create child PIDs directory"
    chmod 700 "$CHILD_PIDS_DIR"
    TEMP_FILES="$TEMP_FILES $CHILD_PIDS_DIR"
  fi
  return 0
}

# Helper: POSIX-compliant child PID management using filesystem
manage_child_pid() {
  local operation="$1"
  local pid="$2"
  
  [ -n "$CHILD_PIDS_DIR" ] || err_exit "Child PIDs directory not initialized"
  
  case "$operation" in
    "add")
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        if [ ! -f "$CHILD_PIDS_DIR/$pid" ]; then
          touch "$CHILD_PIDS_DIR/$pid" 2>/dev/null && log "DEBUG" "Tracked child process: $pid"
        fi
      else
        log "DEBUG" "Process $pid already terminated, not tracking"
      fi
      ;;
    "remove")
      if [ -f "$CHILD_PIDS_DIR/$pid" ]; then
        rm -f "$CHILD_PIDS_DIR/$pid" 2>/dev/null && log "DEBUG" "Untracked child process: $pid"
      fi
      ;;
    "clear")
      rm -f "$CHILD_PIDS_DIR"/* 2>/dev/null && log "DEBUG" "Cleared all child processes"
      ;;
    "list")
      if [ -d "$CHILD_PIDS_DIR" ]; then
        ls "$CHILD_PIDS_DIR" 2>/dev/null | tr '\n' ' '
      fi
      ;;
    "count")
      if [ -d "$CHILD_PIDS_DIR" ]; then
        ls "$CHILD_PIDS_DIR" 2>/dev/null | wc -l
      else
        echo 0
      fi
      ;;
  esac
}

# Helper: Add child process to tracking list
track_child_process() {
  local pid="$1"
  [ -n "$pid" ] || return 1
  init_child_pids_dir || return 1
  manage_child_pid "add" "$pid"
}

# Helper: Remove child process from tracking list
untrack_child_process() {
  local pid="$1"
  [ -n "$pid" ] || return 1
  init_child_pids_dir || return 1
  manage_child_pid "remove" "$pid"
}

# Helper: terminate child processes efficiently
terminate_child_processes() {
  local child_list signal_type timeout_sec
  
  init_child_pids_dir || return 1
  child_list=$(manage_child_pid "list")
  
  [ -n "$child_list" ] || return 0
  
  signal_type="${1:-TERM}"
  timeout_sec="${2:-10}"
  
  log "DEBUG" "Terminating child processes with SIG$signal_type: $child_list"
  
  # Send signal to all processes
  for pid in $child_list; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "-$signal_type" "$pid" 2>/dev/null || manage_child_pid "remove" "$pid"
    else
      manage_child_pid "remove" "$pid"
    fi
  done
  
  # Wait for graceful termination
  local wait_count=0
  while [ $wait_count -lt $timeout_sec ] && [ "$(manage_child_pid "count")" -gt 0 ]; do
    sleep 1
    wait_count=$((wait_count + 1))
    
    # Remove terminated processes
    for pid in $(manage_child_pid "list"); do
      kill -0 "$pid" 2>/dev/null || manage_child_pid "remove" "$pid"
    done
  done
  
  return 0
}

# Helper: graceful shutdown function
graceful_shutdown() {
  local signal="${1:-UNKNOWN}"
  local exit_code=0

  # Prevent recursive shutdown calls
  if [ "$SHUTDOWN_REQUESTED" = "true" ]; then
    log "DEBUG" "Shutdown already in progress, ignoring $signal"
    return
  fi

  SHUTDOWN_REQUESTED=true
  SIGNAL_RECEIVED="$signal"
  
  log "INFO" "Received $signal, initiating graceful shutdown"
  
  # Terminate child processes gracefully, then forcefully
  terminate_child_processes "TERM" 10
  
  if [ "$(manage_child_pid "count")" -gt 0 ]; then
    log "WARN" "Force killing remaining processes: $(manage_child_pid "list")"
    terminate_child_processes "KILL" 2
    manage_child_pid "clear"
  fi
  
  # Clean up temporary files
  cleanup_temp_files
  
  # Set exit code based on signal
  case "$signal" in
    INT) exit_code=130 ;;
    TERM) exit_code=143 ;;
    *) exit_code=1 ;;
  esac
  
  log "INFO" "Shutdown complete"
  exit $exit_code
}

# Helper: Wait for child processes
safe_wait() {
  local pids="$*"
  local failed=0
  local wait_count=0
  local max_wait=30
  
  # Return early if no PIDs provided
  [ -n "$pids" ] || return 0
  
  # Wait for all processes in parallel with timeout
  while [ $wait_count -lt $max_wait ]; do
    local remaining_pids=""
    local all_done=1
    
    # Check shutdown request
    if [ "$SHUTDOWN_REQUESTED" = "true" ]; then
      log "DEBUG" "Shutdown requested, aborting wait"
      failed=1
      break
    fi
    
    # Check each PID
    for pid in $pids; do
      if kill -0 "$pid" 2>/dev/null; then
        remaining_pids="$remaining_pids $pid"
        all_done=0
      else
        untrack_child_process "$pid"
      fi
    done
    
    # Exit if all processes finished
    [ $all_done -eq 1 ] && break
    
    pids="$remaining_pids"
    sleep 0.5
    wait_count=$((wait_count + 1))
  done
  
  # Cleanup any remaining PIDs (only if timeout occurred)
  if [ $wait_count -ge $max_wait ]; then
    for pid in $pids; do
      untrack_child_process "$pid"
      failed=1
    done
  fi
  
  return $failed
}
