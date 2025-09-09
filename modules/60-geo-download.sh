# shellcheck shell=sh
# Guard
[ -n "${MWP_GEO_DOWNLOAD_SH_LOADED:-}" ] && return 0
MWP_GEO_DOWNLOAD_SH_LOADED=1

# Helper function to safely follow redirects, validating each host
follow_redirects_safe() {
  local url="$1"
  local max_redirs="${2:-3}"
  local current_url="$url"
  local redir_count=0
  local headers status location host_lower auth_opt
  auth_opt=""
  if [ -n "$GEO_AUTH_USER" ] && [ -n "$GEO_AUTH_PASS" ]; then
    auth_opt="--user $GEO_AUTH_USER:$GEO_AUTH_PASS"
  fi
  log "DEBUG" "Safely follow redirects for $url"
  while [ $redir_count -lt $max_redirs ]; do
      # extract host from current_url (strip scheme/path, remove userinfo, support [ipv6])
      tmp="${current_url#*://}"
      tmp="${tmp%%/*}"
      case "$tmp" in *@*) tmp="${tmp#*@}" ;; esac
      case "$tmp" in \[*\]*) host="${tmp#\[}"; host="${host%%]*}" ;; *) host="${tmp%%:*}" ;; esac
      host_lower=$(printf '%s' "$host" | tr 'A-Z' 'a-z')
      if ! validate_resolved_ips "$host_lower"; then
      log "ERROR" "Invalid resolved IPs in redirect chain for host: $host_lower"
      return 1
    fi
    if command -v curl >/dev/null 2>&1; then
      headers=$(timeout 30 curl -fsSI --http1.1 --max-time 30 $auth_opt "$current_url" 2>/dev/null) || err_exit "Failed to get headers for $current_url"
    else
      err_exit "No curl or wget available for headers"
    fi
    if command -v curl >/dev/null 2>&1; then
      status=$(printf '%s' "$headers" | head -n1 | cut -d' ' -f2)
      location=$(printf '%s' "$headers" | grep -i '^location:' | cut -d' ' -f2- | tr -d '\r')
    else
      status=$(printf '%s' "$headers" | grep '^  HTTP/' | head -n1 | cut -d' ' -f2)
      location=$(printf '%s' "$headers" | grep '^  Location:' | cut -d' ' -f3- | tr -d '\r')
    fi
    if [ -z "$status" ] || [ "$status" -lt 200 ] || [ "$status" -ge 400 ]; then
      err_exit "Invalid HTTP status $status for $current_url in redirect chain"
    fi
    if [ "$status" -lt 300 ]; then
      printf '%s\n%s' "$current_url" "$headers"
      return 0
    fi
    if [ -z "$location" ]; then
      err_exit "Redirect without Location header for $current_url"
    fi
    # Block dangerous percent-encodings and raw control chars in redirect Location
    case "$location" in
      *%00*|*%0a*|*%0A*|*%0d*|*%0D*|*%1b*|*%1B*|*%2e%2e*|*%2E%2E*|*%25*)
        err_exit "Redirect Location contains dangerous percent-encoding: $location"
        ;;
    esac
    if printf '%s' "$location" | LC_ALL=C grep -q '[[:cntrl:]]'; then
      err_exit "Redirect Location contains raw control characters: $location"
    fi
    case "$location" in
      https://*) current_url="$location" ;;
      //*) # protocol-relative: prepend scheme from current_url
        proto=$(printf '%s' "$current_url" | sed -n 's,^\(https\?://\).*,\1,p')
        current_url="${proto}${location#//}" ;;
      /*) # absolute path: keep scheme+host
        base=$(printf '%s' "$current_url" | sed 's,^\(https\?://[^/]*\).*,\1,')
        current_url="${base}${location}" ;;
      *) # relative path: append to current base dir
        base=$(printf '%s' "$current_url" | sed 's,^\(https\?://.*/\).*,\1,')
        current_url="${base}${location}" ;;
    esac
    redir_count=$((redir_count + 1))
  done
  err_exit "Too many redirects for $url"
}

# Helper function to extract metadata from headers (ETag, Last-Modified, Content-Length, Content-Type)
get_remote_file_metadata() {
  local headers="$1"
  local metadata_file="$2"
  printf '%s' "$headers" | awk '
  /^[Ee][Tt]ag:/ { gsub(/["\r\n]/, "", $2); print "etag=" $2 }
  /^[Ll]ast-[Mm]odified:/ { 
    sub(/^[Ll]ast-[Mm]odified: */, ""); 
    gsub(/\r/, ""); 
    print "last_modified=" $0 
  }
  /^[Cc]ontent-[Ll]ength:/ { print "content_length=" $2 }
  /^[Cc]ontent-[Tt]ype:/ { gsub(/\r$/, ""); print "content_type=" $2 }
  ' > "$metadata_file"
  return 0
}

# Helper function to check if file needs update
needs_update() {
  local url="$1"
  local dst="$2"
  local provided_meta="$3"
  local cache_dir="$MIHOMO_DATA/.cache"
  local cache_file url_hash metadata_file old_metadata new_metadata
  
  # Create cache directory
  mkdir -p "$cache_dir" || return 0  # If can't create cache, assume update needed
  chmod 700 "$cache_dir"
  
  # Generate cache filename from URL hash
  url_hash=$(printf '%s' "$url" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo "fallback")
  cache_file="$cache_dir/$url_hash.meta"
  metadata_file="$provided_meta"
  
  # If file doesn't exist locally, update needed
  if [ ! -f "$dst" ]; then
    rm -f "$cache_file"
    if [ -n "$provided_meta" ]; then
      remove_temp_file "$provided_meta"
    fi
    return 0
  fi
  
  # If no cached metadata, assume update needed
  if [ ! -f "$cache_file" ]; then
    cp "$metadata_file" "$cache_file" 2>/dev/null
    if [ -n "$provided_meta" ]; then
      remove_temp_file "$provided_meta"
    fi
    return 0
  fi
  
  # Compare metadata
  old_metadata=$(cat "$cache_file" 2>/dev/null | sort)
  new_metadata=$(cat "$metadata_file" 2>/dev/null | sort)
  
  if [ "$old_metadata" = "$new_metadata" ] && [ -n "$old_metadata" ]; then
    log "DEBUG" "Skip Download. File unchanged on server: $url"
    if [ -n "$provided_meta" ]; then
      remove_temp_file "$provided_meta"
    fi
    return 1  # No update needed
  fi
  
  # Update cache with new metadata
  cp "$metadata_file" "$cache_file" 2>/dev/null
  if [ -n "$provided_meta" ]; then
    remove_temp_file "$provided_meta"
  fi
  return 0  # Update needed
}

# Helper function for download
download_file() {
  url="$1"; dst="$2"
  
  url_lower=$(printf '%s' "$url" | tr 'A-Z' 'a-z')
  # Strict URL scheme validation — only HTTPS allowed
  case "$url_lower" in
    https://*)
      # Basic safety checks using POSIX-compatible syntax
      case "$url" in
        *"
"*) err_exit "URL contains newline: $url" ;;
        *" "*) log "WARN" "URL contains space: $url" ;;
      esac
      
      # Check for tab (POSIX-safe)
      if printf '%s' "$url" | grep -q "$(printf '\t')"; then
        log "WARN" "URL contains tab: $url"
      fi
      
      # Check for null bytes and validate host/port to prevent SSRF
      if printf '%s' "$url" | od -t x1 | grep -q ' 00 '; then
        err_exit "URL contains null bytes: $url"
      fi
      # Block dangerous percent-encodings and raw control chars in URL
      case "$url" in
        *%00*|*%0a*|*%0A*|*%0d*|*%0D*|*%1b*|*%1B*|*%2e%2e*|*%2E%2E*|*%25*)
          err_exit "URL contains dangerous percent-encoding: $url"
          ;;
      esac
      if printf '%s' "$url" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        err_exit "URL contains raw control characters: $url"
      fi
      # extract host_port (remove scheme and path), then strip userinfo, support [ipv6]
      tmp="${url#*://}"
      tmp="${tmp%%/*}"
      case "$tmp" in *@*) tmp="${tmp#*@}" ;; esac
      if [ -z "$tmp" ]; then
        err_exit "Invalid URL: no host part in $url"
      fi
      port=''  # initialize to empty to avoid "parameter not set"
      case "$tmp" in
        \[*\]*) host="${tmp#\[}"; host="${host%%]*}";;
        *) case "$tmp" in *:*) port="${tmp##*:}"; host="${tmp%:$port}";; *) host="$tmp";; esac;;
      esac
      host_lower=$(printf '%s' "$host" | tr 'A-Z' 'a-z')
      [ -n "$host_lower" ] || err_exit "ERROR" "No host in URL: $url"
      # make sure port is numeric (if set); if non-numeric, reset to empty
      case "$port" in ''|*[!0-9]*) port='' ;; esac
      
      # Enhanced hostname validation
      case "$host_lower" in
        localhost|*.local|127.*|::1|0.0.0.0|169.254.*)
          err_exit "Forbidden hostname: $host_lower"
        ;;
        # Block encoded IPs and suspicious patterns  
        0x*|0[0-7][0-7][0-7]*|*[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*)
          err_exit "Suspicious encoded hostname: $host_lower"
        ;;
      esac
      
      # Resolve and validate all IPs for this hostname
      if ! validate_resolved_ips "$host_lower"; then
        return 1
      fi
      
      # Port validation for sensitive services (regardless of IP)
      if [ -n "$port" ]; then
        case "$port" in
          22|23|25|53|110|143|993|995|1433|1521|3306|3389|5432|5984|6379|8086|9200|9300|11211|27017)
            err_exit "Forbidden port (sensitive service): $port"
          ;;
          2375|2376|2377|2378)
            err_exit "Forbidden port (Docker API): $port"
          ;;
        esac
      fi
      ;;
    *)  
      err_exit "Invalid URL scheme — only HTTPS is allowed: $url"
      ;;
  esac

  # Prepare curl auth options if credentials provided
  auth_opt=""
  if [ -n "$GEO_AUTH_USER" ] && [ -n "$GEO_AUTH_PASS" ]; then
    auth_opt="--user $GEO_AUTH_USER:$GEO_AUTH_PASS"
  fi
  # Flag to track if auth was attempted
  auth_attempted=0
  if [ -n "$auth_opt" ]; then
    auth_attempted=1
  fi

  # Validate destination path
  validate_path "$dst" "download destination"

  # Smart caching: get file metadata and check if file needs update
  local final_url headers remote_data
  remote_data=$(follow_redirects_safe "$url") || return 1
  final_url=$(printf '%s' "$remote_data" | head -n 1)
  headers=$(printf '%s' "$remote_data" | tail -n +2)

  local temp_meta
  temp_meta=$(create_secure_temp_file "$(dirname "$dst")" "metadata") || return 1
  get_remote_file_metadata "$headers" "$temp_meta"

  local content_type
  content_type=$(grep '^content_type=' "$temp_meta" | cut -d'=' -f2 | cut -d';' -f1 | tr -d ' ' | tr 'A-Z' 'a-z')
  case "$content_type" in
    application/octet-stream|application/binary|application/vnd.maxmind.com-geoip2-mmdb|'') ;;
    text/*) log "ERROR" "Unexpected text content type $content_type for $url - possible error page"; remove_temp_file "$temp_meta"; return 1 ;;
    *) log "WARN" "Unexpected content type $content_type for $url, proceeding with caution" ;;
  esac
  
  if ! is_true "${GEO_REDOWNLOAD}"; then
    if ! needs_update "$url" "$dst" "$temp_meta"; then
      remove_temp_file "$temp_meta"
      return 0
    fi
  fi
  remove_temp_file "$temp_meta"
  
  log "DEBUG" "Downloading $url -> $dst"

  tmp_dst=$(create_secure_temp_file "$(dirname "$dst")" "download") || err_exit "Failed to create temp file for $dst"

  if command -v curl >/dev/null 2>&1; then
    (ulimit -v 131072; timeout 300 curl -fsS --http1.1 \
      --retry 3 --connect-timeout 30 --max-time 300 --max-filesize 104857600 \
      --proto '=https' --proto-redir '=https' \
      $auth_opt -o "$tmp_dst" "$final_url") &
    local download_pid=$!
    track_child_process "$download_pid"
    if wait "$download_pid"; then
      untrack_child_process "$download_pid"
    else
      untrack_child_process "$download_pid"
      rm -f "$tmp_dst"
      if [ "$auth_attempted" -eq 0 ] && [ -n "$(curl -I -s -w "%{http_code}" "$url" | grep '^401')" ]; then
        err_exit "Download failed: Authentication required but GEO_AUTH_USER/GEO_AUTH_PASS not set for $url"
      else
        err_exit "Failed to download $url using curl"
      fi
    fi
  else
    rm -f "$tmp_dst"
    return 1
  fi
  
  # Verify file size and basic format
  if [ ! -s "$tmp_dst" ]; then
    rm -f "$tmp_dst"
    err_exit "Downloaded file is empty: $url"
  fi
  
  file_size=$(stat -c%s "$tmp_dst" 2>/dev/null || stat -f%z "$tmp_dst" 2>/dev/null || echo "0")
  if [ "$file_size" -gt 104857600 ]; then  # 100MB limit
    rm -f "$tmp_dst"
    err_exit "Downloaded file too large: $file_size bytes from $url"
  fi
  
  mv "$tmp_dst" "$dst" || { rm -f "$tmp_dst"; return 1; }
  return 0
}

prepare_geo_files() {
  local GEOIP_DST="$MIHOMO_DATA/geoip.dat"
  local GEOSITE_DST="$MIHOMO_DATA/geosite.dat"
  local MMDB_DST="$MIHOMO_DATA/geoip.metadb"
  local ASN_DST="$MIHOMO_DATA/GeoLite2-ASN.mmdb"
  local bg_pids
  local exit_code=0
  
  (download_file "$GEO_URL_GEOIP" "$GEOIP_DST" || err_exit "Failed to download geoip: $GEO_URL_GEOIP") &
  pid1=$!; bg_pids="$pid1"; track_child_process "$pid1"
  
  (download_file "$GEO_URL_GEOSITE" "$GEOSITE_DST" || err_exit "Failed to download geosite: $GEO_URL_GEOSITE") &
  pid2=$!; bg_pids="$bg_pids $pid2"; track_child_process "$pid2"
  
  (download_file "$GEO_URL_MMDB" "$MMDB_DST" || err_exit "Failed to download mmdb: $GEO_URL_MMDB") &
  pid3=$!; bg_pids="$bg_pids $pid3"; track_child_process "$pid3"
  
  (download_file "$GEO_URL_ASN" "$ASN_DST" || err_exit "Failed to download asn: $GEO_URL_ASN") &
  pid4=$!; bg_pids="$bg_pids $pid4"; track_child_process "$pid4"
  
  if ! safe_wait $bg_pids; then
    exit_code=1
  fi
  
  [ "$exit_code" -eq 0 ] || err_exit "One or more geo file downloads failed"

  # Set secure permissions and verify file integrity
  for geo_file in "$GEOIP_DST" "$GEOSITE_DST" "$MMDB_DST" "$ASN_DST"; do
    if [ -f "$geo_file" ]; then
      chmod 0600 "$geo_file" || log "WARN" "Failed to set permissions on $geo_file"
      # Basic file validation - check if file is not empty and has reasonable size
      if [ ! -s "$geo_file" ]; then
        log "ERROR" "Geo file is empty: $geo_file"
        rm -f "$geo_file"
        return 1
      fi
    fi
  done
}
