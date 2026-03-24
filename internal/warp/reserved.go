// Package warp fetches the WARP device's reserved bytes from the Cloudflare
// API. The reserved field is a [3]byte array embedded in the WireGuard
// handshake that identifies the WARP client to Cloudflare's network.
// Without it mihomo still connects, but Cloudflare may route the traffic
// differently or apply stricter rate limits.
package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
)

// maxAccountFileSize caps reads of wgcf-account.toml to prevent OOM.
const maxAccountFileSize = 64 * 1024 // 64 KB

const (
	warpAPIBase     = "https://api.cloudflareclient.com/v0a2158/reg"
	apiTimeout      = 30 * time.Second
	maxResponseSize = 1 * 1024 * 1024 // 1 MB — API responses are small JSON objects
)

// validDeviceID matches UUIDs as produced by wgcf (hex digits and hyphens only).
// Validating before URL interpolation prevents path traversal into other API endpoints.
var validDeviceID = regexp.MustCompile(`^[a-fA-F0-9\-]{1,64}$`)

// accountFile is a minimal representation of the fields we need from
// wgcf-account.toml. Full TOML parsing is used to avoid brittle line-by-line
// grep logic that would break on key ordering or whitespace changes.
type accountFields struct {
	AccessToken string
	DeviceID    string
}

// deviceResponse is the subset of the Cloudflare WARP API response that
// contains the client_id used to derive the reserved bytes.
type deviceResponse struct {
	Config struct {
		ClientID string `json:"client_id"`
	} `json:"config"`
	Error string `json:"error"`
}

// FetchReserved reads credentials from accountFile, calls the Cloudflare WARP
// API to retrieve the device's client_id, decodes it from base64, and returns
// it as a [3]byte array.
//
// Failures are non-fatal at the call site — mihomo functions without reserved
// bytes. Callers should log the error and continue rather than aborting startup.
func FetchReserved(accountFile string, log *logging.Logger) ([3]byte, error) {
	var empty [3]byte

	if err := checkFilePermissions(accountFile); err != nil {
		return empty, err
	}

	fields, err := parseAccountFile(accountFile)
	if err != nil {
		return empty, fmt.Errorf("warp: parse account file: %w", err)
	}

	if !validDeviceID.MatchString(fields.DeviceID) {
		return empty, fmt.Errorf("warp: device_id %q contains invalid characters", fields.DeviceID)
	}

	log.Debugf("warp: fetching reserved bytes for device %s", fields.DeviceID)

	resp, err := fetchDeviceInfo(fields.AccessToken, fields.DeviceID)
	if err != nil {
		return empty, fmt.Errorf("warp: API request failed: %w", err)
	}

	if resp.Error != "" {
		return empty, fmt.Errorf("warp: API returned error: %s", resp.Error)
	}

	if resp.Config.ClientID == "" {
		return empty, errors.New("warp: client_id not present in API response")
	}

	reserved, err := decodeClientID(resp.Config.ClientID)
	if err != nil {
		return empty, fmt.Errorf("warp: decode client_id: %w", err)
	}

	log.Debugf("warp: reserved bytes: [%d, %d, %d]", reserved[0], reserved[1], reserved[2])
	return reserved, nil
}

// fetchDeviceInfo calls the WARP API and returns the parsed response.
func fetchDeviceInfo(accessToken, deviceID string) (*deviceResponse, error) {
	// deviceID is validated against validDeviceID before this call, so URL
	// interpolation is safe.
	apiURL := fmt.Sprintf("%s/%s", warpAPIBase, deviceID)

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create API request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("CF-Client-Version", "a-6.10-2158")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // read-only body

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseSize)
	var result deviceResponse
	if err := json.NewDecoder(limited).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse JSON response: %w", err)
	}

	return &result, nil
}

// decodeClientID base64-decodes the client_id and validates it is exactly
// 3 bytes. The WARP protocol reserves exactly 3 bytes in the WireGuard
// handshake for client identification — any other length is invalid.
func decodeClientID(clientID string) ([3]byte, error) {
	var result [3]byte

	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		// Some WARP API versions use URL-safe base64 without padding.
		decoded, err = base64.RawURLEncoding.DecodeString(clientID)
		if err != nil {
			return result, fmt.Errorf("base64 decode failed: %w", err)
		}
	}

	if len(decoded) != 3 {
		return result, fmt.Errorf("client_id decoded to %d bytes, expected exactly 3", len(decoded))
	}

	copy(result[:], decoded)
	return result, nil
}

// parseAccountFile extracts access_token and device_id from the TOML file
// written by wgcf. We use a simple line scanner rather than a full TOML
// parser to avoid adding a dependency for a two-field extraction.
// The format produced by wgcf is stable and well-known.
func parseAccountFile(path string) (*accountFields, error) {
	// #nosec G304 -- Path is strictly internal (cfg.Paths.WgcfAccountFile),
	// verified by the caller (checkFilePermissions).
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open account file: %w", err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only file

	data, err := io.ReadAll(io.LimitReader(f, maxAccountFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read account file: %w", err)
	}
	if len(data) > maxAccountFileSize {
		return nil, fmt.Errorf("account file %q exceeds 64KB limit", path)
	}

	fields := &accountFields{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		switch key {
		case "access_token":
			fields.AccessToken = value
		case "device_id":
			fields.DeviceID = value
		}
	}

	if fields.AccessToken == "" {
		return nil, fmt.Errorf("access_token not found in %q", path)
	}
	if fields.DeviceID == "" {
		return nil, fmt.Errorf("device_id not found in %q", path)
	}

	return fields, nil
}

// checkFilePermissions rejects account files with permissions broader than
// 0o600 to prevent credential exposure via world-readable files.
func checkFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("warp: stat %q: %w", path, err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o400 {
		return fmt.Errorf("warp: account file %q has unsafe permissions %04o (want 0o600 or 0o400)", path, perm)
	}
	return nil
}
