// Package geo downloads and caches the four geodata files required by mihomo.
// Downloads run in parallel via errgroup. Each download is protected against
// SSRF by resolving the target hostname and rejecting restricted IP ranges
// before any connection is made, and again after every redirect hop.
package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/config"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/logging"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/validate"
)

const (
	maxFileSize     = 100 * 1024 * 1024 // 100 MB hard ceiling per geo file
	maxRedirects    = 5
	downloadTimeout = 5 * time.Minute
	headTimeout     = 30 * time.Second
	maxMetaSize     = 4 * 1024 // metadata cache files are small
)

// PrepareGeoFiles downloads all four geo files in parallel.
// It returns the first error encountered; partial downloads are cleaned up
// before returning so mihomo never starts with incomplete geodata.
func PrepareGeoFiles(cfg *config.Config, log *logging.Logger) error {
	urls := []struct {
		url string
		dst string
	}{
		{cfg.Geo.URLs.GeoIP, filepath.Join(cfg.Paths.MihomoData, "geoip.dat")},
		{cfg.Geo.URLs.GeoSite, filepath.Join(cfg.Paths.MihomoData, "geosite.dat")},
		{cfg.Geo.URLs.MMDB, filepath.Join(cfg.Paths.MihomoData, "geoip.metadb")},
		{cfg.Geo.URLs.ASN, filepath.Join(cfg.Paths.MihomoData, "GeoLite2-ASN.mmdb")},
	}

	client := newHTTPClient()

	g, _ := errgroup.WithContext(context.Background())
	for _, entry := range urls {
		entry := entry
		g.Go(func() error {
			return download(client, cfg, log, entry.url, entry.dst)
		})
	}
	return g.Wait()
}

// download fetches a single geo file to dst, skipping if the remote has not
// changed since the last successful download (ETag / Last-Modified comparison).
func download(client *http.Client, cfg *config.Config, log *logging.Logger, rawURL, dst string) error {
	if err := validateGeoURL(rawURL); err != nil {
		return fmt.Errorf("geo: invalid URL %q: %w", rawURL, err)
	}

	origURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("geo: parse original URL %q: %w", rawURL, err)
	}
	origHost := origURL.Hostname()

	log.Debugf("geo: checking %s -> %s", rawURL, dst)

	// HEAD request to retrieve cache-validation headers without downloading the body.
	meta, finalURL, err := fetchMeta(client, cfg, rawURL, origHost)
	if err != nil {
		return fmt.Errorf("geo: HEAD %q: %w", rawURL, err)
	}

	if !cfg.Geo.Redownload {
		unchanged, err := isCached(dst, rawURL, meta, cfg.Paths.MihomoData)
		if err == nil && unchanged {
			log.Debugf("geo: %s unchanged, skipping download", filepath.Base(dst))
			return nil
		}
	}

	log.Debugf("geo: downloading %s", filepath.Base(dst))
	if err := streamToFile(client, cfg, finalURL, origHost, dst); err != nil {
		return fmt.Errorf("geo: download %q: %w", rawURL, err)
	}

	if err := os.Chmod(dst, 0o600); err != nil {
		return fmt.Errorf("geo: chmod %q: %w", dst, err)
	}

	if err := writeCacheMeta(rawURL, meta, cfg.Paths.MihomoData); err != nil {
		// Cache write failure is non-fatal — next run will re-download.
		log.Warnf("geo: failed to write cache metadata for %s: %v", filepath.Base(dst), err)
	}

	log.Debugf("geo: %s saved", filepath.Base(dst))
	return nil
}

// fetchMeta performs a HEAD request, following redirects manually so every
// hop can be validated against the SSRF blocklist. Returns the response
// headers of the final response and the final URL.
func fetchMeta(client *http.Client, cfg *config.Config, rawURL, origHost string) (http.Header, string, error) {
	current := rawURL

	for i := 0; i < maxRedirects; i++ {
		if err := validateGeoURL(current); err != nil {
			return nil, "", fmt.Errorf("redirect target invalid: %w", err)
		}

		req, err := http.NewRequest(http.MethodHead, current, nil)
		if err != nil {
			return nil, "", err
		}
		applyAuth(req, cfg, origHost)

		ctx, cancel := context.WithTimeout(context.Background(), headTimeout)
		resp, err := client.Do(req.WithContext(ctx))
		cancel()
		if err != nil {
			return nil, "", err
		}
		defer func() { _ = resp.Body.Close() }() // HEAD response body is empty; close error is non-actionable

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp.Header, current, nil
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, "", fmt.Errorf("redirect %d with no Location header", resp.StatusCode)
			}
			resolved, err := resolveRedirect(current, loc)
			if err != nil {
				return nil, "", fmt.Errorf("resolve redirect location %q: %w", loc, err)
			}
			current = resolved
			continue
		}

		return nil, "", fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, current)
	}

	return nil, "", fmt.Errorf("exceeded %d redirects for %s", maxRedirects, rawURL)
}

// streamToFile downloads rawURL to dst via a secure temp file in the same
// directory, then atomically renames it. The body is capped at maxFileSize
// to prevent unbounded disk writes from a malicious or broken server.
func streamToFile(client *http.Client, cfg *config.Config, rawURL, origHost, dst string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	applyAuth(req, cfg, origHost)

	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	// Reject obvious error pages before writing anything to disk.
	ct := strings.ToLower(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0])
	ct = strings.TrimSpace(ct)
	if strings.HasPrefix(ct, "text/") {
		return fmt.Errorf("server returned text content-type %q — likely an error page", ct)
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".geo_download_*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		defer func() { _ = tmp.Close() }()
		defer func() { _ = os.Remove(tmpName) }()
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	limited := io.LimitReader(resp.Body, maxFileSize+1)
	n, err := io.Copy(tmp, limited)
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if n > maxFileSize {
		return fmt.Errorf("download exceeds %d byte limit", maxFileSize)
	}
	if n == 0 {
		return fmt.Errorf("downloaded file is empty")
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	return os.Rename(tmpName, dst)
}

// metaKey returns a deterministic cache filename derived from the URL so that
// each URL maps to exactly one metadata record regardless of path depth.
func metaKey(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:]) + ".meta"
}

// cacheDir returns (and creates) the metadata cache directory.
func cacheDir(mihomoData string) (string, error) {
	dir := filepath.Join(mihomoData, ".cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// isCached returns true when the local file exists and the cached metadata
// matches the headers returned by the server, indicating no update is needed.
func isCached(dst, rawURL string, remoteHeaders http.Header, mihomoData string) (bool, error) {
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		return false, nil
	}

	dir, err := cacheDir(mihomoData)
	if err != nil {
		return false, err
	}

	cacheFile := filepath.Join(dir, metaKey(rawURL))
	// #nosec G304 -- Path is deterministically constructed within the managed .cache directory.
	cached, err := os.ReadFile(cacheFile)
	if err != nil {
		return false, err
	}

	current := serializeMeta(remoteHeaders)
	return string(cached) == current, nil
}

// writeCacheMeta persists the ETag and Last-Modified headers from remoteHeaders
// so the next run can skip the download if the file has not changed.
func writeCacheMeta(rawURL string, remoteHeaders http.Header, mihomoData string) error {
	dir, err := cacheDir(mihomoData)
	if err != nil {
		return err
	}

	cacheFile := filepath.Join(dir, metaKey(rawURL))
	data := serializeMeta(remoteHeaders)

	tmp, err := os.CreateTemp(dir, ".meta_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		defer func() { _ = tmp.Close() }()
		defer func() { _ = os.Remove(tmpName) }()
	}()

	if _, err := tmp.WriteString(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, cacheFile)
}

// serializeMeta extracts cache-relevant headers into a deterministic string.
// Only ETag and Last-Modified are used — Content-Length alone is not a
// reliable change indicator (servers may serve the same size with new content).
func serializeMeta(h http.Header) string {
	etag := h.Get("Etag")
	lm := h.Get("Last-Modified")
	return fmt.Sprintf("etag=%s\nlast-modified=%s\n", etag, lm)
}

// validateGeoURL enforces HTTPS-only and calls the SSRF hostname validator.
func validateGeoURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if strings.ToLower(u.Scheme) != "https" {
		return fmt.Errorf("only HTTPS URLs are allowed, got scheme %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host: %q", rawURL)
	}

	// Reject dangerous percent-encodings before DNS resolution.
	lower := strings.ToLower(rawURL)
	for _, bad := range []string{"%00", "%0a", "%0d", "%2e%2e", "%25"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("URL contains dangerous percent-encoding %q", bad)
		}
	}

	return validate.ResolveAndValidate(host)
}

// resolveRedirect resolves a redirect Location value against the current URL,
// handling absolute, protocol-relative, and relative paths.
func resolveRedirect(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid Location header %q: %w", location, err)
	}
	resolved := base.ResolveReference(loc).String()

	// Downgrade is not allowed: HTTPS -> HTTP redirect is rejected to prevent
	// a server from stripping TLS and exposing credentials mid-redirect chain.
	if strings.HasPrefix(strings.ToLower(current), "https://") &&
		!strings.HasPrefix(strings.ToLower(resolved), "https://") {
		return "", fmt.Errorf("redirect would downgrade from HTTPS to HTTP: %q", resolved)
	}

	return resolved, nil
}

// applyAuth sets HTTP Basic Auth on req when GEO credentials are configured
// and the request destination matches the original hostname. This prevents
// credential leakage if the server redirects to a third-party domain.
func applyAuth(req *http.Request, cfg *config.Config, origHost string) {
	if cfg.Geo.AuthUser != "" && cfg.Geo.AuthPass != "" && req.URL.Hostname() == origHost {
		req.SetBasicAuth(cfg.Geo.AuthUser, cfg.Geo.AuthPass)
	}
}

// newHTTPClient returns an http.Client configured for geo downloads.
// Auto-redirect following is disabled so every hop is validated explicitly
// in fetchMeta before the next request is made.
//
// Control fires after DNS resolution but before connect(), guaranteeing that
// the IP checked here is the IP the kernel will actually connect to — closing
// the DNS rebinding window that exists between ResolveAndValidate and TCP connect.
// Both checks are kept as defence-in-depth: ResolveAndValidate catches bad URLs
// early and improves error messages; Control is the actual security boundary.
func newHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: -1, // keepalive disabled — matches DisableKeepAlives on transport
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("geo: malformed dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip != nil && validate.IsRestrictedIP(ip) {
				return fmt.Errorf("geo: connection to restricted IP %s blocked (DNS rebinding protection)", host)
			}
			return nil
		},
	}

	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			DisableKeepAlives: true,
			DialContext:       dialer.DialContext,
		},
	}
}
