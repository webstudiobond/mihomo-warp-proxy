# mihomo-warp-proxy

A Docker container that exposes a Cloudflare WARP connection as an authenticated SOCKS5/HTTP(S) proxy, powered by [mihomo (Clash Meta)](https://github.com/MetaCubeX/mihomo) and [wgcf](https://github.com/ViRb3/wgcf).

[![CI](https://github.com/webstudiobond/mihomo-warp-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/webstudiobond/mihomo-warp-proxy/actions/workflows/ci.yml)
[![GitHub last commit](https://img.shields.io/github/last-commit/webstudiobond/mihomo-warp-proxy)](https://github.com/webstudiobond/mihomo-warp-proxy/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/webstudiobond/mihomo-warp-proxy)](https://github.com/webstudiobond/mihomo-warp-proxy/issues)
[![GitHub repo size](https://img.shields.io/github/repo-size/webstudiobond/mihomo-warp-proxy)](https://github.com/webstudiobond/mihomo-warp-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

On startup the container automatically registers a Cloudflare WARP account, generates a WireGuard profile, and produces a minimal working mihomo configuration. Advanced users can extend the configuration with custom listeners, additional proxies, proxy groups, and routing rules — everything outside the set of managed fields is preserved across restarts.

## How it works

1. **wgcf** registers a free Cloudflare WARP account and generates a WireGuard profile (`wgcf-account.toml`, `wgcf-profile.conf`).
2. The entrypoint fetches the WARP `reserved` bytes from the Cloudflare API and writes a minimal `config.yaml` for mihomo with a WireGuard proxy pointing at WARP.
3. **mihomo** starts and serves a mixed SOCKS5/HTTP(S) proxy on the configured port, routing all traffic through WARP.

On subsequent restarts the existing account and profile are reused — no new registration occurs, provided the `./wgcf-data` volume is mounted. Without a mounted volume every container start registers a fresh WARP account.

> If you have a WARP+ license key, set `WARP_PLUS_KEY` in `.env`. Full WARP+ functionality
> has not been verified — use at your own risk.

## Requirements

- Docker 24+ with Compose v2
- Outbound UDP access on port 500 (or 2408 / 4500 / 1701 — configurable)

## Quick start — using the pre-built image

### 1. Download the configuration files

```bash
curl -fsSL https://raw.githubusercontent.com/webstudiobond/mihomo-warp-proxy/main/docker-compose.yaml \
  -o docker-compose.yaml
curl -fsSL https://raw.githubusercontent.com/webstudiobond/mihomo-warp-proxy/main/env-example \
  -o .env
```

### 2. Configure credentials

Edit `.env` and set your proxy credentials:

```bash
PROXY_USER=your_unique_username
PROXY_PASS=your_unique_password
```

Generate strong values with:
```bash
pwgen -s 64 1   # username
pwgen -s 128 1  # password
```

Password requirements:
- Username: 8–64 characters; no `:`, spaces, control characters, or shell metacharacters (`$`, `` ` ``, `"`, `'`, `\`, `!`, `&`, `;`, `|`, `<`, `>`)
- Password: 32–128 characters; at least one uppercase letter (A–Z), one lowercase letter (a–z), one digit (0–9); no run of 4+ identical consecutive characters; at least 12 distinct characters; no spaces or shell metacharacters

Both credentials are **required** — an open unauthenticated proxy is a security risk.

### 3. (Optional) Select the CPU variant for your amd64 host

The default image tag contains a baseline `v1` binary that runs on any x86-64 machine. If your host supports SSE4.2 or AVX2, you can select a more optimised build:

```bash
# Detect your level
grep -q avx2 /proc/cpuinfo && echo v3 || { grep -q sse4_2 /proc/cpuinfo && echo v2 || echo v1; }
```

Set the result in `.env`:
```bash
MIHOMO_CPU_VARIANT=v3   # or v2, or leave empty for v1
```

On ARM64 hosts (including Docker Desktop on Apple Silicon) leave `MIHOMO_CPU_VARIANT` empty — the registry automatically serves the correct image.

### 4. Start

```bash
docker compose up -d
```

The proxy will be available on `localhost:7890` (SOCKS5 and HTTP).

### 5. Expose ports (optional)

The `ports` section in `docker-compose.yaml` is pre-configured for the default proxy port.
If you add custom listeners in `config.yaml` (see [Custom mihomo configuration](#custom-mihomo-configuration)), add their ports to this section as well.

## Build from GitHub source

If you need a fresh build before the automated pipeline publishes a new image, uncomment the `build` section in `docker-compose.yaml`:

```yaml
build:
  context: https://github.com//webstudiobond/mihomo-warp-proxy.git
  args:
    MIHOMO_CPU_VARIANT: ${MIHOMO_CPU_VARIANT:-v1}
```

The latest versions of mihomo and wgcf are resolved automatically from GitHub at build time — no version pinning required.
Then run:

```bash
docker compose build --no-cache
```

## Local development — cloning the repository

```bash
git clone https://github.com//webstudiobond/mihomo-warp-proxy.git
cd mihomo-warp-proxy
cp env-example .env
# Edit .env and set PROXY_USER, PROXY_PASS
docker compose -f docker-compose.dev.yaml build --no-cache
```

## Image tags

| Tag | Platforms | Use case |
|---|---|---|
| `latest`, `1.19.21` | linux/amd64 (v1) + linux/arm64 | Default — works on any hardware |
| `latest-amd64v2`, `1.19.21-amd64v2` | linux/amd64 (SSE4.2) | Opt-in for SSE4.2 hosts |
| `latest-amd64v3`, `1.19.21-amd64v3` | linux/amd64 (AVX2) | Opt-in for AVX2 hosts |

Pin a specific version in `.env` with `MWP_VERSION=1.19.21`. Leave it as `latest` to always pull the newest release.

The image is rebuilt automatically when mihomo, wgcf, Alpine, or the Go base image receives an update.

## Configuration

### Environment variables

See [`env-example`](env-example) for the full list of variables with descriptions.

### Custom mihomo configuration

The entrypoint manages a specific set of fields in `config.yaml` and leaves everything else untouched. You can freely add:

- Additional `proxies` entries (VLESS, Trojan, Shadowsocks, etc.)
- `listeners` (additional ports, protocols)
- `proxy-groups` for traffic routing
- `rules` — any rules you add above the terminal `MATCH` entry are preserved

#### Config lifecycle

1. **First start, `USE_WARP_CONFIG=true`** — a minimal `config.yaml` is created with a `warp` proxy entry and a single `MATCH,warp` catch-all rule.
2. **First start, `USE_WARP_CONFIG=false`** — a minimal `config.yaml` is created with no
   proxies and a single `MATCH,DIRECT` catch-all rule.
3. **Switching from `false` → `true`** — three sub-cases:
   - If a `warp` proxy entry already exists — it is updated in place. Rules untouched.
   - If there is no `warp` entry but other proxies exist — `warp` is appended to the list. Rules untouched — the user is responsible for adding a rule that references `warp`.
   - If `proxies` is empty and the only rule is `MATCH,DIRECT` (the exact minimal template from case 2) — `warp` is added and `MATCH,DIRECT` is replaced with `MATCH,warp` automatically.
4. **Switching from `true` → `false`** — the entrypoint does nothing to `config.yaml`.  The `warp` proxy entry and all rules remain exactly as they are. Changes to WARP-related variables (`WARP_ENDPOINT`, `WARP_DNS`, `WARP_AMNEZIA`, `WARP_REGENERATE`, etc.) are completely ignored. The wgcf data directory is not touched or checked.
5. **Switching back to `true`** — all WARP variables are applied again: the `warp` proxy entry is updated, re-registration or profile regeneration occurs if `WARP_REGENERATE=true`, and Amnezia/DNS/endpoint settings take effect immediately.

Once you edit `config.yaml`, the entrypoint never touches `rules[]`, `proxy-groups`, `listeners`, or any other section outside the managed fields listed above.

For the full mihomo configuration reference see the [official documentation](https://github.com/MetaCubeX/mihomo/blob/Meta/docs/config.yaml).

### Persistent data

| Host path | Container path | Contents |
|---|---|---|
| `./mihomo-data` | `/app/mihomo` | `config.yaml`, geodata files, cache |
| `./wgcf-data` | `/app/wgcf` | `wgcf-account.toml`, `wgcf-profile.conf` |

Both directories are created automatically on first run. Back them up if you want to preserve your WARP registration.

### WARP+ key

If you have a WARP+ license key, set it in `.env`:

```bash
WARP_PLUS_KEY=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx
```

The key must follow the format: four groups of 8 hexadecimal characters separated by hyphens.

The account will be upgraded on the next restart.

### AmneziaWG

AmneziaWG adds WireGuard obfuscation to disguise the protocol from DPI systems. Enable it in `.env`:

```bash
WARP_AMNEZIA=true
```

Pre-filled values for `WARP_AMNEZIA_JC`, `WARP_AMNEZIA_JMIN`, `WARP_AMNEZIA_JMAX`, `WARP_AMNEZIA_I1`, and `WARP_AMNEZIA_I2` in `env-example` are ready to use. See the [AmneziaWG documentation](https://docs.amnezia.org/documentation/amnezia-wg/) for details.

### Forcing WARP re-registration

To discard the existing WARP account and generate a fresh one:

```bash
WARP_REGENERATE=true docker compose up -d
```

Reset the variable to `false` after the first successful start.

## Running as a non-root user

By default the container starts as root and drops to `PROXY_UID:PROXY_GID` (911:911).
`PROXY_UID` and `PROXY_GID` must be in range 1–65535 — UID/GID 0 (root) is not permitted.

Two alternative modes are available:

**Fixed non-root user:**
```bash
# In docker-compose.yaml
user: "911:911"
```
The mounted volumes must be pre-owned by 911:911.

**Arbitrary UID (multi-user mode):**
```bash
MULTI_USER_MODE=true  # default
```
```bash
user: "1000:1000"
```
The mounted volumes must be owned by the UID you pass. Ownership is the operator's responsibility in this mode.

## Healthcheck

The built-in healthcheck connects through the proxy to `https://cp.cloudflare.com/generate_204`.
A `healthy` status confirms end-to-end proxy connectivity through WARP.

## Security

All environment variables are validated at startup before any action is taken.
The container refuses to start if any value fails validation, reporting the exact requirement. Key constraints:

- Proxy credentials are mandatory — anonymous access is not permitted
- `PROXY_UID`/`PROXY_GID` must be ≥ 1 (root is rejected)
- `WARP_ENDPOINT` is restricted to `engage.cloudflareclient.com` with allowed ports only (500, 2408, 1701, 4500)
- All GEO download URLs must use HTTPS
- `WARP_PLUS_KEY` must match `xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx` format if set
- `TZ` must be a valid IANA timezone (e.g. `Europe/London`, `America/New_York`)

## Security considerations for local builds

When building locally via `docker-compose.dev.yaml`, the latest versions of mihomo and wgcf are resolved automatically from the GitHub Releases API at build time. The Dockerfile verifies each binary's SHA256 digest against the value published in the same API response.

**Known limitation:** this verification protects against accidental transmission errors only. It does not provide cryptographic proof of authenticity — neither mihomo nor wgcf publish PGP or Cosign signatures, so it is impossible to verify that a release was produced by a trusted build pipeline and has not been tampered with after publication.

If you require a higher assurance level for local builds, you can pin specific versions by setting `MIHOMO_CPU_VARIANT` and editing the auto-resolve steps in `Dockerfile` to use fixed version strings and pre-verified digests:

```dockerfile
# Example: pin wgcf to a known-good version with a verified digest
ARG WGCF_VERSION=2.2.30
ARG WGCF_SHA256=<digest you verified independently>
```

The automated CI/CD pipeline (`build.yml`) always pins both versions explicitly and records them as image labels — providing a reproducible audit trail for production images pulled from the registry.

## License

MIT
