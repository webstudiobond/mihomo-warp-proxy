# syntax=docker/dockerfile:1

# ── Stage 1: compile the Go entrypoint binary ─────────────────────────────────
# TARGETOS/TARGETARCH are injected by buildx for each platform in the matrix.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine3.23 AS go-builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version is injected from the build arg so the compiled binary carries it
# without requiring a separate version file in the image.
ARG MIHOMO_VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${MIHOMO_VERSION}" \
    -trimpath \
    -o /entrypoint \
    ./cmd/entrypoint/

# ── Stage 2: download wgcf and mihomo for the target platform ─────────────────
FROM alpine:3.23 AS bin-builder

# ash supports -e and -o pipefail via the SHELL directive; required for
# correct pipe exit-code propagation in the download verification steps.
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates wget jq

# TARGETARCH is injected by buildx — no default to avoid masking the actual
# target platform when building for arm64.
ARG TARGETARCH
# CPU microarchitecture level — only meaningful for amd64.
# v1 = baseline x86-64, v2 = SSE4.2, v3 = AVX2.
# For arm64 this arg is ignored; the binary name has no variant suffix.
ARG MIHOMO_CPU_VARIANT=v1

# wgcf: binary name matches TARGETARCH directly (amd64, arm64).
# Digest is fetched from the GitHub releases API, same as mihomo —
# both publishers embed per-asset digests in the API response.
# hadolint ignore=DL4006
RUN WGCF_VERSION=$(wget -q -O - \
        "https://api.github.com/repos/ViRb3/wgcf/releases/latest" \
        | jq -r '.tag_name // empty' | sed 's/^v//') && \
    [ -n "${WGCF_VERSION}" ] || { echo "ERROR: could not resolve latest wgcf version"; exit 1; } && \
    echo "Resolved wgcf version: ${WGCF_VERSION}" && \
    WGCF_FILE="wgcf_${WGCF_VERSION}_linux_${TARGETARCH}" && \
    wget -q -O /tmp/wgcf \
        "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/${WGCF_FILE}" && \
    WGCF_SHA256=$(wget -q -O - \
        "https://api.github.com/repos/ViRb3/wgcf/releases/tags/v${WGCF_VERSION}" \
        | jq -r --arg f "${WGCF_FILE}" '.assets[] | select(.name == $f) | .digest' \
        | sed 's/^sha256://') && \
    [ -n "${WGCF_SHA256}" ] || { echo "ERROR: could not fetch digest for ${WGCF_FILE}"; exit 1; } && \
    echo "${WGCF_SHA256}  /tmp/wgcf" | sha256sum -c - && \
    chmod +x /tmp/wgcf

# mihomo binary naming differs by arch:
#   amd64: mihomo-linux-amd64-<variant>-v<VER>.gz  (variant = v1/v2/v3)
#   arm64: mihomo-linux-arm64-v<VER>.gz             (no variant suffix)
# hadolint ignore=DL4006
RUN MIHOMO_VERSION=$(wget -q -O - \
        "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" \
        | jq -r '.tag_name // empty' | sed 's/^v//') && \
    [ -n "${MIHOMO_VERSION}" ] || { echo "ERROR: could not resolve latest mihomo version"; exit 1; } && \
    echo "Resolved mihomo version: ${MIHOMO_VERSION}" && \
    if [ "${TARGETARCH}" = "amd64" ]; then \
        MIHOMO_FILE="mihomo-linux-amd64-${MIHOMO_CPU_VARIANT}-v${MIHOMO_VERSION}.gz"; \
    else \
        MIHOMO_FILE="mihomo-linux-${TARGETARCH}-v${MIHOMO_VERSION}.gz"; \
    fi && \
    wget -q -O /tmp/mihomo.gz \
        "https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/${MIHOMO_FILE}" && \
    MIHOMO_SHA256=$(wget -q -O - \
        "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v${MIHOMO_VERSION}" \
        | jq -r --arg f "${MIHOMO_FILE}" '.assets[] | select(.name == $f) | .digest' \
        | sed 's/^sha256://') && \
    [ -n "${MIHOMO_SHA256}" ] || { echo "ERROR: could not fetch digest for ${MIHOMO_FILE}"; exit 1; } && \
    echo "${MIHOMO_SHA256}  /tmp/mihomo.gz" | sha256sum -c - && \
    gunzip /tmp/mihomo.gz && \
    chmod +x /tmp/mihomo

# ── Stage 3: final image ───────────────────────────────────────────────────────
FROM alpine:3.23

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

LABEL org.opencontainers.image.source="https://github.com/webstudiobond/mihomo-warp-proxy" \
      org.opencontainers.image.description="Cloudflare WARP SOCKS5/HTTP(S) proxy via mihomo (Clash Meta)" \
      maintainer="webstudiobond"

# hadolint ignore=DL3018
RUN apk add --no-cache \
        su-exec \
        tini \
        curl \
        tzdata \
    && addgroup -g 911 -S mihomo \
    && adduser  -u 911 -D -S -G mihomo mihomo

COPY --from=go-builder  /entrypoint  /usr/local/bin/entrypoint
COPY --from=bin-builder /tmp/wgcf    /usr/local/bin/wgcf
COPY --from=bin-builder /tmp/mihomo  /usr/local/bin/mihomo

RUN chmod 0755 /usr/local/bin/entrypoint \
               /usr/local/bin/mihomo \
               /usr/local/bin/wgcf \
    && mkdir -p /app/mihomo /app/wgcf /app/logs \
    && chown -R 911:911 /app \
    && chmod 0750 /app/mihomo /app/wgcf

ENV PROXY_UID=911 \
    PROXY_GID=911 \
    MULTI_USER_MODE=true \
    PROXY_PORT=7890 \
    PROXY_LOG_LEVEL=error \
    SCRIPT_LOG_LEVEL=ERROR

WORKDIR /app
EXPOSE 7890

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint"]
