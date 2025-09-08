FROM alpine:latest AS builder

RUN apk add --no-cache \
        ca-certificates \
        jq \
        gzip

WORKDIR /tmp

# wgcf
RUN set -eux; \
    WGCF_VER=$(wget -q -O - --timeout=30 https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r .tag_name | sed 's/^v//'); \
    [ -n "$WGCF_VER" ]; \
    wget -O wgcf --timeout=60 "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VER}/wgcf_${WGCF_VER}_linux_amd64"; \
    chmod +x wgcf

# mihomo (clash-meta)
RUN set -eux; \
    MIHOMO_VER=$(wget -q -O - --timeout=30 https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | jq -r .tag_name | sed 's/^v//'); \
    [ -n "$MIHOMO_VER" ]; \
    wget -O mihomo.gz --timeout=60 "https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VER}/mihomo-linux-amd64-v${MIHOMO_VER}.gz"; \
    gunzip mihomo.gz; \
    chmod +x mihomo

RUN ./wgcf --help >/dev/null 2>&1 && ./mihomo --help >/dev/null 2>&1

FROM alpine:latest

LABEL maintainer="webstudiobond" \
      description="Make Cloudflare WARP your SOCKS/HTTP(S) proxy server with mihomo (clash meta)"

RUN apk add --no-cache \
            su-exec \
            curl \
            yq \
            tini \
            tzdata \
            && rm -rf /var/cache/apk/*

RUN addgroup -g 911 -S mihomo && \
    adduser -u 911 -D -S -G mihomo mihomo

ENV PROXY_UID=911 \
    PROXY_GID=911 \
    MULTI_USER_MODE=true \
    MIHOMO_DATA=/app/mihomo \
    MIHOMO_CONFIG_FILE=/app/mihomo/config.yaml

# copy binaries
COPY --from=builder /tmp/wgcf /usr/local/bin/
COPY --from=builder /tmp/mihomo /usr/local/bin/

COPY modules/  /usr/local/bin/modules/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY version /app/version

RUN set -eux; \
    ver="$(cat /app/version)"; \
    printf 'SCRIPT_VERSION=%s\n' "$ver" > /app/script_version.sh; \
    chmod 0644 /app/script_version.sh

# create app dirs; set default ownership to 911:911 (image-level) so non-root runs with --user=911:911 work without extra chown
RUN mkdir -p /app/mihomo /app/wgcf /app/logs && \
    chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/wgcf.sh && \
    chmod 0755 /usr/local/bin/mihomo /usr/local/bin/wgcf && \
    chmod 644 /usr/local/bin/modules/*.sh && \
    chown -R 911:911 /app && \
    chmod 0750 /app/mihomo /app/wgcf

WORKDIR /app

# declare default proxy port
EXPOSE 7890

ENTRYPOINT ["/sbin/tini","--","/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/mihomo","-d","/app/mihomo"]
