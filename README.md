# mihomo warp proxy
Make Cloudflare WARP your SOCKS/HTTP(S) proxy server with mihomo (clash meta)

Based on [mihomo](https://github.com/MetaCubeX/mihomo) and [wgcf](https://github.com/ViRb3/wgcf).

## Short start-up instructions
1. Copy and edit [docker-compose.yaml](https://github.com/webstudiobond/mihomo-warp-proxy/blob/main/docker-compose.yaml) to suit your needs.
2. Create and configure the `.env` file (see example [env-example](https://github.com/webstudiobond/mihomo-warp-proxy/blob/main/env-example)).
3. Build the docker image:
```bash
docker compose -f docker-compose.yaml build
```
4. Launching a docker container:
```bash
docker compose -f docker-compose.yaml up -d
```
By default (`USE_WARP_CONFIG=true`), when the container starts, an wireguard warp account is registered and a wireguard warp profile is generated using `wgcf`. After that, the minimal `config.yaml` configuration file for mihomo is generated and the mihomo SOCKS/HTTP(S) proxy server is started. You can disable the autogeneration functionality (`USE_WARP_CONFIG=false`), create your own `config.yaml` with more fine-grained settings and run the container with them (see the [example](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml) from the `mihomo` kernel author).
