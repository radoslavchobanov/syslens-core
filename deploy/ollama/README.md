# Dedicated Ollama on Acemagic

This optional project lives at `/home/acemagic/ollama/`. Native Core and
diagnosis continue independently. Use the official `ollama/ollama` image,
CPU execution, one loaded model, one parallel inference request, a queue of
four, and a 4096-token default context. The configurable resource defaults are
4 CPUs and 8 GiB RAM; confirm the host has enough capacity alongside native
services before starting. No GPU devices, privileged mode, or Docker socket
are configured. Models persist in `./data`; no image build downloads a model.

## Prepare and restrict access

As `acemagic`, set `SYSLENS_SOURCE` to your checkout:

```sh
SYSLENS_SOURCE=/home/acemagic/syslens-core
umask 077
install -d -m 0700 /home/acemagic/ollama
cd /home/acemagic/ollama
install -d -m 0700 backups
sudo install -d -o 0 -g 0 -m 0700 data
install -m 0600 "$SYSLENS_SOURCE/deploy/ollama/compose.yaml" compose.yaml
install -m 0600 "$SYSLENS_SOURCE/deploy/ollama/.env.example" .env
install -m 0700 "$SYSLENS_SOURCE/deploy/ollama/preflight.sh" preflight.sh
install -m 0700 "$SYSLENS_SOURCE/deploy/ollama/start.sh" start.sh
```

The official image runs as root with all capabilities dropped, so its `data/`
mount must be owned by numeric UID/GID `0:0`, with mode 0700. A directory owned
by `acemagic` at 0700 would reject the container's writes. These instructions
assume normal Docker UID mapping; rootless Docker/user-namespace remapping
needs the corresponding mapped owner instead.

Set `OLLAMA_IMAGE` to an explicit verified official version tag (or preferably
`ollama/ollama@sha256:...`). The placeholder deliberately cannot start a floating
`latest` image. Set `OLLAMA_LAN_IP` to Acemagic's private IPv4 LAN address,
currently illustrated as `192.168.0.144`. Never use `0.0.0.0`, `::`, a public
address, a public reverse proxy, router port forwarding, or a public tunnel.
`OLLAMA_HOST=0.0.0.0:11434` is only the listener *inside the container*; the
published host port binds only `OLLAMA_LAN_IP:11434`.

`./start.sh` is the required and only supported startup command. It runs
`./preflight.sh` before Docker and accepts only a literal RFC1918 IPv4 address:
`10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`. It rejects an unset,
wildcard, loopback, public, malformed, or IPv6 value. The Compose file has no
wildcard default, but `docker compose up` bypasses this validation and **must
not be used directly**. `start.sh` validates an externally supplied
`OLLAMA_LAN_IP` when one is set; otherwise it safely reads only the single
`OLLAMA_LAN_IP=...` entry from this deployment directory's `.env` before it
calls Docker. Do not source `.env` in a shell.

Before starting, configure a persistent host firewall policy that allows TCP
11434 from Orange Pi's LAN address (`192.168.0.108` in this example) and drops
other remote sources. Apply this to Docker's forwarded traffic path, not just
the host INPUT chain: Docker port publishing can bypass ordinary UFW rules.
For Docker's iptables backend, use the `DOCKER-USER` chain and match the original
destination `192.168.0.144:11434` with conntrack; for a native nftables backend,
use the appropriate forward hook before Docker's accept rules. Preserve
established connections and other services. Verify access from Orange Pi and
verify rejection from another LAN host before enabling gateway AI. Binding a
LAN address alone does not restrict which LAN clients can call the raw API.

The API has no application authentication or TLS in this pilot. Enable the
gateway's explicit trusted-LAN HTTP opt-in only after this restriction is in
place. Gateway-to-diagnosis traffic continues to use mTLS.

## Start and pull the pilot model explicitly

```sh
docker compose config --quiet
docker compose pull ollama
./start.sh
docker compose logs --tail=50 ollama
docker compose exec ollama ollama pull qwen3:4b
docker compose exec -T ollama ollama list
docker compose exec -T ollama ollama show qwen3:4b
curl --fail --silent --show-error http://192.168.0.144:11434/api/tags
```

Run the last request from Orange Pi to verify the actual permitted network
path. Record `qwen3:4b`'s full `digest` from `/api/tags` alongside the image
digest from `docker image inspect IMAGE --format '{{json .RepoDigests}}'`.
`ollama list` displays a shortened model ID; the tag may change on a later
pull. To preserve an accepted pilot, create a local versioned name using
`docker compose exec ollama ollama cp qwen3:4b qwen3-pilot:ACCEPTED_DIGEST_PREFIX`
and record its full digest. Keep the data backup for model rollback; an image
rollback alone does not restore a model overwritten by a pull.

The healthcheck uses `ollama list` and succeeds even before any models are
downloaded. Confirm logs report cloud disabled (`OLLAMA_NO_CLOUD=1`). This
disables cloud features, but does not block network access used by explicit
image/model downloads. After a real inference, `docker compose exec -T ollama
ollama ps` should show CPU execution. A healthy API is not a successful pilot
inference; test a bounded gateway question before accepting the deployment.

## Configure and switch models centrally

In the [Orange Pi gateway config](../gateway/config.toml.example), explicitly
enable AI, set `endpoint_url` to
`http://192.168.0.144:11434/v1/chat/completions`, set `model = "qwen3:4b"`, and
set `allow_insecure_http = true`. Restart the gateway to load config changes.
To switch models later, pull the chosen model on Acemagic, then run on Orange Pi:

```sh
cd /home/orangepi/syslens-gateway
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml models list
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml models set qwen3:4b
```

Replace the final model argument with the accepted versioned name if used.
The override persists in gateway state and takes precedence over the config
default. No Core or diagnosis configuration changes are needed.

## Backup, update, rollback

The official image owns files under `data/` as root. Back up with sufficient
read permission, without changing model-store ownership:

```sh
cd /home/acemagic/ollama
umask 077
docker compose images
docker compose stop ollama
sudo tar -czf - compose.yaml .env data > "backups/ollama-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
./start.sh
```

Preserve the prior image tag/digest and full model digest. Edit `.env` to a new
verified official image, then `docker compose pull ollama` and `./start.sh`.
Check logs, `/api/tags`, and a gateway
inference. Model updates require a separate explicit `ollama pull`; restarting
the service never downloads a model automatically.

For image rollback, restore the previous `OLLAMA_IMAGE` and run `./start.sh`.
For model-store rollback, stop Ollama,
move the current `data/` to a protected recovery location, restore the matching
backup using `sudo tar -xzf backups/CHOSEN_BACKUP.tar.gz`, and start with
`./start.sh`. Retain old images and backups until the
pilot is accepted. Protect backups: the store can also contain server keys.

References: [official CPU Docker setup](https://docs.ollama.com/docker),
[Ollama limits and local-only settings](https://docs.ollama.com/faq),
[Docker firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/).
Compose files use JSON syntax, a YAML subset, for offline standard-library
parsing in CI; validate Docker's resolved config again on the deployment host.
