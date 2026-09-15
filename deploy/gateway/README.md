# Optional Docker gateway on Orange Pi

Core and `syslens-diagnosis` stay native on every monitored host. Only the
gateway runs here; it connects outbound to the native mTLS evidence APIs and,
when explicitly enabled, to [Ollama on Acemagic](../ollama/README.md).
The Debian gateway package and systemd service remain an independent option.
Do not run both daemons against the same state or socket.

Requires Docker Engine and Compose v2 on Linux. The image supports native arm64
and amd64 builds. No images are published automatically by the Debian release
workflow. The Compose file uses JSON syntax (a YAML subset), allowing offline
validation with Python's standard library.

## Prepare the dedicated host directory

Run as `orangepi`. Set `SYSLENS_SOURCE` to an existing clean checkout of the
desired commit, outside the deployment directory:

```sh
SYSLENS_SOURCE=/home/orangepi/syslens-core
umask 077
install -d -m 0700 /home/orangepi/syslens-gateway
cd /home/orangepi/syslens-gateway
install -d -m 0700 config config/certs state run backups
install -m 0600 "$SYSLENS_SOURCE/deploy/gateway/compose.yaml" compose.yaml
install -m 0600 "$SYSLENS_SOURCE/deploy/gateway/.env.example" .env
install -m 0600 "$SYSLENS_SOURCE/deploy/gateway/config.toml.example" config/config.toml
id -u
id -g
```

Set `GATEWAY_UID`/`GATEWAY_GID` in `.env` to those numeric IDs (never root).
They must own `config/`, `config/certs/`, `state/`, and `run/`. This assumes
normal Docker UID mapping; rootless Docker or user-namespace remapping needs
matching mapped ownership. The daemon rejects mismatches and group/world access.
Install each real CA, client certificate, and key into `config/certs/` using
`install -m 0600 SOURCE DESTINATION`. Keep credentials outside the checkout.

Edit `config/config.toml`: add mTLS hosts, pin their identities, then set the
top-level `enabled = true`. AI stays disabled until its endpoint is configured
and `[ai].enabled` is explicitly enabled. Do not call the systemd-oriented
`init`, `enable`, or `disable` commands inside Docker. Stop/start with Compose.
For LAN Ollama, follow its firewall setup first, then configure the commented
endpoint/model and replace `allow_insecure_http = false` with `true`.

| Host path (relative to this directory) | Container path | Access |
| --- | --- | --- |
| `config/` including `certs/` | `/etc/syslens-gateway` | read-only, directories 0700 / files 0600 |
| `state/` | `/var/lib/syslens-gateway` | writable, directory 0700 / SQLite files 0600 |
| `run/` | `/run` | writable, directory 0700 / socket and lock 0600 |

The socket is `/run/syslens-gateway.sock` inside the container and
`/home/orangepi/syslens-gateway/run/syslens-gateway.sock` on the host. The whole
dedicated `run/` directory is mounted because socket creation and replacement
need a writable, owner-only parent. No TCP port is published. The container
uses a read-only root filesystem, non-root UID, no extra capabilities, no new
privileges, a 16 MiB temporary directory, 1 CPU and 512 MiB memory limits.
It has no Docker socket, host PID namespace, or host network namespace.

## Build or pull, then start

Build on Orange Pi (arm64) or an amd64 host for that host's architecture:

```sh
docker build --pull \
  --file "$SYSLENS_SOURCE/deploy/gateway/Dockerfile" \
  --tag "syslens-gateway:$(git -C "$SYSLENS_SOURCE" rev-parse HEAD)" \
  "$SYSLENS_SOURCE"
```

Set `SYSLENS_GATEWAY_IMAGE` in `.env` to that exact commit tag. Never reuse a
commit tag for different source. For a private registry, build/push a manifest
for both architectures with an installed Buildx builder and emulation or
native builders (replace `REGISTRY/OWNER`):

```sh
docker buildx build --platform linux/arm64,linux/amd64 \
  --file "$SYSLENS_SOURCE/deploy/gateway/Dockerfile" \
  --tag "REGISTRY/OWNER/syslens-gateway:$(git -C "$SYSLENS_SOURCE" rev-parse HEAD)" \
  --push "$SYSLENS_SOURCE"
```

Alternatively set `.env` to an existing trusted registry image tagged with its
source commit, preferably pinned as `REGISTRY/OWNER/syslens-gateway@sha256:...`,
then pull it:

```sh
docker compose pull gateway
```

Start either the locally built or pulled image:

```sh
docker compose config --quiet
docker compose up -d --no-build --wait gateway
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml health
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml hosts list
docker compose images
docker compose logs --tail=50 gateway
```

The healthcheck contacts the local Unix socket, so it works with AI disabled
and without reachable evidence hosts. It checks daemon availability, not model
quality or host evidence coverage. `unless-stopped` restarts a failed process;
Docker does not automatically restart a process merely marked unhealthy.

Run chat or deterministic diagnosis through `docker compose exec` with the same
config argument. An installed native gateway client owned by the same host UID
can also use `--socket /home/orangepi/syslens-gateway/run/syslens-gateway.sock`.
For `syslens chat` forwarding, install the native gateway client and set its
owner-only default config's `socket` to that host path; do not enable its native
daemon. Runtime model selection is stored centrally in gateway state:

```sh
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml models list
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml models set qwen3:4b
```

## Backup, update, rollback

Keep the previous image available and record its image ID/digest with the
backup. Stop the gateway for a consistent SQLite database/WAL/SHM snapshot:

```sh
cd /home/orangepi/syslens-gateway
umask 077
docker compose images
docker compose stop gateway
tar -czf "backups/gateway-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" \
  compose.yaml .env config state
docker compose start gateway
```

Backups contain private keys and conversation/evidence data; keep them 0600,
copy to protected storage, and never commit them. Do not back up live sockets.
For updates, build a new clean source commit (or change `.env` to its registry
image and run `docker compose pull gateway`), after saving the old `.env` and
state as above. Then run:

```sh
docker compose up -d --no-build --wait gateway
docker compose exec -T gateway syslens-gateway --config /etc/syslens-gateway/config.toml health
```

For rollback, set `.env` back to the saved image tag/digest and repeat the last
commands. If the old binary cannot read the new state, stop the gateway, move
the current `state/` and `config/` to a protected recovery directory, restore
`state/`, `config/`, `.env`, and `compose.yaml` from the matching stopped backup
with `tar -xzf backups/CHOSEN_BACKUP.tar.gz`, then run
`docker compose up -d --no-build --wait gateway`. Restoring state loses events
and chats since that snapshot; retain the moved state for recovery. Do not
prune the previous image until the update is accepted.
