# SysLens Core

`syslens` is a low-overhead Linux system monitor and telemetry collector. Run
`syslens` in a terminal for its interactive local monitor, or use its stable
JSON snapshot and optional MQTT publisher to feed other SysLens interfaces. It
has no database, web server, or broker of its own.

## SysLens components

SysLens is intentionally split by responsibility. The collector remains useful
on its own; each interface consumes its stable snapshot contract rather than
embedding a second collector.

| Component | Purpose | Connection to Core |
| --- | --- | --- |
| [syslens-core](https://github.com/radoslavchobanov/syslens-core) | Linux telemetry collector and MQTT publisher | Source of truth |
| [syslens-plasmoid](https://github.com/radoslavchobanov/syslens-plasmoid) | KDE Plasma widget | Direct local command or SSH command |
| [syslens-home-assistant](https://github.com/radoslavchobanov/syslens-home-assistant) | Home Assistant dashboard integration | Retained MQTT state only |

The Plasma interface is deliberately separate. It can monitor a local host or
a remote host over SSH without MQTT. The Home Assistant interface is also
separate and intentionally does **not** execute Core commands: it consumes the
retained MQTT contract described below.

## First-time setup

Install Core, then run the first-run wizard:

```bash
scripts/install-core.sh
syslens setup
```

The wizard starts with a clear choice:

1. **Local TUI / CLI / KDE Plasma** — no broker, configuration file, or
   background service. It optionally enables the read-only hardware-inventory
   helper.
2. **MQTT publisher** — configures the broker, host ID, credentials, publish
   interval, optional hardware inventory, and can install and start the
   per-user publishing service.

The local monitor is the default human-facing interface:

```bash
syslens
```

It is designed for a normal terminal (minimum 62 × 22 cells) and provides:

- an overview of CPU, RAM and swap, disk, GPU, network activity, and a compact
  top-process preview;
- a sortable process table (`c` CPU, `m` memory, `j`/`k` selection); and
- a dedicated thermal and hardware-inventory view.

Use `Tab` or `1`–`3` to switch views, `r` to refresh immediately, and `q` to
quit. The refresh interval defaults to two seconds and can be changed with:

```bash
syslens tui --interval 3
```

For scripts, pipes, the Plasma widget, and any program consuming Core, the
machine-facing JSON contract remains explicit and unchanged:

```bash
syslens snapshot --pretty
# Compatibility spelling for a one-shot JSON snapshot:
syslens --json
```

When `syslens` has no subcommand but stdout is not an interactive terminal, it
also keeps the previous JSON snapshot behaviour. Existing automation therefore
does not unexpectedly receive terminal control codes.

The separate [`syslens-plasmoid`](../syslens-plasmoid) package uses
`syslens snapshot --json` locally, or over SSH on a remote host.

The old `syslens-core` spelling remains as a compatibility alias.

## Debian / Ubuntu installation

Tagged releases publish architecture-specific `syslens-core` Debian packages
for `amd64` and `arm64`. Final releases are also added to the signed SysLens
APT repository once it is enabled. To use it, install the published archive
key and source once:

```bash
curl -fsSL https://radoslavchobanov.github.io/syslens-core/apt/syslens-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/syslens-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/syslens-archive-keyring.gpg] https://radoslavchobanov.github.io/syslens-core/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/syslens.list >/dev/null
sudo apt update
sudo apt install syslens-core
```

Until that repository is live, download the matching release artifact and
install it explicitly:

```bash
sudo apt install ./syslens-core_<version>_<architecture>.deb
```

The package installs `/usr/bin/syslens` and an optional systemd user-service
template. It does not configure a broker, start a publisher, or enable the
privileged inventory helper automatically. Follow the guided commands below
after installation. Packaging details and local build instructions are in
[`packaging/debian`](packaging/debian/README.md); APT repository policy,
signing, and maintainer setup are in [`packaging/apt`](packaging/apt/README.md).

## MQTT / Home Assistant

Run the guided setup and choose **MQTT publisher** on each publishing host:

```bash
syslens setup
# Compatibility spelling also works:
syslens --setup
```

It writes `~/.config/syslens/config.toml` (owner-only) and, when needed,
`~/.config/syslens/syslens.env` (owner-only). Passwords are referenced via an
environment variable and are never written into the TOML file or printed by
`--validate-config`.

```bash
syslens --config ~/.config/syslens/config.toml --validate-config
syslens --config ~/.config/syslens/config.toml --publish --once
syslens agent --config ~/.config/syslens/config.toml
```

The MQTT broker is user-provided. SysLens publishes retained messages on:

```text
syslens/<host-id>/meta
syslens/<host-id>/state
syslens/<host-id>/availability
```

The topic layout and `schema_version: 1` snapshot envelope are compatible with
the existing SysLens Python MQTT collector. MQTT may use plain TCP or standard
system-CA TLS (`mqtt.tls = true`).

Setup can install and start the systemd user service automatically. To manage
it afterwards:

```bash
systemctl --user status syslens.service
systemctl --user restart syslens.service
```

Use [`config/syslens.toml.example`](config/syslens.toml.example) for
non-interactive provisioning. The included
[`systemd/syslens.service`](systemd/syslens.service) remains available as a
manual template.

## Local persistent history

Each host keeps its own compact, owner-only collector state at
`~/.local/state/syslens-core/state.json`. It is written atomically every minute
and survives normal service and system restarts. No central database is
required.

For each tracked metric, the state stores weighted aggregates rather than raw
three-second samples:

- 24 hourly averages for the last day;
- 30 daily averages for the last month; and
- one all-time average with its sample count.

This keeps 1-day, 1-month, and all-time values durable without allowing the
state file to grow with every poll. Network transfer totals and short-lived
process smoothing are stored separately in the same file.

## Optional hardware inventory

SysLens always reports live RAM use. DIMM part number, RAM type, populated
slots, and nominal module data rate are static firmware inventory fields. On
ordinary PC/server hardware, DMI type 17 provides them; board-integrated
systems such as many ARM SBCs may not expose them at all. The inventory stores
every populated module with its slot, part number, capacity, type, and rate:
matching modules are presented as (for example) `2 × M425R2GA3BB0-CWM`, while
mixed modules are identified slot by slot.

For an NVMe root disk, the same helper also reads the standard SMART health
log: endurance remaining, lifetime data written, and critical warnings. It
does not install `nvme-cli`, and the normal SysLens agent never opens raw disk
devices.

The agent deliberately remains unprivileged. During `syslens setup`, compatible
hosts offer to enable managed hardware inventory. After one normal
system-password prompt, SysLens installs a root-owned one-shot systemd service
and a 15-minute timer. The probe reads DMI and the NVMe SMART log when those
interfaces are exposed, writes only sanitised hardware fields to
`/var/cache/syslens/hardware-inventory.json`, and the agent reads that cache
without `sudo` or any special configuration.

Existing installations can use the same managed flow:

```bash
syslens inventory enable
syslens inventory status
# Stop scheduled collection and clear the cached inventory:
syslens inventory disable
```

The timer invokes the fixed internal `inventory probe` command; it is not an
arbitrary privileged command runner. If firmware does not provide DMI or the
root disk is not NVMe, SysLens reports unavailable fields rather than guessing.

## Migrating a legacy Python publisher

Use the same `agent.host_id`, MQTT topic prefix, credentials file, and MQTT
client ID so receivers continue to see the exact same topics. Do not run the
old and new publisher under the same client ID at once: MQTT correctly treats
that as a duplicate connection.

1. Install `syslens` as `~/.local/bin/syslens`.
2. Stop the Python service, then prove the real configuration once:

   ```bash
   systemctl --user stop syslens.service
   set -a; . ~/.config/syslens/credentials.env; set +a
   ~/.local/bin/syslens --config ~/.config/syslens/config.toml --publish --once
   ```

3. Change `syslens.service` to the systemd `ExecStart` above, reload, and
   restart it. Keep a copy of the former unit beside it as
   `syslens.service.python-backup`.
4. Check the retained `<prefix>/<host-id>/state` and `availability` topics.
   Roll back immediately by restoring that saved unit and restarting the
   service if either is missing.

## Resource model

Each snapshot samples CPU, disk I/O, network throughput, and per-process CPU
over a short window (default 0.35 s). Other values are single sysfs or procfs
reads. The agent only serializes one snapshot per configured interval, so
shortening the interval is the main resource-cost tradeoff.

Hardware data is capability-based: CPU, GPU, NVMe, battery, and thermal values
appear only when Linux exposes them. Missing hardware is represented as empty
or unavailable data rather than guessed values.

For MQTT, the core omits CPU feature-flag lists and inactive container links
from the state payload. Those values are not rendered by SysLens, and keeping
the state compact makes it work with conservative 10 KiB broker packet limits.

## License

SysLens Core is released under the [MIT License](LICENSE).
