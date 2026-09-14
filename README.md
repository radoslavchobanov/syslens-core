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

Collection runs on a worker thread, so keys and rendering remain responsive while
sampling. Repeated refresh requests coalesce into the current collection. The TUI
restores the terminal before joining an active sample on exit. Optional `lspci`
enrichment has a 500 ms timeout and a 64 KiB output limit; failed probes retain the
usual unavailable fallback and are cached per PCI slot. The TUI
collects the complete process list (ignoring `--process-limit`), so memory sorting
can find idle processes and selection scrolls through all entries. CLI JSON and
MQTT still publish the requested CPU-ranked top processes, six by default.

One-shot snapshots and the first agent/TUI sample use `--sample-window` (default
0.35 seconds, accepted range 0.05–2 seconds). Later agent/TUI samples reuse the
previous counters and cover the full interval between readings, including
collection work. Disk, network, and energy rates use each source's read midpoint;
process CPU uses each PID's stat-read midpoint. `sample_window_seconds` reports
the actual interval between CPU readings. Slow collection skips missed deadlines
instead of publishing a burst of catch-up snapshots.

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
APT repository once it is enabled. To configure that repository once on a
Debian/Ubuntu host, from any directory:

```bash
curl -fsSL https://radoslavchobanov.github.io/syslens-core/apt/install.sh | sudo bash
sudo apt update
sudo apt install syslens-core
```

The setup script only downloads a public archive key, verifies its expected
fingerprint, and adds the APT source; it does not install SysLens itself. From
then on, `sudo apt install syslens-core` and normal APT upgrades work from any
directory without a cloned SysLens repository.

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

Each process entry in a snapshot includes `private_bytes`, the resident
anonymous memory currently held by that process. File-backed mappings such as
large database caches are not included in this value. The older `rss_bytes`
field remains in the payload for compatibility with older consumers, but new
interfaces should use `private_bytes`.

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

The agent keeps collecting and saving this local history while its MQTT broker
is unavailable. It retries MQTT with capped exponential backoff and small
jitter, retaining only the newest snapshot during an outage. Each new broker
session publishes retained `meta`, then retained `availability: online`, then
the current `state`. `--once` waits for its selected MQTT QoS to complete and
returns an error if connection or delivery times out. A clean SIGINT or SIGTERM
always saves history and makes a bounded, best-effort retained `offline` update;
that final MQTT attempt has a 400 ms budget.

The agent holds an advisory history lock for its lifetime; a second agent using
the same state path exits with an error. Standalone snapshots and TUI refreshes
lock before loading, update and atomically save, then release ownership. While
the agent owns history, local views keep ephemeral history without writing it.
An open TUI therefore does not hold the lock between refreshes. A new agent may
need to retry if a local refresh currently owns the lock. Temporary state files
are unique and owner-only. Read, parse, and persistence errors are reported;
malformed history is preserved and must be moved aside explicitly to reset it.

For each tracked metric, the state stores weighted aggregates rather than raw
three-second samples:

- 24 hourly averages for the last day;
- 30 daily averages for the last month; and
- one all-time average with its sample count.

This keeps 1-day, 1-month, and all-time values durable without allowing the
state file to grow with every poll. Network transfer totals and short-lived
process smoothing are stored separately in the same file.

## Optional diagnosis add-on

`syslens-diagnosis` is a separate local-host add-on. Core does not install or
run it, so an absent or disabled add-on adds no writer, database, model client,
or diagnosis collection to `syslens`.

The optional add-on records local RAM and process evidence in a SQLite database.
It has no MQTT, model, or Core dependency. It keeps detailed samples for 185
days by default and pauses recording rather than silently shortening retention
when its 16 GiB database budget is reached.

```bash
syslens-diagnosis status
syslens-diagnosis enable
syslens-diagnosis disable
syslens-diagnosis diagnose memory --since today --compare previous-week
syslens-diagnosis diagnose storage --since 7d --compare previous-week
syslens diagnose memory --since 7d
syslens-diagnosis chat "What local evidence explains the recent RAM increase?"
```

`enable` creates `~/.config/syslens-diagnosis/config.toml` (owner-only),
initialises `~/.local/state/syslens-diagnosis/diagnosis.sqlite`, then enables
its user service. The daemon stores host RAM composition plus visible process
RssAnon/RSS and CPU/I/O counters every 30 seconds. `diagnose memory` compares
stored local intervals and names observed process growth; it clearly reports
insufficient coverage below 80% in either interval and never claims RssAnon is USS/private memory.

The add-on also records durable local warning, escalation, and recovery events
for sustained unusual memory use, Linux memory pressure, filesystem capacity,
and supported storage-growth forecasts. It has no push transport: inspect or
replay events with `syslens-diagnosis incidents list`, `events --after CURSOR`,
`show ID`, and `acknowledge ID`. Reading events never marks them delivered.
The strict `[detection]` configuration defaults to a 24-hour warm baseline and
80% coverage before a memory-baseline alert can open.

### Optional AI chat

The add-on's outbound OpenAI-compatible `/v1/chat/completions` client is
disabled by default. It neither installs nor runs a model. Enable it only in
the owner-only diagnosis configuration created by `enable`:

```toml
[ai]
enabled = true
endpoint_url = "https://ai.example.net/v1/chat/completions"
# Default false. Set true only for a trusted LAN/loopback IP endpoint using HTTP.
allow_insecure_http = false
model = "your-compatible-model"
# Optional: bearer token is read from this environment variable, never TOML.
api_key_env = "SYSLENS_DIAGNOSIS_AI_API_KEY"
request_timeout_seconds = 20
```

[`crates/syslens-diagnosis/config.toml.example`](crates/syslens-diagnosis/config.toml.example)
is a minimal equivalent example. Do not place this `[ai]` section in the Core
MQTT configuration.

HTTPS is required by default. A separately supplied lightweight model service on
a trusted LAN or loopback address may use plaintext HTTP only after explicitly
setting `allow_insecure_http = true`; HTTP hostnames and public IPs remain
rejected. HTTP exposes prompts and responses to anyone able to observe that
network, so use it only on a network you trust. Redirects remain disabled.

`syslens-diagnosis chat "question"` sends the question and a fixed capability
description first. The endpoint can then request only validated, read-only
memory or storage diagnoses (up to 30 days), current evidence status, or up to
20 recent incidents. It cannot invoke a shell, SQL, filesystem, network, or
arbitrary tools. The client limits action rounds, results, response size, and
HTTP time, and reports disabled, unreachable, or malformed endpoints without
printing endpoint credentials. A plain answer is permitted, but it must not be
treated as local evidence unless the endpoint requested and received it.

Every `incidents ... --json` response uses a version `1` envelope. `watch`
emits one notification-event envelope per event, while `list`, `show`, and
`events` emit list or item envelopes. `acknowledge ID --json` emits an
acknowledgement envelope. Event replay reports a history gap when the requested
cursor predates retained events. `events --limit` is paginated (at most 256
events per request); use `next_cursor` until `has_more` is false. Storage
forecasts require a contiguous compatible history and use a robust Theil-Sen
hourly growth slope, so isolated spikes and flat post-jump usage do not predict
capacity exhaustion.

The add-on also records local writable mount capacity and inode counters every
collection interval. It scans eligible local mount roots at startup and then
hourly by default, retaining directory summaries to four levels. Directory
paths remain only in the host-local SQLite database. The unprivileged scanner
does not follow symlinks or cross mount boundaries, applies configured time and
entry budgets, traverses deeper descendants into the deepest retained summary,
includes directory metadata allocation consistently, and marks permission-limited or partial scans as incomplete.
The separate scanner worker requests a lower CPU priority on Unix as a best-effort
hint; collection and diagnosis remain usable if that request is denied.
`diagnose storage` only attributes growth to a path when two complete scans are
comparable; it can prove mount growth without guessing a path or process cause.
The optional `[storage]` configuration accepts `scan_interval_seconds` (300 to
86400), `max_depth` (1 to 8), `max_entries` (1000 to 10000000),
`max_duration_seconds` (5 to 3600), and an explicit `roots` list that replaces
the default eligible-mount selection.

`enable` checks user-service lingering. If it reports that lingering is off,
the collector will stop after logout; enable it explicitly with
`loginctl enable-linger $USER` when continuous home-server recording is wanted.

Core forwards `syslens diagnose ...`, `syslens chat`, and `syslens incidents
...` to the companion on the same host when installed. Core-only installations
create no diagnosis state or background work.
See [`packaging/debian`](packaging/debian/README.md) for the independent
package build.

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
