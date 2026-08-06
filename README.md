# SysLens Core

`syslens-core` is the small Linux collector behind SysLens. It reads kernel and
sysfs data directly, produces one stable JSON snapshot, and can optionally
publish it to an MQTT broker. It has no database, web server, or broker of its
own.

The Plasma interface is deliberately a separate package. Home Assistant can
consume the same retained MQTT snapshots without depending on Plasma.

## Install and use

Build once, then install it under the non-conflicting migration name:

```bash
scripts/install-core.sh
syslens-core snapshot --pretty
```

`syslens-core` does not need any setup for local-only use. The future Plasma
package simply executes `syslens-core snapshot --json` locally, or over SSH on
a remote host.

When all consumers have moved off the legacy Python CLI, install it as the
normal `syslens` command:

```bash
scripts/install-core.sh --activate
```

## MQTT / Home Assistant

Run the guided setup on each publishing host:

```bash
syslens-core setup
# Compatibility spelling also works:
syslens-core --setup
```

It writes `~/.config/syslens/config.toml` (owner-only) and, when needed,
`~/.config/syslens/syslens.env` (owner-only). Passwords are referenced via an
environment variable and are never written into the TOML file or printed by
`--validate-config`.

```bash
syslens-core --config ~/.config/syslens/config.toml --validate-config
syslens-core --config ~/.config/syslens/config.toml --publish --once
syslens-core agent --config ~/.config/syslens/config.toml
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

For a systemd user service, load the secret file before starting the agent:

```ini
[Service]
EnvironmentFile=%h/.config/syslens/syslens.env
ExecStart=%h/.local/bin/syslens-core agent --config %h/.config/syslens/config.toml
Restart=on-failure
```

The ready-to-copy unit is [`systemd/syslens.service`](systemd/syslens.service):

```bash
mkdir -p ~/.config/systemd/user
cp systemd/syslens.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now syslens.service
```

Use [`config/syslens.toml.example`](config/syslens.toml.example) for
non-interactive provisioning.

## Resource model

Each snapshot samples CPU, disk I/O, network throughput, and per-process CPU
over a short window (default 0.35 s). Other values are single sysfs or procfs
reads. The agent only serializes one snapshot per configured interval, so
shortening the interval is the main resource-cost tradeoff.

Hardware data is capability-based: CPU, GPU, NVMe, battery, and thermal values
appear only when Linux exposes them. Missing hardware is represented as empty
or unavailable data rather than guessed values.
