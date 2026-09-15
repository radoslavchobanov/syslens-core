# Debian packaging

The `syslens-core` package installs the `syslens` command and an optional
systemd **user** service template. It does not configure MQTT, start a service,
or enable the privileged hardware-inventory timer during package installation.
Those actions remain explicit user choices through `syslens setup` and
`syslens inventory enable`.

## Build locally

Build Core for the architecture on which the package will run, then package the
result with a Debian-based build host:

```bash
cargo build --locked --release
packaging/debian/build-deb.sh \
  target/release/syslens \
  0.2.0 \
  amd64 \
  dist
```

Install the resulting artifact locally with:

```bash
sudo apt install ./dist/syslens-core_0.2.0_amd64.deb
```

For aarch64 builds, pass an aarch64-built binary and `arm64`. The GitHub
release workflow performs these builds for tagged releases.

## Optional diagnosis add-on

The separately installable `syslens-diagnosis` package records local RAM and
process evidence only after `syslens-diagnosis enable`. It does not contact a
model. Build it independently after building the workspace:

```bash
cargo build --locked --release --package syslens-diagnosis
packaging/debian/build-diagnosis-deb.sh \
  target/release/syslens-diagnosis \
  0.2.0 \
  amd64 \
  dist
```

The package installs a disabled systemd user-service template. Package
installation never starts it. Enable it explicitly after installation.

## Optional gateway

`syslens-gateway` is an independent owner-owned evidence gateway and terminal
client. It polls configured mTLS host APIs, keeps bounded event/session state,
and is the only package that can optionally contact an OpenAI-compatible
endpoint. It neither bundles nor starts a model. Build and package it
independently:

```bash
cargo build --locked --release --package syslens-gateway
packaging/debian/build-gateway-deb.sh \
  target/release/syslens-gateway \
  0.2.0 \
  amd64 \
  dist
```

After installation, run `syslens-gateway init`, configure the owner-only
`~/.config/syslens-gateway/config.toml`, then run `syslens-gateway enable`.
The package never starts the service or creates state during installation.

### Optional split Docker deployment

Core and diagnosis remain native Debian/systemd services on each monitored
host. The gateway may instead use the [Orange Pi Docker project](../../deploy/gateway/README.md)
with a separate [Acemagic Ollama project](../../deploy/ollama/README.md).
These templates do not modify the native gateway package or unit and do not
deploy automatically during package installation. They include independent
image/model update and rollback procedures. CI and the release verification
job run `python3 deploy/test_assets.py` to parse the Compose YAML subset and
statically check Dockerfile and deployment security conventions without a
Docker daemon, third-party Python packages, or network requests.

## APT repository policy

Release artifacts are suitable for direct `apt install ./file.deb`. Final
release tags are additionally eligible for the signed `stable` APT repository;
pre-release tags are deliberately excluded. See [`../apt`](../apt/README.md)
for the repository structure, signing-key boundary, maintainer setup, and user
installation instructions.
