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
  0.1.0 \
  amd64 \
  dist
```

Install the resulting artifact locally with:

```bash
sudo apt install ./dist/syslens-core_0.1.0_amd64.deb
```

For aarch64 builds, pass an aarch64-built binary and `arm64`. The GitHub
release workflow performs these builds for tagged releases.

## APT repository policy

Release artifacts are suitable for direct `apt install ./file.deb`. Final
release tags are additionally eligible for the signed `stable` APT repository;
pre-release tags are deliberately excluded. See [`../apt`](../apt/README.md)
for the repository structure, signing-key boundary, maintainer setup, and user
installation instructions.
