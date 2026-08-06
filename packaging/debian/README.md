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

Release artifacts are suitable for direct `apt install ./file.deb`. A later
signed APT repository is a separate publication surface: it must publish the
package index and signed Release metadata, then users add its keyring and
source once before `apt install syslens-core` works. Do not expose an
unversioned development artifact through that repository.
