# SysLens APT repository

SysLens publishes a signed, static Debian repository for final releases. It is
not a server process or a database: the published site contains versioned
`.deb` packages, APT index files, signed release metadata, and the public
archive key.

The production repository is hosted through GitHub Pages from the `gh-pages`
branch of this repository. Its intended URL is:

```text
https://radoslavchobanov.github.io/syslens-core/apt
```

The URL becomes live only after GitHub Pages is enabled and the first signed
release is published.

## What is published

```text
apt/
├── dists/stable/
│   ├── InRelease
│   ├── Release
│   ├── Release.gpg
│   └── main/binary-{amd64,arm64}/Packages.{,gz,xz}
├── pool/main/s/syslens-core/*.deb
└── syslens-archive-keyring.gpg
```

`stable` contains final tags only. Prerelease tags such as `v0.3.0-rc.1` do
not update it. APT selects the highest package version in the configured
suite; users can still request a specific older version explicitly.

## Maintainer setup, once

Do these steps before enabling APT publication. The secret key must never be
committed, attached to a GitHub Release, or copied into documentation.

1. Create an offline primary OpenPGP key and a separate signing subkey with an
   expiry. Keep an encrypted offline backup of the primary key.
2. Export **only the signing subkey** in a form GitHub Actions can import, then
   base64-encode it:

   ```bash
   gpg --export-secret-subkeys --armor <SIGNING_FINGERPRINT> | base64 | tr -d '\n'
   ```

3. Add the result as the repository Actions secret `SYSLENS_APT_SIGNING_KEY`.
   If the subkey has a passphrase, add it as `SYSLENS_APT_SIGNING_PASSPHRASE`.
4. Add a repository variable `SYSLENS_APT_SIGNING_FINGERPRINT` containing the
   public fingerprint, and set `APT_REPOSITORY_ENABLED` to `true` only after
   the other steps succeed.
5. Create an orphan `gh-pages` branch once. Enable GitHub Pages and select
   **GitHub Actions** as its publishing source. The branch preserves the
   `apt/` directory between releases; the release workflow deploys that static
   directory to Pages explicitly.

The release workflow imports the secret into a temporary GNUPG home, signs the
metadata, exports the matching public key into the repository, then discards
the temporary keyring when the runner exits.

## User installation

After the repository is live, a Debian/Ubuntu user installs its public key and
source once:

```bash
curl -fsSL https://radoslavchobanov.github.io/syslens-core/apt/syslens-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/syslens-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/syslens-archive-keyring.gpg] https://radoslavchobanov.github.io/syslens-core/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/syslens.list >/dev/null
sudo apt update
sudo apt install syslens-core
```

To upgrade later:

```bash
sudo apt update
sudo apt upgrade
```

To install a particular published version:

```bash
apt-cache madison syslens-core
sudo apt install syslens-core=<version>
```

## Local verification

`build-repository.sh` is used by CI but can also produce a test repository.
It requires `dpkg-dev`, `apt-utils`, and `gnupg` on a Debian/Ubuntu host and a
previously imported test signing key:

```bash
packaging/apt/build-repository.sh \
  --repository /tmp/syslens-apt/apt \
  --packages dist \
  --signing-key <TEST_SIGNING_FINGERPRINT>
```

Use a temporary test key locally. Never use, export, or retain the production
signing key outside the protected release process.
