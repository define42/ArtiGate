# ArtiGate

[![codecov](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg?token=RBKT8U26R8)](https://codecov.io/gh/define42/ArtiGate)

ArtiGate is a dependency mirror for **one-way data-diode networks**. It mirrors
Go modules, Python (PyPI) wheels, Java (Maven) artifacts, APT (`.deb`) and RPM
(`.rpm`) repositories from the internet into an air-gapped network, and serves
them there in each ecosystem's native format.

One binary, two modes:

- **`low`** — runs on the internet side. From its web dashboard you give it a spec
  (a `go.mod` or module list, a Python requirements list, Maven coordinates, an
  APT source, or a `.repo`); it fetches the artifacts from upstream and writes
  **signed, numbered bundle files**.
- **`high`** — runs air-gapped. It imports the bundles (in order, verifying every
  signature and hash) and serves them as a GOPROXY, a PyPI index, a Maven 2
  repository, and APT/RPM repositories.

```
  spec ──▶ [ low ] ──▶ signed bundles ──▶ ((diode)) ──▶ [ high ] ──▶ clients
         fetch + sign        carry across          verify + serve
```

Each ecosystem is an independently numbered **stream**, so a stalled or missing
bundle in one never blocks the others.

## Build

```bash
go build -o artigate ./cmd/artigate
```

## Quick start (Docker Compose)

Brings up a low + high stack wired together by a shared `diode` volume, with the
signing keys generated automatically:

```bash
make run          # foreground   (make run-detach to background)
make stop         # stop, keep state    make reset  wipe state
```

Then open the low-side dashboard at <http://localhost:8080/>, pick an ecosystem,
enter a spec (or upload a `go.mod`), and click **Collect & export**. Watch it
appear on the high-side dashboard at <http://localhost:8081/>, then point a client
at the high side (see below).

## Signing keys

```bash
./artigate keygen --private low.ed25519 --public high.ed25519.pub
```

Keep the private key on the low side only; install the public key on the high side.

## Low side

```bash
./artigate low \
  --listen :8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct \
  --goprivate github.com/your-org/*
```

Everything is driven from the **dashboard at `http://<low-host>:8080/`** — one page
per ecosystem. Each collect fetches from upstream and writes a signed bundle to
the export directory (three files per bundle: `.tar.gz`, `.manifest.json`,
`.manifest.json.sig`).

Fetching uses the host's normal tools and credentials (`go`/`git`, `pip`, `mvn`,
`gpgv`). For private Go modules, configure the service user's Git/SSH before
starting. `--gotoolchain` (default `auto`) lets `go` download a newer toolchain
when a module requires one.

### What each page mirrors

- **Go** — list modules to fetch (`module@version`, or a bare `module` /
  `module@latest` for the newest), or upload a project's `go.mod` (and optional
  `go.sum`) to mirror exactly what it builds. The full dependency graph is always
  fetched.
- **Python** — a requirements list (paste or upload `requirements.txt`). An
  optional cross-target downloads wheels for the high-side interpreter/platform
  rather than the low-side host. Wheels only.
- **Java** — Maven coordinates (`groupId:artifactId:version`, one per line) or an
  uploaded `pom.xml`. Release versions only; SNAPSHOTs and version ranges are
  rejected.
- **APT** — a deb822 source stanza (paste or upload a `.sources` file). An optional
  `Signed-By` keyring verifies the upstream release with `gpgv`; several stanzas
  mirror several repositories. Example:

  ```text
  Types: deb
  URIs: https://packages.microsoft.com/repos/code
  Suites: stable
  Components: main
  Architectures: amd64
  Signed-By: /usr/share/keyrings/microsoft.gpg
  ```

- **RPM** — a yum/dnf `.repo` stanza (paste or upload). `baseurl` must be concrete
  (no `$releasever`/`$basearch`). Mirrors the repository's full metadata plus its
  `.rpm`s. Example:

  ```text
  [code]
  baseurl=https://packages.microsoft.com/yumrepos/vscode
  gpgcheck=1
  gpgkey=https://packages.microsoft.com/keys/microsoft.asc
  ```

For APT and RPM, a **"Newest version only"** checkbox (on by default) mirrors just
the latest version of each package; untick it to mirror every version.

### Scheduling

Each ecosystem page can turn its inputs into a **recurring pull**: set an interval
(hours or days) and click *Add schedule* — e.g. re-pull a `go.mod` or a
requirements list every day. Schedules run in the background and can be paused,
run immediately, or deleted from the same page.

### Status and re-export

The **Status** page shows each stream's next bundle number and the exported
bundles (with sizes). If the high side reports a bundle missing, use its
re-transmit form to regenerate that bundle number or range from the archive.

## Data diode

Carry each bundle's three files across the diode into the high side's landing
directory. The high side imports each **stream** strictly in order. An
out-of-order bundle (e.g. `go-bundle-000043` before `000042`) is quarantined, not
rejected, and imported automatically once the gap is filled; duplicates and old
replays are ignored. A gap in one stream never blocks the others.

## High side

```bash
./artigate high \
  --listen :8080 \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --public-key /etc/artigate/high.ed25519.pub \
  --import-interval 10s \
  # --apt-gpg-key <keyid>  --rpm-gpg-key <keyid>   (optional: sign the served repos)
```

It imports on a timer, and the **dashboard at `http://<high-host>:8080/`** shows
import status (per stream, flagging any missing bundles) and a browsable tree of
everything mirrored. The high side never trusts transferred index/`latest`/
metadata files as truth — it regenerates them from the artifacts actually present,
and serves only complete versions.

### Point clients at the high side

```bash
# Go
go env -w GOPROXY=https://artigate-high.local,off
go env -w GOSUMDB=off
```

```ini
# Python — /etc/pip.conf
[global]
index-url = https://artigate-high.local/simple/
```

```xml
<!-- Maven — ~/.m2/settings.xml -->
<settings><mirrors><mirror>
  <id>artigate</id><mirrorOf>*</mirrorOf>
  <url>https://artigate-high.local/maven/</url>
</mirror></mirrors></settings>
```

```text
# APT — /etc/apt/sources.list.d/artigate.sources  (use ArtiGate's key, not the vendor's)
Types: deb
URIs: https://artigate-high.local/apt/<mirror>
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/artigate-apt.gpg
```

```ini
# RPM — /etc/yum.repos.d/artigate.repo
[artigate]
baseurl=https://artigate-high.local/rpm/<mirror>
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-artigate
```

On the high side, use **only** ArtiGate as the source — don't add
`--extra-index-url`, `mavenCentral()`, or other upstreams, which reopens
dependency-confusion risk. If a repo is published unsigned, relax the client's
signature check (`repo_gpgcheck=0`, `[trusted=yes]`, etc.).

## Notes and limitations

- The dashboards are **unauthenticated** — bind to localhost or put them behind a
  firewall / authenticating reverse proxy.
- **Go**: no sumdb mirroring — use `GOSUMDB=off` on the high side and rely on your
  committed `go.sum` plus the signed bundles.
- **Python**: wheels only (no sdists).
- **Java/Maven**: release versions only; SNAPSHOT and dynamic/range versions are
  rejected.
- **APT/RPM**: mirror the newest version of each package by default; untick
  "Newest version only" to mirror every version. RPM `.zck`-only indexes aren't
  supported (use `.gz`/`.xz`). Each collect is a full re-sync.
- **Signing the served repos** is optional (`--apt-gpg-key`/`--rpm-gpg-key`);
  otherwise APT/RPM repositories are published unsigned.
- Low-side collects for different ecosystems run concurrently; the high side never
  runs `go`/`pip`/`mvn` and does no upstream fetching.
