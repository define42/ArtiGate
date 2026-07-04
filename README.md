# ArtiGate

[![codecov](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg?token=RBKT8U26R8)](https://codecov.io/gh/define42/ArtiGate)

ArtiGate is a dependency mirror for **one-way data-diode networks**. It mirrors
Go modules, Python (PyPI) wheels, Java (Maven) artifacts, APT (`.deb`) and RPM
(`.rpm`) repositories from the internet into an air-gapped network, and serves
them there in each ecosystem's native format.

One binary, two modes:

- **`low`** — runs on the internet side. You give it a spec (a `go.mod` or module
  list, a Python requirements list, Maven coordinates, an APT source, or a
  `.repo`); it fetches the artifacts from upstream and writes **signed, numbered
  bundle files**.
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

- Low-side dashboard:  <http://localhost:8080/>
- High-side dashboard: <http://localhost:8081/>

Mirror something and watch it flow through:

```bash
curl -XPOST localhost:8080/admin/go/collect     -d '{"modules":["rsc.io/quote@latest"]}'
curl -XPOST localhost:8080/admin/python/collect -d '{"requirements":["requests"]}'
curl -XPOST localhost:8080/admin/maven/collect  -d '{"coordinates":["org.slf4j:slf4j-api:2.0.16"]}'
curl -XPOST localhost:8080/admin/apt/collect    -d '{"source_list":"Types: deb\nURIs: https://packages.microsoft.com/repos/code\nSuites: stable\nComponents: main\nArchitectures: amd64\n"}'
curl -XPOST localhost:8080/admin/rpm/collect    -d '{"repo_file":"[code]\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\ngpgcheck=1\n"}'
```

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

The low side is an **exporter, not a proxy** — nothing points a client at it. You
drive it from the dashboard or the `/admin/<ecosystem>/collect` endpoints. Each
collect fetches from upstream and writes a signed bundle to the export directory
(three files per bundle: `.tar.gz`, `.manifest.json`, `.manifest.json.sig`).

Fetching uses the host's normal tools and credentials (`go`/`git`, `pip`, `mvn`,
`gpgv`). For private Go modules, configure the service user's Git/SSH before
starting. `--gotoolchain` (default `auto`) lets `go` download a newer toolchain
when a module requires one.

### Mirroring each ecosystem

**Go** — a module list (`module@version`, or a bare `module`/`@latest` for the
newest), which is fetched with its full dependency graph:

```bash
curl -XPOST localhost:8080/admin/go/collect \
  -d '{"modules":["github.com/caddyserver/certmagic","golang.org/x/text@v0.14.0"]}'
```

Or send a project's own `go.mod` (optionally `go.sum`) to mirror exactly what it
builds — the closest to "everything needed to build this offline":

```bash
jq -n --rawfile mod go.mod '{go_mod:$mod}' | curl -XPOST localhost:8080/admin/go/collect -d @-
```

**Python** — a requirements list. Add an optional `target` to download wheels for
the high-side interpreter rather than the low-side host:

```bash
curl -XPOST localhost:8080/admin/python/collect -d '{
  "requirements": ["requests==2.32.4", "urllib3"],
  "target": {"python_version":"3.12","abi":"cp312","platforms":["manylinux_2_28_x86_64"]}
}'
```

**Java/Maven** — coordinates (`groupId:artifactId:version`) or a `pom.xml`.
Release versions only; SNAPSHOTs and version ranges are rejected:

```bash
curl -XPOST localhost:8080/admin/maven/collect -d '{"coordinates":["com.google.guava:guava:33.3.1-jre"]}'
```

**APT** — a deb822 source stanza. Optional `Signed-By` (a low-side keyring path)
verifies the upstream release with `gpgv`; several stanzas mirror several repos.
By default only the newest version of each package is mirrored (`newest_only:
false` for all versions):

```bash
curl -XPOST localhost:8080/admin/apt/collect -d "$(jq -Rs '{source_list: .}' <<'EOF'
Types: deb
URIs: https://packages.microsoft.com/repos/code
Suites: stable
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/microsoft.gpg
EOF
)"
```

**RPM** — a yum/dnf `.repo` stanza (`baseurl` must be concrete). Mirrors the
repository's full metadata plus its `.rpm`s; newest-only by default:

```bash
curl -XPOST localhost:8080/admin/rpm/collect -d "$(jq -Rs '{repo_file: .}' <<'EOF'
[code]
baseurl=https://packages.microsoft.com/yumrepos/vscode
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
EOF
)"
```

### Dashboard and scheduling

The dashboard (at `/`) has a page per ecosystem for one-off collects, a **Status**
page (per-stream sequence numbers and exported bundles), and re-export controls.

Each ecosystem page can also **schedule** a recurring pull from its own inputs —
set an interval (hours/days) and click *Add schedule*, e.g. re-pull a `go.mod` or
a requirements list every day. Schedules run in the background and can be paused,
run now, or deleted.

### Re-export

If the high side is missing a bundle, re-export it (bundles are archived, so the
exact signed files are replayed — name the stream, default `go`):

```bash
curl -XPOST 'localhost:8080/admin/reexport?stream=python&sequences=42,45-47'
curl localhost:8080/admin/bundles     # list what has been exported
```

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

It imports on a timer (or `POST /admin/import`), and `GET /admin/status` reports
per-stream progress and any missing ranges. The dashboard (at `/`) shows import
status and a lazily-loaded, browsable tree of everything mirrored.

The high side never trusts transferred index/`latest`/metadata files as truth —
it regenerates them from the artifacts actually present, and serves only complete
versions.

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

- **Admin endpoints are unauthenticated** — bind to localhost or put them behind a
  firewall / authenticating reverse proxy.
- **Go**: no sumdb mirroring — use `GOSUMDB=off` on the high side and rely on your
  committed `go.sum` plus the signed bundles.
- **Python**: wheels only (no sdists).
- **Java/Maven**: release versions only; SNAPSHOT and dynamic/range versions are
  rejected.
- **APT/RPM**: mirror the newest version of each package by default; disable
  "newest only" to mirror every version. RPM `.zck`-only indexes aren't supported
  (use `.gz`/`.xz`). Each collect is a full re-sync.
- **Signing the served repos** is optional (`--apt-gpg-key`/`--rpm-gpg-key`);
  otherwise APT/RPM repositories are published unsigned.
- Low-side collects for different ecosystems run concurrently; the high side never
  runs `go`/`pip`/`mvn` and does no upstream fetching.
