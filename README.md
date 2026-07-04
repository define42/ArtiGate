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

## TLS / HTTPS

Both servers serve plain HTTP by default. Enable HTTPS entirely through environment
variables (no flags) — the same set applies to `low` and `high`.
`ARTIGATE_TLS_MODE` selects one of:

- `unencrypted` (default) — plain HTTP.
- `acme` — obtain and renew certificates automatically via ACME (certmagic).
- `own-certificate` — use a certificate and key you provide.
- `auto-generate-certificate` — a self-signed certificate made at startup (handy
  for testing; clients must trust it or skip verification).

| Variable | Modes | Meaning |
|---|---|---|
| `ARTIGATE_TLS_MODE` | all | `unencrypted` / `acme` / `own-certificate` / `auto-generate-certificate` |
| `ARTIGATE_TLS_DOMAINS` | acme, auto-generate | comma-separated domains/IPs (ACME cert names; self-signed SANs) |
| `ARTIGATE_TLS_CERT`, `ARTIGATE_TLS_KEY` | own-certificate | PEM certificate and private-key paths |
| `ARTIGATE_ACME_EMAIL` | acme | account email |
| `ARTIGATE_ACME_DIRECTORY` | acme | ACME server directory URL (defaults to Let's Encrypt) |
| `ARTIGATE_ACME_CA_ROOT` | acme | PEM root CA to trust, for a private ACME server |
| `ARTIGATE_ACME_STORAGE` | acme | certificate cache directory (default `<root>/acme`) |

Example against a private ACME server (e.g. step-ca):

```bash
export ARTIGATE_TLS_MODE=acme
export ARTIGATE_TLS_DOMAINS=mirror.internal
export ARTIGATE_ACME_EMAIL=ops@internal
export ARTIGATE_ACME_DIRECTORY=https://ca.internal/acme/acme/directory
export ARTIGATE_ACME_CA_ROOT=/etc/artigate/ca-root.pem
```

ACME uses the TLS-ALPN-01 challenge on the server's own listen port, so that port
must be reachable by the ACME server as the configured domain.

## Authentication (low side)

The low-side dashboard can require a login. It is off by default and enabled
through a single environment variable, `ARTIGATE_LOW_AUTH`, holding one or more
credentials. Passwords are stored as argon2id hashes, never in plaintext —
generate one with the `hashpw` subcommand (it reads the password from stdin so it
never appears in your shell history):

```bash
./artigate hashpw --user alice
# prompts on stdin, then prints:  alice:$argon2id$v=19$m=65536,t=3,p=1$...$...
```

Put one or more `username:hash` credentials in the variable, separated by `;` or
newlines (not commas — the argon2 parameters inside a hash contain commas):

```bash
export ARTIGATE_LOW_AUTH='alice:$argon2id$v=19$...;bob:$argon2id$v=19$...'
```

When set, the dashboard presents a sign-in page and, after a successful login,
carries the session in an encrypted, signed cookie (gorilla/securecookie); a
**Log out** button in the header clears it. Sessions last 12 hours and survive a
restart (the cookie keys are persisted to `<root>/session.key`). The `/healthz`
probe stays open so container health checks keep working. The **high side is
never authenticated** — it serves only already-verified public mirror content.

**When `ARTIGATE_LOW_AUTH` is unset the low-side dashboard is unauthenticated** —
including the mutating `/admin/*` endpoints — so bind it to localhost or a trusted
network, or set credentials.

The session cookie's `Secure` flag defaults to whether ArtiGate itself terminates
TLS. If ArtiGate serves plain HTTP behind a TLS-terminating reverse proxy, set
`ARTIGATE_LOW_COOKIE_SECURE=true` so the cookie is still marked `Secure` (values:
`auto` (default), `true`, `false`).

> In `docker-compose.yml`, remember that Compose treats `$` as a variable
> reference, so every `$` in the hash must be written `$$` (see the `low`
> service). This does not apply to shell `export`s with single quotes.

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

- The **low-side dashboard** can require a session login (`ARTIGATE_LOW_AUTH`, see
  above) but is **unauthenticated by default** — until you set credentials, bind it
  to localhost or a trusted network. The **high-side dashboard** is always
  unauthenticated — it serves only already-verified public mirror content, so bind
  it to localhost or a trusted network too.
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
