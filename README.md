# ArtiGate

[![codecov](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg?token=RBKT8U26R8)](https://codecov.io/gh/define42/ArtiGate)
[![docs](https://img.shields.io/badge/docs-define42.github.io%2FArtiGate-green)](https://define42.github.io/ArtiGate/)

ArtiGate is a dependency mirror for **one-way data-diode networks**. It mirrors
Go modules, Python (PyPI) wheels, Java (Maven) artifacts, NPM packages, APT
(`.deb`) and RPM (`.rpm`) repositories, container images (Docker/OCI,
linux/amd64), and AI models from Hugging Face (GGUF for Ollama, plus full
safetensors repositories) from the internet into an air-gapped network, and
serves them there in each ecosystem's native format.

One binary, two modes:

- **`low`** — runs on the internet side. From its web dashboard you give it a spec
  (a `go.mod` or module list, a Python requirements list, Maven coordinates, a
  `package.json` or NPM package list, an APT source, a `.repo`, a list of
  container images, or a list of Hugging Face model references); it fetches the
  artifacts from upstream and writes **signed, numbered bundle files**.
- **`high`** — runs air-gapped. It imports the bundles (in order, verifying every
  signature and hash) and serves them as a GOPROXY, a PyPI index, a Maven 2
  repository, an NPM registry, APT/RPM repositories, a read-only OCI
  container registry, and an Ollama-compatible model registry with a
  Hugging Face Hub download API.

```
  spec ──▶ [ low ] ──▶ signed bundles ──▶ ((diode)) ──▶ [ high ] ──▶ clients
         fetch + sign        carry across          verify + serve
```

Each ecosystem is an independently numbered **stream**, so a stalled or missing
bundle in one never blocks the others. The high side never trusts transferred
metadata: it verifies every byte against the signed manifest and regenerates
all repository indexes from the artifacts actually present.

Full documentation lives at **<https://define42.github.io/ArtiGate/>**.

## Quick start (Docker Compose)

Brings up a low + high stack wired together over the HTTP diode transport (the
low side uploads each bundle to the high side's `/diode` ingest endpoint), with
the signing keys generated automatically. The stack refuses to start until an
operator login and a random diode token are configured:

```bash
cp .env.example .env
go run ./cmd/artigate hashpw --user admin  # paste into ARTIGATE_LOW_AUTH
openssl rand -hex 32              # paste the output into ARTIGATE_DIODE_TOKEN
make run          # foreground   (make run-detach to background)
make stop         # stop, keep state    make reset  wipe state
```

Then open the low-side dashboard at <http://localhost:8080/>, pick an ecosystem,
enter a spec (or upload a `go.mod`), and click **Collect & export**. Watch it
appear on the high-side dashboard at <http://localhost:8081/>, then point a client
at the high side (see below). Both published ports are loopback-only by default;
terminate TLS in a reverse proxy before deliberately exposing either one.

## Build

```bash
go build -o artigate ./cmd/artigate     # or: make build
```

CI publishes a container image on every push to `main`:
`ghcr.io/define42/artigate` (tags: `latest`, the commit SHA, and a
semver tag). The image bundles the fetch toolchains the low side shells out to
(`go`/`git`, `pip`, `mvn` + JDK, `npm`, `gpgv`, `xz`); a high-only deployment
needs none of them except `gnupg` when signing served APT/RPM repos.

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
`npm`, `gpgv`). For private Go modules, configure the service user's Git/SSH
before starting. `--gotoolchain` (default `auto`) lets `go` download a newer
toolchain when a module requires one. The [configuration
reference](https://define42.github.io/ArtiGate/configuration/) lists every flag
and environment variable.

### What each page mirrors

- **Go** — list modules to fetch (`module@version`, or a bare `module` /
  `module@latest` for the newest), or upload a project's `go.mod` (and optional
  `go.sum`) to mirror exactly what it builds. The full dependency graph is always
  fetched.
- **Python** — a requirements list (paste or upload `requirements.txt`). Wheels
  only (no sdists), enforced with `--only-binary=:all:` for every collect so
  package build hooks never run beside the signing key. The collect fails when a
  package in the closure has no compatible wheel. An optional cross-target
  downloads wheels for the high-side interpreter/platform rather than the
  low-side host.
- **Java** — Maven coordinates (`groupId:artifactId:version`, one per line) or an
  uploaded `pom.xml`. Only the pom's dependency information is used — build
  sections, profiles, and repository overrides are rejected, so an uploaded pom
  can never execute code through Maven. Release versions only; SNAPSHOTs and
  version ranges are rejected.
- **NPM** — package specs (one per line: `lodash@4.17.21`, a bare `lodash` for
  the newest version, a range like `react@^18.2`, scoped `@types/node`), or an
  uploaded `package.json` (with an optional `package-lock.json` pinning the
  exact resolved graph). The full dependency graph is resolved with `npm`
  (`--package-lock-only`, scripts never run) and every resolved registry
  tarball is downloaded and verified against the lockfile's integrity hash.
  Dependencies that resolve outside the registry (git/file URLs) are skipped
  and reported. `--npm-registry` points resolution at a different registry.
- **APT** — a deb822 source stanza (paste or upload a `.sources` file). `Suites:`
  may list several suites of the archive (they share one mirror and its pool); an
  optional `Signed-By` keyring verifies each suite's upstream release with `gpgv`;
  several stanzas mirror several repositories. The mirror is named after the
  repository URI. Example:

  ```text
  Types: deb
  URIs: http://archive.ubuntu.com/ubuntu
  Suites: noble noble-updates noble-security
  Components: main universe
  Architectures: amd64
  Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
  ```

- **RPM** — a yum/dnf `.repo` stanza (paste or upload). `baseurl` must be concrete
  (no `$releasever`/`$basearch`) and names the mirror. Mirrors the repository's
  metadata plus its `.rpm`s — by default only the **x86_64 and noarch**
  packages (noarch rides along because hardware-arch packages depend on it);
  list architectures explicitly in the collect request to override. Example:

  ```text
  [code]
  baseurl=https://packages.microsoft.com/yumrepos/vscode
  gpgcheck=1
  gpgkey=https://packages.microsoft.com/keys/microsoft.asc
  ```

- **Containers** — image references, one per line: `alpine:3.20`,
  `ghcr.io/org/app:v1`, `registry.access.redhat.com/ubi9/ubi@sha256:…`. Only
  **linux/amd64** is fetched (a multi-platform image is resolved to its amd64
  manifest). Public images from any OCI registry (Docker Hub, GitHub, Red Hat,
  quay.io, …) work anonymously; each upstream registry keeps its own namespace
  on the high side, so `docker.io/...` and `ghcr.io/...` content never mixes.
  Layers are content-addressed, so a base layer shared by several images is
  bundled and stored once.

  The tag position also takes a **version constraint**, resolved against the
  upstream tag list at collect time to the newest matching version:

  ```text
  golang:1.26.x          # newest 1.26 patch release (e.g. 1.26.3)
  golang:<2.0.0          # newest version below 2.0.0
  golang:>=1.24, <2.0    # a range ([hashicorp/go-version] syntax)
  ```

  Only plain numeric tags (`1.26.3`, `v2.0`, `17`) are considered, so a variant
  tag like `1.26.3-alpine` never outranks the plain image — pin variants
  explicitly. The bundle records the resolved concrete tag, and a **scheduled**
  collect re-resolves on every run, so `golang:1.26.x` keeps tracking new patch
  releases through the diode automatically.

- **AI Models** — two kinds of Hugging Face references, one per line each.
  **GGUF models**, container-style:

  ```text
  hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0
  bartowski/Llama-3.2-1B-Instruct-GGUF:Q8_0     # hf.co/ prefix optional
  unsloth/gpt-oss-20b-GGUF                       # no tag = default quantization
  ```

  The repository names the Hugging Face model; the tag selects a
  **variant/quantization**, resolved by Hugging Face itself (the same
  Ollama-compatible API behind `ollama run hf.co/…`), so it works for any GGUF
  model repository that Ollama accepts. The manifest, model file, chat
  template, params, and license are fetched with their SHA-256s verified and
  stored content-addressed — a license or model blob shared between variants
  is bundled and stored once.

  **Full repositories**, for safetensors releases that publish no GGUF
  (`openai/gpt-oss-20b`, say) — consumed on the high side by vLLM,
  transformers, and `hf download` through the Hub API:

  ```text
  openai/gpt-oss-20b                # branch main, pinned to its commit
  openai/gpt-oss-20b@main           # same, explicit
  org/model@<commit-hash>           # pin an exact revision
  ```

  Every file is mirrored at the pinned commit (large LFS files verified
  against their upstream SHA-256s) into the same content-addressed store. A
  **"Skip repository paths"** field excludes subtrees you don't want to carry
  across the diode — e.g. `original, metal` skips gpt-oss's two extra full
  copies of the weights and roughly third-sizes the bundle.

  For both kinds: gated or private models need `ARTIGATE_HF_TOKEN` (a Hugging
  Face access token) set on the low side; `--hf-endpoint` points the collector
  at a private mirror instead of `https://huggingface.co`.

[hashicorp/go-version]: https://github.com/hashicorp/go-version

For APT and RPM, a **"Newest version only"** checkbox (on by default) mirrors just
the latest version of each package; untick it to mirror every version.

- **Uploads** — arbitrary files, no ecosystem behind them: pick a folder name
  and one or more files (`POST /admin/uploads/collect`, multipart form data).
  The high side serves them at `/uploads/<folder>/<name>`, lists them on its
  dashboard under **Uploads**, and — uniquely among the streams — lets the
  operator **delete** a file there again (an emptied folder disappears with its
  last file). Re-uploading a name replaces the file; uploads always ship in
  full (the forwarded-content index is not consulted), so a file deleted on
  the high side comes back by simply uploading it again. Uploads cannot be
  scheduled — there is no upstream to re-pull.

### Scheduling

Each ecosystem page can turn its inputs into a **recurring pull**: set an interval
(hours or days) and click *Add schedule* — e.g. re-pull a `go.mod` or a
requirements list every day. Schedules run in the background (due schedules are
checked every `--watch-interval`, default one minute) and can be paused, run
immediately, or deleted from the same page.

### Export deduplication

A collect only bundles — and where possible only downloads — content it has not
already sent. The low side records every forwarded file (bundle path plus
content hash), per stream, in a small SQLite index (`<root>/exported.db`):

- **Nothing new** — when a collect resolves to a file set that is *entirely*
  already-forwarded, no bundle is written and no bundle number is consumed; the
  dashboard (and a schedule's status) simply reports "no new content".
- **Partly new** — the bundle's archive carries only the new files. The rest are
  listed in the manifest as *prior* references, which the high side verifies
  against its accumulated repository instead of receiving again. A daily
  schedule over a slowly-changing mirror therefore sends only the churn.
- **Download skip** — collectors whose upstream declares each file's SHA-256
  before the bytes are fetched (APT `Packages` indexes, RPM `primary.xml`,
  container image digests, Hugging Face LFS files) check the index first and
  skip the download entirely. pip-, mvn-, npm-, and go-driven fetches still
  download as before (their upstreams declare no usable pre-download SHA-256;
  the Go module cache already avoids re-downloads on its own), and their
  unchanged files are still deduplicated from the bundle after hashing.

Every collect request accepts `"force": true` to bypass the index and produce a
full, self-contained bundle — the disaster-recovery path when a high side is
rebuilt from scratch or bundles were pruned before it caught up. Note that a
delta bundle imports only on a high side that holds the stream's earlier
bundles; importing out of order fails with a "prior file … not in the
repository" error naming the missing content.

The index is independent of the re-export archive: re-transmitting a bundle
never consults or updates it, and if the index is ever unavailable a collect
simply downloads and exports as normal rather than wrongly skipping.

### Status and re-export

The **Status** page shows each stream's next bundle number and the exported
bundles (with sizes, and whether each is still staged in the export directory
or already sent). If the high side reports a bundle missing, use its
re-transmit form to regenerate that bundle number or range from the archive
(`<root>/bundles`), which keeps a copy of every bundle ever exported.

## Data diode

Carry each bundle's three files across the diode into the high side's landing
directory. The high side imports each **stream** strictly in order. An
out-of-order bundle (e.g. `go-bundle-000043` before `000042`) is quarantined, not
rejected, and imported automatically once the gap is filled; duplicates and old
replays are ignored. Future gaps are capped at 10,000 sequences; unsupported,
excessively-future, or cryptographically invalid bundles move to
`<root>/rejected` and do not block the other streams.

### HTTP transport (optional)

For diodes (or diode proxies) that speak HTTP instead of moving files, both
sides also support an HTTP transport, configured entirely by environment
variables — the folder flow stays the default:

| Variable | Side | Meaning |
|---|---|---|
| `ARTIGATE_DIODE_URL` | low | endpoint bundles are uploaded to after every export and re-export (`PUT <url>/<file>`, archive first) |
| `ARTIGATE_DIODE_INGEST` | high | `on` accepts bundle uploads at `PUT/POST /diode/<file>` into the landing directory (default `off`) |
| `ARTIGATE_DIODE_TOKEN` | both | shared bearer token, at least 32 bytes and required whenever HTTP diode transport is enabled |

```bash
# low side — upload each bundle to the diode proxy (or directly to the high side)
export ARTIGATE_DIODE_URL=https://artigate-high.local/diode
export ARTIGATE_DIODE_TOKEN=…

# high side — accept uploads into the landing directory
export ARTIGATE_DIODE_INGEST=on
export ARTIGATE_DIODE_TOKEN=…
```

After a successful upload the low side clears the bundle from the export
directory (it shows as *sent* on the Status page), exactly like a folder diode
moving the files out; the archive copy is kept for re-transmits, which also go
out over HTTP. A failed upload never loses a bundle — the collect still
succeeds, the dashboard (and a schedule's status) reports the upload error,
and the bundle stays staged for a re-transmit from the Status page. A complete
bundle received over HTTP is imported immediately rather than on the next scan
tick. Completion notifications use one coalescing worker rather than creating a
goroutine per upload.

The transport carries no trust: uploads land in the landing directory exactly
as diode-carried files would, and the importer still verifies the Ed25519
signature, per-stream sequencing, and every file hash. The token only protects
the high side's disk from unauthenticated uploads — leave the ingest off (the
default) unless you use the HTTP transport. Anything that can `PUT` a file
works as a sender, e.g.:

```bash
curl -fT go-bundle-000042.tar.gz -H "Authorization: Bearer $TOKEN" \
  https://artigate-high.local/diode/go-bundle-000042.tar.gz
```

Ingress is bounded before verification: archives are limited to 64 GiB,
manifests to 16 MiB, signatures to 4 KiB, and pending/quarantined/rejected files
to 128 GiB in aggregate. The archive bound is no ceiling on what a collect can
carry: a collect whose new content would overflow it — a full safetensors
repository easily does — is split automatically into consecutive sequenced
bundles, each within the limit. The content ships in *part* bundles first and
the ecosystem metadata arrives in the final bundle, which references the parts'
files, so the model appears on the high side exactly once, complete. With the
built-in UDP pitcher enabled, the split budget also respects the wire's
block-count bound for the configured FEC geometry, so every bundle produced is
guaranteed transmittable as configured.

### Built-in UDP diode transport (optional)

ArtiGate can also drive a **hardware diode directly** — a one-way fiber
between a spare NIC on each side, no diode proxy software at all. The low
side's **pitcher** transmits every bundle as rate-limited, Reed-Solomon-coded
IPv6 link-local multicast (multicast because a one-way link can never resolve
the receiver's MAC address); the high side's **catcher** reassembles the
datagrams into the landing directory and imports immediately. Naming the
interface is what enables each side — ArtiGate configures the NIC itself
(MTU 9000, deep TX/RX queues, IPv6 `addr-gen-mode eui64` link-local, link up):

| Variable | Side | Meaning |
|---|---|---|
| `ARTIGATE_PITCHER_INTERFACE` | low | dedicated diode TX NIC (e.g. `eth1`); enables the pitcher |
| `ARTIGATE_PITCHER_RATE_MBIT` | low | max wire rate, default `800` — a one-way link has no congestion control, so stay below what the catcher absorbs |
| `ARTIGATE_PITCHER_FEC_DATA` / `_FEC_PARITY` | low | Reed-Solomon geometry, default `32`+`8`: any 8 of every 40 datagrams may be lost harmlessly |
| `ARTIGATE_PITCHER_TXQUEUELEN` | low | TX NIC queue length, default `10000` — raise if the driver drops on bursts |
| `ARTIGATE_CATCHER_INTERFACE` | high | dedicated diode RX NIC; enables the catcher |
| `ARTIGATE_CATCHER_RCVBUF_MB` | high | receive buffer (MiB), default `64`, set via `SO_RCVBUFFORCE` |
| `ARTIGATE_{PITCHER,CATCHER}_{MTU,GROUP,PORT,NETSETUP}` | both | MTU `9000`, group `ff02::4147`, port `4147`; `NETSETUP=off` when the host pre-configures the NIC |

Loss beyond the parity budget expires the transfer on the catcher (nothing
partial ever lands) and is recovered the usual way: the gap shows on the high
side's `/admin/missing`, and a low-side re-export re-transmits it from the
archive. The retry is cheap even for huge bundles, because recovery is
per-block: the catcher keeps an expired transfer's completed FEC blocks beside
the landing directory (for 24 hours), and the re-sent file — same name, same
content hash — resumes from them, so each attempt only has to deliver the
blocks every earlier attempt lost. A multi-gigabyte model bundle therefore
converges on a lossy link instead of demanding one perfect pass. In Docker
both sides need `network_mode: host`, `cap_add: [NET_ADMIN]`, and a root user
— see `examples/docker-compose-diode-low.yml`,
`examples/docker-compose-diode-high.yml`, and the
[data-diode documentation](https://define42.github.io/ArtiGate/data-diode/)
for tuning guidance.

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
go env -w GOPROXY=https://artigate-high.local/go,off
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

```ini
# NPM — ~/.npmrc (or /etc/npmrc)
registry=https://artigate-high.local/npm/
audit=false
fund=false
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

```bash
# Containers — the pull name embeds the upstream registry
docker pull artigate-high.local/docker.io/library/alpine:3.20
docker pull artigate-high.local/ghcr.io/org/app:v1
```

```bash
# AI models — Ollama pulls straight from the mirror (add --insecure for plain HTTP)
ollama pull artigate-high.local/unsloth/gpt-oss-20b-GGUF:Q4_0
ollama run  artigate-high.local/unsloth/gpt-oss-20b-GGUF:Q4_0

# ...or download the raw GGUF for vLLM / llama.cpp
curl -fL -o gpt-oss-20b-GGUF-Q4_0.gguf \
  https://artigate-high.local/hf/unsloth/gpt-oss-20b-GGUF/Q4_0.gguf
HF_HUB_OFFLINE=1 vllm serve ./gpt-oss-20b-GGUF-Q4_0.gguf

# Full repositories (safetensors) — every huggingface_hub client, via HF_ENDPOINT
export HF_ENDPOINT=https://artigate-high.local
vllm serve openai/gpt-oss-20b
hf download openai/gpt-oss-20b
```

Docker/podman require HTTPS for remote registries — enable TLS on the high side,
or, for a plain-HTTP mirror, trust it explicitly (then `systemctl restart docker`).
The high-side **"Set me up"** guide renders this block ready to copy, with the
actual host and port filled in — for APT it even offers a per-suite release
picker with component checkboxes:

```json
// /etc/docker/daemon.json
{
  "insecure-registries": [
    "artigate-high.local:8081"
  ]
}
```

On the high side, use **only** ArtiGate as the source — don't add
`--extra-index-url`, `mavenCentral()`, or other upstreams, which reopens
dependency-confusion risk. If a repo is published unsigned, relax the client's
signature check (`repo_gpgcheck=0`, `[trusted=yes]`, etc.).

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

> The shipped Compose stack requires this value. Put it in the gitignored
> `.env` file as a single-quoted value so the `$` characters remain literal;
> see `.env.example`. Direct binary/systemd deployments may still leave auth
> unset only when strict network controls protect the low-side control plane.

## Notes and limitations

- The **low-side dashboard** is a privileged control plane — it holds the signing
  key, so anyone who can reach it can have arbitrary content signed and sent across
  the diode. It requires a session login (`ARTIGATE_LOW_AUTH`, see above); when it
  is not set the low side **refuses to start on a non-loopback listen address**.
  Bind `--listen` to loopback, set `ARTIGATE_LOW_AUTH`, or — only behind a trusted
  TLS-authenticating reverse proxy — set `ARTIGATE_LOW_ALLOW_UNAUTHENTICATED=true`
  to acknowledge that layer. The **high-side dashboard** serves only
  already-verified public mirror content and is unauthenticated, so bind it to
  localhost or a trusted network; its state-changing admin endpoints
  (`POST /admin/uploads/delete`, `/admin/import`) are additionally restricted to
  loopback callers unless `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN=on` (set this when a
  published-port or reverse-proxy hop makes local admin appear non-loopback, and
  keep the listener itself restricted at the host).
- **Go**: no sumdb mirroring — use `GOSUMDB=off` on the high side and rely on your
  committed `go.sum` plus the signed bundles.
- **Python**: wheels only (no sdists), always enforced. A package with no
  compatible wheel fails the collect; pin a wheel-bearing version or exclude it.
- **Java/Maven**: release versions only; SNAPSHOT and dynamic/range versions are
  rejected.
- **NPM**: registry tarballs only — dependencies resolved to git or file URLs
  are skipped (and reported). Resolution needs npm 7 or newer on the low side
  (lockfile v2+). The high side regenerates all packument metadata from each
  tarball's own embedded `package.json`; `dist-tags` carries only `latest`
  (the highest mirrored release). Set `audit=false` in clients — the advisory
  endpoint needs the public registry.
- **APT/RPM**: mirror the newest version of each package by default; untick
  "Newest version only" to mirror every version. RPM collects default to
  x86_64 + noarch packages. RPM `.zck`-only indexes aren't supported (use
  `.gz`/`.xz`). Each collect re-syncs against upstream, but the export dedup
  index keeps it from re-downloading or re-sending what already crossed.
- **Signing the served repos** is optional (`--apt-gpg-key`/`--rpm-gpg-key`);
  otherwise APT/RPM repositories are published unsigned.
- **Containers**: linux/amd64 only, anonymous pulls of public images only, and
  registries on non-standard ports can't be mirrored (the port can't appear in
  the high-side pull name). `--container-registry host=baseURL` on the low side
  redirects a registry's API to a private mirror/proxy. The high-side registry
  is read-only (no push).
- **AI Models**: GGUF references use Hugging Face's Ollama-compatible endpoint
  (the repos `ollama run hf.co/…` accepts; sharded/split GGUFs are not
  supported upstream); tags are quantization names resolved at collect time,
  and digest pins are not supported. Ollama requires HTTPS — enable TLS on the
  high side or pass `--insecure` to `ollama pull`. The raw GGUF is also served
  at `/hf/<org>/<model>/<variant>.gguf` for llama.cpp and vLLM's GGUF loader
  (with vLLM set `HF_HUB_OFFLINE=1`; without `--tokenizer` it converts the
  tokenizer from the GGUF, which slows the first start). Full-repository
  snapshots serve the download subset of the Hub API (`/api/models/…` and
  `…/resolve/…`) — enough for `HF_ENDPOINT`-pointed vLLM, transformers, and
  `hf download`, but not search or the write APIs. Snapshots are pinned to a
  commit; re-collecting a branch adds the new commit and moves the branch
  name to it (old snapshots stay pullable by commit hash).
- Low-side collects for different ecosystems run concurrently; the high side never
  runs `go`/`pip`/`mvn` and does no upstream fetching.

## End-to-end tests

Beyond the offline unit suite (`go test ./...`), an opt-in end-to-end suite
builds the real binary, starts a low+high pair wired over the HTTP diode
transport, collects **every stream from its real upstream** (PyPI,
proxy.golang.org, Maven Central, npmjs, cli.github.com, Docker Hub,
huggingface.co), and validates each with its real client tool — pip, `go`,
`mvn`+`java`, npm+node, `apt-get`+`dpkg-deb`, `dnf`+`rpm`, `docker`,
huggingface_hub's CLI, and `curl`:

```bash
make e2e        # == go test -tags e2e -v -count=1 -timeout 25m ./e2e
```

It needs network access and the client toolchains on PATH; a missing tool
skips its test locally (CI sets `ARTIGATE_E2E_REQUIRE_ALL=1` to fail
instead). CI runs it on every PR via `.github/workflows/e2e.yml`. See
`e2e/doc.go` for all knobs (`ARTIGATE_E2E_BIN`, `ARTIGATE_E2E_WORKDIR`,
`ARTIGATE_E2E_KEEP`, `ARTIGATE_E2E_HF_GGUF`).

## Documentation

The full manual — architecture, per-ecosystem guides, configuration and HTTP
API references, deployment and troubleshooting — is at
**<https://define42.github.io/ArtiGate/>** (source under `page/`, built with
MkDocs Material). ArtiGate is released under the [Apache 2.0 license](LICENSE).
