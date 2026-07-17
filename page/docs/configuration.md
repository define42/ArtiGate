# Configuration reference

Exhaustive reference for the single `artigate` binary: its four subcommands, every command-line flag, and every environment variable. All defaults below are copied verbatim from the source. For the concepts behind these knobs see [TLS / HTTPS](tls.md), [Security & trust](security.md), and [Deployment](deployment.md).

## Subcommand summary

One binary, four subcommands. The first argument selects the subcommand; each parses its own flag set (`flag.ExitOnError`), so an unknown flag or `-h`/`--help` prints that subcommand's usage and exits. Invoking with no argument prints the top-level usage and exits `2`.

| Subcommand | Purpose | Synopsis |
|---|---|---|
| `keygen` | Generate the Ed25519 signing keypair | `artigate keygen [--private low.ed25519] [--public high.ed25519.pub]` |
| `hashpw` | Produce an argon2id hash for `ARTIGATE_LOW_AUTH` | `artigate hashpw [--user alice] [--password …]` |
| `low` | Internet-side exporter (fetch, verify, sign, export) | `artigate low --private-key low.ed25519 [flags…]` |
| `high` | Air-gapped read-only server (import, verify, serve) | `artigate high --public-key high.ed25519.pub [flags…]` |

!!! note
    Logging is global: `log.LstdFlags | log.Lmicroseconds | log.LUTC` (UTC, microsecond timestamps). Any required-flag or config-validation failure is fatal (`log.Fatal`, exit 1) at startup.

---

## `keygen`

Generates an Ed25519 keypair with `ed25519.GenerateKey`. The private key is written base64-encoded with mode `0o600`; the public key base64-encoded with mode `0o644`. Each file holds the base64 string plus a trailing newline; parent directories are created `0o755`.

```bash
artigate keygen --private low.ed25519 --public high.ed25519.pub
```

| Flag | Default | Meaning |
|---|---|---|
| `--private` | `low.ed25519` | Private key output path |
| `--public` | `high.ed25519.pub` | Public key output path |

!!! warning
    Keep the **private** key on the low side only; install only the **public** key on the high side. This trust split is the core of the diode's integrity — see [Security & trust](security.md).

---

## `hashpw`

Prints an argon2id PHC-format hash to paste into `ARTIGATE_LOW_AUTH`. The password comes from `--password`; if that is empty, one line is read from stdin (trailing `\r`/`\n` stripped) so the secret never lands in shell history or process arguments. An empty password is fatal.

```bash
# Reads the password from stdin (recommended):
artigate hashpw --user alice
```

| Flag | Default | Meaning |
|---|---|---|
| `--user` | `""` | Username to prefix; when set prints `user:hash`, otherwise prints just `hash` |
| `--password` | `""` | Password to hash; if empty, read one line from stdin |

Output format:

```text
$argon2id$v=19$m=65536,t=3,p=1$<b64salt>$<b64key>
```

With `--user alice` the line becomes `alice:$argon2id$v=19$m=65536,t=3,p=1$…$…`. New hashes use argon2id parameters `m=65536` KiB (64 MiB), `t=3`, `p=1`.

---

## `low`

Internet-side exporter. Requires `--private-key` (fatal if empty). It is an **exporter, not a proxy**: any non-admin, non-UI path returns 404. When `--watch-interval > 0` the watch scheduler goroutine starts before serving. See [Low side](low-side.md).

```bash
artigate low \
  --private-key low.ed25519 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `:8080` | HTTP listen address |
| `--root` | `/var/lib/artigate-low` | Low-side working directory |
| `--export-dir` | `/var/spool/diode-out` | Directory where signed bundles are written |
| `--private-key` | `""` (**required**) | Base64 Ed25519 private key path |
| `--upstream-goproxy` | `https://proxy.golang.org,direct` | GOPROXY for the low-side fetcher; use `direct` to fetch from GitHub/VCS |
| `--gosumdb` | `sum.golang.org` | GOSUMDB for the low-side fetcher; also the checksum database whose records go collects capture for high-side clients (`off` disables mirroring) |
| `--goprivate` | `""` | GOPRIVATE for private modules |
| `--gonosumdb` | `""` | GONOSUMDB for private modules |
| `--gonoproxy` | `""` | GONOPROXY for private modules |
| `--govcs` | `*:git` | GOVCS for the low-side fetcher |
| `--go` | `go` | `go` command path |
| `--gotoolchain` | `auto` | GOTOOLCHAIN for the fetcher; `auto` lets `go` download a newer toolchain when a module requires one, `local` pins the installed toolchain |
| `--python` | `python3` | Python interpreter used for `pip download` |
| `--pypi-json` | `""` (→ `https://pypi.org/pypi`) | Index JSON API base that opted-in [sdists](ecosystems/python.md#opt-in-sdists-for-packages-that-publish-no-wheel) are resolved from |
| `--maven` | `mvn` | Maven command used to resolve Java/Maven artifacts |
| `--npm` | `npm` | npm command used to resolve NPM package graphs |
| `--npm-registry` | `""` | Registry URL npm resolves against (passed as `--registry`; empty uses npm's own config) |
| `--container-registry` | `""` | Comma-separated `host=baseURL` registry overrides (e.g. `docker.io=https://mirror.example.com`); private-registry logins go in `ARTIGATE_CONTAINER_AUTH` instead |
| `--hf-endpoint` | `""` (→ `https://huggingface.co`) | Hugging Face endpoint AI models are fetched from (a private Hub mirror, or a test server) |
| `--crates-index` | `""` (→ `https://index.crates.io`) | Sparse registry index Rust crates are resolved from |
| `--terraform-registry` | `""` (→ `https://registry.terraform.io`) | Registry Terraform providers/modules are fetched from; use `https://registry.opentofu.org` for OpenTofu |
| `--nuget-source` | `""` (→ `https://api.nuget.org/v3/index.json`) | NuGet v3 service index packages are resolved from |
| `--osv-upstream` | `""` (→ `https://osv-vulnerabilities.storage.googleapis.com`) | Base URL OSV vulnerability databases (per-ecosystem `all.zip` archives) are fetched from |
| `--conda-channel-base` | `""` (→ `https://conda.anaconda.org`) | Base URL bare conda channel names resolve under (a full channel URL in the collect bypasses it) |
| `--rubygems-url` | `""` (→ `https://rubygems.org`) | Gem server gems and their compact index are fetched from |
| `--composer-repo` | `""` (→ `https://repo.packagist.org`) | Composer repository package metadata and dists are resolved from |
| `--vsx-registry` | `""` (→ `https://open-vsx.org`) | Open VSX registry VS Code extensions are fetched from |
| `--galaxy-server` | `""` (→ `https://galaxy.ansible.com`) | Galaxy server Ansible collections are fetched from |
| `--cran-mirror` | `""` (→ `https://cloud.r-project.org`) | CRAN mirror R packages are fetched from |
| `--git` | `git` | git command used to fetch Terraform modules from `git::` sources |
| `--watch-interval` | `60s` | How often the scheduler checks for due watches; `0` disables scheduled watches |

!!! note
    `GOPRIVATE`, `GONOSUMDB`, `GONOPROXY`, and `GOTOOLCHAIN` are exported only when non-empty (the default `GOTOOLCHAIN=auto` is exported); `GOPROXY`, `GOSUMDB`, and `GOVCS` are always exported (even if set to empty). `GIT_TERMINAL_PROMPT=0` is always forced (no interactive git password prompts) and `GO111MODULE=on` is always set.

`--watch-interval` is a Go `time.Duration`, so it accepts `30s`, `10m`, `2h`, etc. On startup the low server creates `<root>`, `<export-dir>`, and `<root>/gopath/pkg/mod/cache/download` (`0o755`), opens `<root>/watches.db` and `<root>/exported.db` (SQLite), and loads or creates `<root>/low-state.json` (`0o600`).

### Routes

- `POST /admin/{go,python,maven,apt,rpm,hf,containers,npm,crates,terraform,helm,nuget,apk,conda,rubygems,composer,vsx,galaxy,cran,git,osv,uploads}/collect` — one endpoint per stream (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate; every JSON body accepts `"force": true` to bypass export dedup). `uploads` takes `multipart/form-data` instead of JSON
- `POST /admin/reexport?stream=go&sequences=42,45-47` (`stream` defaults to `go`; also accepts a JSON body `{"stream":"go","sequences":"42,45-47"}`)
- `GET /admin/bundles`
- `GET /admin/watches`, `POST /admin/watches`, `POST /admin/watches/{update,run,enable,disable,delete}` — the [watch scheduler](scheduling.md)
- `GET /healthz` → `ok\n` (liveness; always open, even with auth enabled)
- `GET /readyz` → `200 ok` / `503` with the failing checks — schedule store, export spool, stuck diode transfers (always open; `?verbose` lists every check)
- `GET /metrics` → Prometheus telemetry (always open)

!!! warning
    Without `ARTIGATE_LOW_AUTH`, the dashboard **and** all mutating `/admin/*` endpoints are unauthenticated — anyone who can reach the listener can drive collects and re-exports. Bind to localhost/a trusted network or enable auth. See [Security & trust](security.md).

---

## `high`

Air-gapped read-only server. Requires `--public-key` (fatal if empty). When `--import-interval > 0` the import loop goroutine starts before serving. The high side never invokes `go`/`pip`/`mvn`/`npm`, never fetches upstream, and is **never authenticated**. See [High side](high-side.md).

```bash
artigate high \
  --public-key high.ed25519.pub \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `:8080` | HTTP listen address |
| `--root` | `/var/lib/artigate-high` | High-side repository root |
| `--landing` | `/var/spool/diode-in` | Directory where diode-delivered bundles arrive |
| `--quarantine` | `""` (defaults to `<root>/quarantine`) | Directory for out-of-order future bundles |
| `--public-key` | `""` (**required**) | Base64 Ed25519 public key path |
| `--import-interval` | `10s` | Bundle import scan interval; `0` disables background import |
| `--apt-gpg-key` | `""` | GPG key id used to sign regenerated APT repositories (InRelease); unset serves them unsigned |
| `--rpm-gpg-key` | `""` | GPG key id used to sign regenerated RPM repositories (repomd.xml.asc); unset serves them unsigned |
| `--apk-rsa-key` | `""` | PEM RSA private key path used to sign regenerated Alpine APKINDEX files; unset serves them unsigned |
| `--apk-key-name` | `artigate.rsa.pub` | Filename Alpine clients install the APK signing public key under (`/etc/apk/keys/<name>`) |

!!! note
    An empty `--quarantine` resolves to `<root>/quarantine` inside `NewHighServer`. `--import-interval` is a `time.Duration`; `0` disables the background importer but manual `POST /admin/import` still works.

### Routes

- `POST /admin/import` (loopback callers only unless `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN` is on)
- `POST /admin/uploads/delete` — remove one mirrored [upload](ecosystems/uploads.md) (same loopback restriction)
- `GET /admin/missing`
- `GET /admin/status`
- `GET /healthz` (liveness)
- `GET /readyz` → `200 ok` / `503` with the failing checks — blocked streams, undrained backlog, stalled/failing import passes, exhausted transport quota (`?verbose` lists every check)
- `GET /metrics` → Prometheus telemetry
- `PUT|POST /diode/<bundle-file>` — bundle ingest, only when `ARTIGATE_DIODE_INGEST=on` (403 otherwise)

---

## Environment variables

There are **no** environment variables for `keygen` or `hashpw`. The TLS variables and the failure-webhook variables apply to **both** `low` and `high` (both call the same `tlsConfigFromEnv` / webhook setup). The auth and cookie variables apply to the **low side only** — the high side has no auth. The diode-transport variables split by side (`ARTIGATE_DIODE_URL` low, `ARTIGATE_DIODE_INGEST` high, the token both; `ARTIGATE_PITCHER_*` low, `ARTIGATE_CATCHER_*` high), `ARTIGATE_HF_TOKEN` is low-side only, and `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN` is high-side only.

### Low-side authentication

| Variable | Default | Meaning |
|---|---|---|
| `ARTIGATE_LOW_AUTH` | unset (auth disabled) | One or more `username:<argon2id-hash>` credentials, separated by `;` or newlines (`\n`/`\r`) — **not commas** |
| `ARTIGATE_LOW_COOKIE_SECURE` | `auto` | Session cookie `Secure` attribute: `auto` follows ArtiGate's own TLS; `true`/`false` override |
| `ARTIGATE_LOW_ALLOW_UNAUTHENTICATED` | `off` | Without `ARTIGATE_LOW_AUTH`, the low side **refuses to start on a non-loopback `--listen` address**; setting `1`/`true`/`on`/`yes` acknowledges a trusted authenticating reverse proxy in front and starts anyway (with a startup warning). Any other value is fatal |

When `ARTIGATE_LOW_AUTH` yields at least one credential, the dashboard requires a form login and sessions are carried in an encrypted, signed cookie (`artigate_session`, 12 hours, `HttpOnly`, `SameSite=Lax`). Keys persist in `<root>/session.key` (`0o600`, 96 bytes) so sessions survive a restart. `/healthz`, `/readyz`, and `/metrics` stay open and a **Log out** button appears.

Parsing rules and gotchas:

- Each hash must start with `$argon2id$`, else: `credential for "<user>" is not an argon2id hash`.
- A malformed entry (no colon, or empty user/hash) is fatal: `invalid ARTIGATE_LOW_AUTH entry (…)`.
- **Fail-closed:** a non-empty value that parses to zero valid credentials (e.g. a stray `;` or whitespace from compose quoting) is fatal — `ARTIGATE_LOW_AUTH is set but contains no valid credentials` — rather than silently leaving the dashboard open.
- **Compose gotcha:** in `docker-compose.yml` each `$` must be written `$$` (Compose interpolates `$`). Not needed for single-quoted shell `export`s.

`ARTIGATE_LOW_COOKIE_SECURE` is trimmed and lowercased:

| Value | Result |
|---|---|
| `""` / `auto` | Follow TLS (`Secure=true` unless `ARTIGATE_TLS_MODE=unencrypted`) |
| `1` / `true` / `yes` / `on` | `Secure=true` |
| `0` / `false` / `no` / `off` | `Secure=false` |
| anything else | Fatal: `invalid ARTIGATE_LOW_COOKIE_SECURE "…" (want auto, true, or false)` |

!!! tip
    Set `ARTIGATE_LOW_COOKIE_SECURE=true` when ArtiGate serves plain HTTP behind a TLS-terminating reverse proxy, so the session cookie is still marked `Secure`. It only takes effect when `ARTIGATE_LOW_AUTH` is set (otherwise there is no session cookie).

### Diode transport (HTTP)

The optional HTTP transfer between the sides — see [Deployment](deployment.md) for semantics and [Security & trust](security.md) for the trust notes.

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_DIODE_URL` | low | unset (folder flow) | HTTP endpoint bundles are uploaded to after every export and re-export (`PUT <url>/<file>`). Must parse as an `http`/`https` URL or startup fails. On success the bundle is cleared from the export dir; on failure it stays staged and the error is reported on the collect result |
| `ARTIGATE_DIODE_INGEST` | high | `off` | `on`/`1`/`true`/`yes` accepts bundle uploads at `PUT/POST /diode/<file>` into the landing directory; any other non-off value is fatal |
| `ARTIGATE_DIODE_TOKEN` | both | unset | Shared bearer token: at least 32 bytes, no whitespace, and required whenever `ARTIGATE_DIODE_URL` or `ARTIGATE_DIODE_INGEST=on` enables HTTP transport; compared in constant time |

### Built-in UDP data diode

The direct one-way-fiber transport — see [Built-in UDP diode](data-diode.md) for how it works, Docker permissions, and tuning. Naming the interface enables each side; every value is validated at startup and a bad one is fatal. `ARTIGATE_DIODE_URL` and `ARTIGATE_PITCHER_INTERFACE` are mutually exclusive.

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_PITCHER_INTERFACE` | low | unset (disabled) | Dedicated diode TX NIC; enables the pitcher |
| `ARTIGATE_PITCHER_RATE_MBIT` | low | `800` | Max wire rate in Mbit/s (1–100000), Ethernet/IP/UDP framing included |
| `ARTIGATE_PITCHER_MTU` | low | `9000` | Interface MTU (1280–65536); datagrams are sized to it and never fragment |
| `ARTIGATE_PITCHER_TXQUEUELEN` | low | `10000` | Interface TX queue length |
| `ARTIGATE_PITCHER_GROUP` | low | `ff02::4147` | IPv6 multicast destination group |
| `ARTIGATE_PITCHER_PORT` | low | `4147` | UDP destination port |
| `ARTIGATE_PITCHER_FEC_DATA` | low | `32` | Reed-Solomon data shards per block (1–255, data+parity ≤ 256) |
| `ARTIGATE_PITCHER_FEC_PARITY` | low | `8` | Reed-Solomon parity shards per block — the per-block loss budget |
| `ARTIGATE_PITCHER_NETSETUP` | low | `on` | `on`: ArtiGate configures the NIC (eui64 link-local, MTU, txqueuelen, TX rings, link up); `off`: host-preconfigured |
| `ARTIGATE_CATCHER_INTERFACE` | high | unset (disabled) | Dedicated diode RX NIC; enables the catcher |
| `ARTIGATE_CATCHER_RCVBUF_MB` | high | `64` | UDP receive buffer in MiB (1–4096), set via `SO_RCVBUFFORCE` when permitted |
| `ARTIGATE_CATCHER_MTU` | high | `9000` | Interface MTU; must be ≥ the pitcher's |
| `ARTIGATE_CATCHER_GROUP` | high | `ff02::4147` | IPv6 multicast group to join (must match the pitcher) |
| `ARTIGATE_CATCHER_PORT` | high | `4147` | UDP port (must match the pitcher) |
| `ARTIGATE_CATCHER_NETSETUP` | high | `on` | `on`: ArtiGate configures the NIC (eui64, MTU, RX rings, link up) and best-effort raises `net.core.netdev_max_backlog`; `off`: host-preconfigured |

### Hugging Face (AI models)

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_HF_TOKEN` | low | unset (anonymous) | Hugging Face access token for gated/private models, sent as a Bearer header; read at collect time, so it rotates without a restart |

### Container registries

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_CONTAINER_AUTH` | low | unset (anonymous) | Comma-separated `host=user:password` logins for private container registries (e.g. `ghcr.io=bot:ghp_xxx`); read at collect time, so it rotates without a restart, and the only credential source scheduled watches use — see [Private registries](ecosystems/containers.md#private-registries) |

### Upstream mirrors (Go, git, APT, RPM, Alpine)

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_UPSTREAM_AUTH` | low | unset (anonymous) | Comma-separated `host=user:password` logins for private git, APT, RPM, Alpine, and Conda upstreams; the key is the upstream's exact host, `host:port` included (e.g. `git.example.com=bot:token,apt.example.com=bot:secret`). Sent as HTTP Basic to the mirror host it is keyed to. Read at collect time, so it rotates without a restart, and the only credential source scheduled watches use |
| `ARTIGATE_GO_AUTH` | low | unset (anonymous) | Comma-separated `host=user:password` logins for private Go module hosts (the key is the VCS host, e.g. `gitlab.example.com=bot:token`); injected into the `go`/`git` subprocesses via a per-collect netrc + git credential helper, and each host is treated as private (`GOPRIVATE`/`GONOSUMDB`/`GONOPROXY`) for that collect — which is why Go has its own variable instead of sharing `ARTIGATE_UPSTREAM_AUTH`. Same rotation and scheduled-watch role |

### Failure webhooks

Both sides can POST a small JSON document to an HTTP(S) endpoint when something goes wrong, so an alert reaches a channel without polling `/metrics`. Unset means disabled; a malformed URL is fatal at startup.

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_WEBHOOK_URL` | both | unset (disabled) | HTTP(S) endpoint failure events are POSTed to (`Content-Type: application/json`) |
| `ARTIGATE_WEBHOOK_TOKEN` | both | unset | Optional bearer token, sent as `Authorization: Bearer …` on every delivery |

| Event | Side | Fires when |
|---|---|---|
| `schedule_failed` | low | a [scheduled collect](scheduling.md) run fails (upstream error, panic, cancel) |
| `bundle_rejected` | high | a bundle is rejected on import or sorting (bad signature/hash, unsupported, too far ahead) |
| `gap_detected` | high | a stream becomes blocked because a later bundle arrived before the next expected one |

Every payload carries `event`, `side` (`low`/`high`), and an RFC 3339 `time`, plus event-specific fields — `schedule_failed` adds `stream`, `watch_id`, `label`, `error`; `bundle_rejected` adds `stream`, `bundle`, `reason`; `gap_detected` adds `stream`, `blocking_sequence`:

```json
{
  "event": "gap_detected",
  "side": "high",
  "time": "2026-07-14T12:00:00Z",
  "stream": "go",
  "blocking_sequence": 42
}
```

Delivery is **best-effort and fire-and-forget**: each event is one background POST with a 10-second overall timeout, a slow or unreachable receiver never blocks an import or a scheduler tick, and failures are logged rather than retried — the `/metrics` counters remain the durable record. `gap_detected` is edge-triggered (one notification per gap; the gap then ages via `artigate_high_gap_age_seconds` until it fills).

### High-side admin endpoints

| Variable | Side | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN` | high | `off` | The high side's state-changing admin endpoints (`POST /admin/import`, `POST /admin/uploads/delete`) answer only **loopback** callers by default; other callers get `403 admin endpoint restricted to local callers`. Set `1`/`true`/`on`/`yes` to permit remote callers when a published-port or reverse-proxy hop makes local admin appear non-loopback — and keep the listener itself restricted at the host. Any other value is fatal |

### TLS

`ARTIGATE_TLS_MODE` is lowercased and defaults to `unencrypted`. All string values are trimmed; `ARTIGATE_TLS_DOMAINS` is comma-split with empty parts dropped. Full mode-by-mode behaviour is in [TLS / HTTPS](tls.md).

| Variable | Applies (mode) | Default | Meaning |
|---|---|---|---|
| `ARTIGATE_TLS_MODE` | all | `unencrypted` | One of `unencrypted` / `acme` / `own-certificate` / `auto-generate-certificate`; any other value is fatal |
| `ARTIGATE_TLS_DOMAINS` | `acme` (required), `auto-generate-certificate` | empty | Comma-separated domains/IPs — ACME cert names or self-signed SANs. IPs become `IPAddresses`, names become `DNSNames`; empty in auto-gen mode falls back to `artigate.local` |
| `ARTIGATE_TLS_CERT` | `own-certificate` (required) | empty | PEM certificate path |
| `ARTIGATE_TLS_KEY` | `own-certificate` (required) | empty | PEM private-key path |
| `ARTIGATE_ACME_EMAIL` | `acme` | empty | ACME account email |
| `ARTIGATE_ACME_DIRECTORY` | `acme` | empty → Let's Encrypt | ACME server directory URL; sets `certmagic.DefaultACME.CA` when non-empty |
| `ARTIGATE_ACME_CA_ROOT` | `acme` | empty | Path to a PEM root CA to trust, for a private ACME server (e.g. step-ca) |
| `ARTIGATE_ACME_STORAGE` | `acme` | `<root>/acme` | Certificate cache directory |

Validation (all fatal at startup):

- `own-certificate` requires both `ARTIGATE_TLS_CERT` and `ARTIGATE_TLS_KEY` → `ARTIGATE_TLS_MODE=own-certificate requires ARTIGATE_TLS_CERT and ARTIGATE_TLS_KEY`.
- `acme` requires `ARTIGATE_TLS_DOMAINS` → `ARTIGATE_TLS_MODE=acme requires ARTIGATE_TLS_DOMAINS`.
- Unknown mode → `invalid ARTIGATE_TLS_MODE "…" (want unencrypted, acme, own-certificate, or auto-generate-certificate)`.

!!! note
    ACME uses the TLS-ALPN-01 challenge on ArtiGate's own `--listen` port (the ALPN protos are prefixed with `h2`, `http/1.1`); there is no separate `:80` listener and no HTTP→HTTPS redirect. `own-certificate` and `auto-generate-certificate` enforce `MinVersion: TLS 1.2`; the self-signed cert is ECDSA P-256, valid one year, organization `ArtiGate`, regenerated on every restart.

---

## Configuration surface at a glance

The file paths, listen addresses, and behaviour toggles are **flag-only**; TLS and low-side auth are **env-only**. There is deliberately no flag for TLS and no env var for paths/listen addresses.

- **Flags only:** `--listen`, `--root`, `--export-dir`, `--landing`, `--quarantine`, `--private-key`, `--public-key`, all `--go*`/toolchain/ecosystem-binary flags (including `--git`), the upstream overrides (`--pypi-json`, `--hf-endpoint`, `--crates-index`, `--terraform-registry`, `--nuget-source`, `--osv-upstream`, `--conda-channel-base`, `--rubygems-url`, `--composer-repo`, `--vsx-registry`, `--galaxy-server`, `--cran-mirror`, `--npm-registry`, `--container-registry`), `--watch-interval`, `--import-interval`, `--apt-gpg-key`, `--rpm-gpg-key`, `--apk-rsa-key`, `--apk-key-name`.
- **Env only:** `ARTIGATE_LOW_AUTH`, `ARTIGATE_LOW_COOKIE_SECURE`, `ARTIGATE_LOW_ALLOW_UNAUTHENTICATED`, `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN`, `ARTIGATE_TLS_*`, `ARTIGATE_ACME_*`, `ARTIGATE_DIODE_*`, `ARTIGATE_PITCHER_*`, `ARTIGATE_CATCHER_*`, `ARTIGATE_HF_TOKEN`, `ARTIGATE_CONTAINER_AUTH`, `ARTIGATE_GO_AUTH`, `ARTIGATE_UPSTREAM_AUTH`, `ARTIGATE_WEBHOOK_URL`, `ARTIGATE_WEBHOOK_TOKEN`.

See also: [Deployment](deployment.md) for production topologies, [Security & trust](security.md) for the trust model, and [TLS / HTTPS](tls.md) for the full TLS matrix.
