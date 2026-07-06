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
| `--gosumdb` | `sum.golang.org` | GOSUMDB for the low-side fetcher |
| `--goprivate` | `""` | GOPRIVATE for private modules |
| `--gonosumdb` | `""` | GONOSUMDB for private modules |
| `--gonoproxy` | `""` | GONOPROXY for private modules |
| `--govcs` | `*:git` | GOVCS for the low-side fetcher |
| `--go` | `go` | `go` command path |
| `--gotoolchain` | `auto` | GOTOOLCHAIN for the fetcher; `auto` lets `go` download a newer toolchain when a module requires one, `local` pins the installed toolchain |
| `--python` | `python3` | Python interpreter used for `pip download` |
| `--maven` | `mvn` | Maven command used to resolve Java/Maven artifacts |
| `--npm` | `npm` | npm command used to resolve NPM package graphs |
| `--npm-registry` | `""` | Registry URL npm resolves against (passed as `--registry`; empty uses npm's own config) |
| `--container-registry` | `""` | Comma-separated `host=baseURL` registry overrides (e.g. `docker.io=https://mirror.example.com`) |
| `--hf-endpoint` | `""` (→ `https://huggingface.co`) | Hugging Face endpoint AI models are fetched from (a private Hub mirror, or a test server) |
| `--watch-interval` | `60s` | How often the scheduler checks for due watches; `0` disables scheduled watches |

!!! note
    `GOPRIVATE`, `GONOSUMDB`, `GONOPROXY`, and `GOTOOLCHAIN` are exported only when non-empty (the default `GOTOOLCHAIN=auto` is exported); `GOPROXY`, `GOSUMDB`, and `GOVCS` are always exported (even if set to empty). `GIT_TERMINAL_PROMPT=0` is always forced (no interactive git password prompts) and `GO111MODULE=on` is always set.

`--watch-interval` is a Go `time.Duration`, so it accepts `30s`, `10m`, `2h`, etc. On startup the low server creates `<root>`, `<export-dir>`, and `<root>/gopath/pkg/mod/cache/download` (`0o755`), opens `<root>/watches.db` and `<root>/exported.db` (SQLite), and loads or creates `<root>/low-state.json` (`0o600`).

### Routes

- `POST /admin/{go,python,maven,apt,rpm,containers,npm,hf}/collect` (add `?stream=1` for streamed progress)
- `POST /admin/reexport?stream=go&sequences=42,45-47` (`stream` defaults to `go`; also accepts a JSON body `{"stream":"go","sequences":"42,45-47"}`)
- `GET /admin/bundles`
- `GET /healthz` → `ok\n` (always open, even with auth enabled)

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

!!! note
    An empty `--quarantine` resolves to `<root>/quarantine` inside `NewHighServer`. `--import-interval` is a `time.Duration`; `0` disables the background importer but manual `POST /admin/import` still works.

### Routes

- `POST /admin/import`
- `GET /admin/missing`
- `GET /admin/status`
- `GET /healthz`
- `PUT|POST /diode/<bundle-file>` — bundle ingest, only when `ARTIGATE_DIODE_INGEST=on` (403 otherwise)

---

## Environment variables

There are **no** environment variables for `keygen` or `hashpw`. The TLS variables apply to **both** `low` and `high` (both call the same `tlsConfigFromEnv`). The auth and cookie variables apply to the **low side only** — the high side has no auth. The diode-transport variables split by side (`ARTIGATE_DIODE_URL` low, `ARTIGATE_DIODE_INGEST` high, the token both; `ARTIGATE_PITCHER_*` low, `ARTIGATE_CATCHER_*` high), and `ARTIGATE_HF_TOKEN` is low-side only.

### Low-side authentication

| Variable | Default | Meaning |
|---|---|---|
| `ARTIGATE_LOW_AUTH` | unset (auth disabled) | One or more `username:<argon2id-hash>` credentials, separated by `;` or newlines (`\n`/`\r`) — **not commas** |
| `ARTIGATE_LOW_COOKIE_SECURE` | `auto` | Session cookie `Secure` attribute: `auto` follows ArtiGate's own TLS; `true`/`false` override |

When `ARTIGATE_LOW_AUTH` yields at least one credential, the dashboard requires a form login and sessions are carried in an encrypted, signed cookie (`artigate_session`, 12 hours, `HttpOnly`, `SameSite=Lax`). Keys persist in `<root>/session.key` (`0o600`, 96 bytes) so sessions survive a restart. `/healthz` stays open and a **Log out** button appears.

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
| `ARTIGATE_DIODE_TOKEN` | both | unset (open) | Shared bearer token: the low side sends it, the high side requires it when set (constant-time compare) |

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

- **Flags only:** `--listen`, `--root`, `--export-dir`, `--landing`, `--quarantine`, `--private-key`, `--public-key`, all `--go*`/toolchain/ecosystem-binary flags, `--hf-endpoint`, `--watch-interval`, `--import-interval`, `--apt-gpg-key`, `--rpm-gpg-key`.
- **Env only:** `ARTIGATE_LOW_AUTH`, `ARTIGATE_LOW_COOKIE_SECURE`, `ARTIGATE_TLS_*`, `ARTIGATE_ACME_*`, `ARTIGATE_DIODE_*`, `ARTIGATE_PITCHER_*`, `ARTIGATE_CATCHER_*`, `ARTIGATE_HF_TOKEN`.

See also: [Deployment](deployment.md) for production topologies, [Security & trust](security.md) for the trust model, and [TLS / HTTPS](tls.md) for the full TLS matrix.
