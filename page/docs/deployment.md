# Deployment

This page covers running ArtiGate in production: the Docker image and the fetch tooling it bundles, the Docker Compose demo stack, `systemd` units for the two sides, how the real one-way diode transfer works, and how state, volumes, and backups are laid out.

ArtiGate is a single static binary with four subcommands (`keygen`, `low`, `high`, `hashpw`). The low side and high side are separate processes, usually on physically separated hosts, connected only by a one-way transfer that carries signed bundle files. For the exhaustive flag and environment-variable reference see [Configuration](configuration.md); for HTTPS see [TLS / HTTPS](tls.md).

## The Docker image

The `Dockerfile` is a two-stage build, both stages on `golang:1.25-alpine`.

**Build stage.** `go.mod` is copied first so the module-download layer caches independently of source changes (ArtiGate's runtime deps are pure-Go: `certmagic` for ACME/TLS, `gorilla/securecookie`, `hashicorp/go-version`, `golang.org/x/crypto`, and `modernc.org` SQLite). The binary is compiled fully static with CGO disabled, so it runs on any base:

```dockerfile
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/artigate ./cmd/artigate
```

**Runtime stage.** A single `apk add` installs the fetch toolchain that the **low side** shells out to. The Go toolchain itself is already present from the `golang:1.25-alpine` base and is not re-installed via apk:

```dockerfile
RUN apk add --no-cache git ca-certificates openssh-client python3 py3-pip \
    maven openjdk17-jre-headless nodejs npm gnupg xz
```

Each tool maps to a low-side ecosystem:

| Tool (package) | Used by the low side for |
|---|---|
| `go` (from the base image) + `git` | Go modules — fetching and VCS resolution |
| `pip` (`python3`, `py3-pip`) | Python wheels/sdists |
| `mvn` (`maven` + `openjdk17-jre-headless`) | Java / Maven artifacts |
| `npm` (`nodejs`, `npm`) | NPM dependency-graph resolution |
| `gpgv` (`gnupg`) | Verifying upstream APT / RPM repository signatures |
| `xz` | Decompressing some RPM indexes |

APT, RPM, NPM, and container files themselves are fetched **over HTTP with the Go standard library**, not with external CLIs — only the tools above are shelled out to. See [Low side](low-side.md) for how each collector works.

!!! note "The high side needs almost none of this"
    The **high side never invokes** `go`, `git`, `pip`, `mvn`, or `npm` and never fetches upstream. It uses `gnupg` only when signing regenerated APT/RPM repositories (`--apt-gpg-key` / `--rpm-gpg-key`); otherwise it needs nothing but the binary. A high-only deployment can therefore use a much slimmer image (binary + optionally gnupg). The shared image above is convenient but over-provisioned for the high side.

The image creates a system user/group `artigate`, installs the binary at `/usr/local/bin/artigate`, sets the Go cache environment, pre-creates the working directories, and drops privileges:

```dockerfile
ENV HOME=/home/artigate \
    GOCACHE=/home/artigate/.cache/go-build \
    GOMODCACHE=/home/artigate/go/pkg/mod
RUN mkdir -p /var/lib/artigate /var/spool/diode-out /var/spool/diode-in /keys ...
USER artigate
WORKDIR /home/artigate
EXPOSE 8080
ENTRYPOINT ["artigate"]
CMD ["--help"]
```

Because the entrypoint is the binary itself, `docker run <image>` prints usage. Override `CMD` with `low …` or `high …` (and their flags) to run a side.

## Docker Compose demo stack

The bundled `docker-compose.yml` runs a complete low + high pipeline on a single host, wired together over the **HTTP diode transport**: the low side uploads each exported bundle to the high side's `/diode` ingest endpoint (`ARTIGATE_DIODE_URL=http://high:8080/diode`, shared `ARTIGATE_DIODE_TOKEN`), which **stands in for the one-way data diode** and lets you exercise the whole flow locally. Prefer the classic folder flow instead? Drop the `ARTIGATE_DIODE_*` variables and mount one shared volume as the low side's `/var/spool/diode-out` and the high side's `/var/spool/diode-in`.

!!! warning "The compose wiring is not a real diode"
    In a real deployment the two sides are physically separated and the transfer is enforced one-way by hardware. In the demo the low side simply HTTP-POSTs to the high side on the same Docker network — nothing enforces directionality. Never treat the demo topology as an air gap, and replace the demo `change-me-diode-token` before sharing the stack. See [Security & trust](security.md).

### Services

| Service | Role | Host port | Key volumes |
|---|---|---|---|
| `keygen` | One-shot: generate the Ed25519 key pair into `keys` (idempotent) | — | `keys:/keys` |
| `low` | Internet-side exporter dashboard | `8080 → 8080` | `keys:/keys:ro`, `low-outbound:/var/spool/diode-out`, `low-data:/var/lib/artigate` |
| `high` | Air-gapped read-only repository + tree | `8081 → 8080` | `keys:/keys:ro`, `high-landing:/var/spool/diode-in`, `high-data:/var/lib/artigate` |

`keygen` runs first; both `low` and `high` declare `depends_on: keygen: condition: service_completed_successfully` (and `low` additionally waits for `high` to start, so the first collect's upload doesn't race the high side's boot). The keygen command is guarded so it never overwrites existing keys:

```bash
test -f /keys/low.ed25519 || artigate keygen --private /keys/low.ed25519 --public /keys/high.ed25519.pub
```

The `low` service exports on port 8080 and the `high` service maps host **8081** to container 8080 (both listen on `:8080` internally):

```yaml
low:
  command:
    - low
    - --listen=:8080
    - --root=/var/lib/artigate
    - --export-dir=/var/spool/diode-out
    - --private-key=/keys/low.ed25519
    - --upstream-goproxy=https://proxy.golang.org,direct
  environment:
    - ARTIGATE_DIODE_URL=http://high:8080/diode
    - ARTIGATE_DIODE_TOKEN=change-me-diode-token
high:
  command:
    - high
    - --listen=:8080
    - --root=/var/lib/artigate
    - --landing=/var/spool/diode-in
    - --public-key=/keys/high.ed25519.pub
    - --import-interval=10s
  environment:
    - ARTIGATE_DIODE_INGEST=on
    - ARTIGATE_DIODE_TOKEN=change-me-diode-token
```

After the stack is up:

- **Low side** (exporter dashboard): <http://localhost:8080/>
- **High side** (repository + tree): <http://localhost:8081/>

Drive the low side by asking it to collect artifacts, then watch them arrive on the high side:

```bash
# Mirror a Go module and its full dependency graph:
curl -XPOST localhost:8080/admin/go/collect \
  -d '{"modules":["rsc.io/quote@latest"],"resolve_deps":true}'

# Mirror Python wheels:
curl -XPOST localhost:8080/admin/python/collect \
  -d '{"requirements":["requests"]}'
```

See the [HTTP API reference](api.md) for every route and JSON field.

### Managing the stack

The `Makefile` wraps Compose (it auto-detects `docker compose` v2 and falls back to legacy `docker-compose`):

| Target | Command | Effect |
|---|---|---|
| `make run` | `docker compose up --build` | Build and start low + high in the foreground |
| `make run-detach` | `docker compose up --build -d` | Start the stack in the background |
| `make stop` | `docker compose down` | Stop the stack, **keeping state** — sequence counters, keys, and mirror survive, so a restart continues where it left off |
| `make reset` | `docker compose down -v` | Stop **and wipe all volumes** — a fresh start, sequences back to `1` |

!!! warning "`reset` destroys the mirror and resets sequencing"
    `make reset` (`docker compose down -v`) removes `low-data`, `high-data`, `low-outbound`, `high-landing`, and `keys`. Sequence numbering restarts at `1` and a new key pair is generated. Use `make stop` for an ordinary restart; only use `reset` when you deliberately want to start over.

### Enabling low-side auth (and the `$$` caveat)

Low-side login is **disabled by default** — with no `ARTIGATE_LOW_AUTH` set, the dashboard *and* its mutating `/admin/*` endpoints are unauthenticated, so bind the low side to a trusted network. To require a login, uncomment the `environment` block in the `low` service and supply your own credentials:

```yaml
    environment:
      - ARTIGATE_LOW_AUTH=user:$$argon2id$$v=19$$m=65536,t=3,p=1$$5ba6Q+p3TKhi2kXkU+OtIw$$lg4sRrA78xnKtlOiNCMOAPtaHAG0KoTNzUV8xStZSes
```

Generate a hash with the `hashpw` subcommand. It reads the password from **stdin** (not an argument), so it never lands in shell history:

```bash
./artigate hashpw --user user
```

The value is an argon2id PHC string of the form `user:$argon2id$v=19$m=…,t=…,p=…$<salt>$<key>`. Multiple credentials are separated by `;` or newlines (not commas — commas appear inside the argon2 parameter string).

!!! warning "Every `$` must be doubled to `$$` in compose files"
    Compose treats a single `$` as a variable reference, so **every `$` in the argon2 hash must be written `$$`** in `docker-compose.yml`; it reaches the container as a single `$`. The example hash above encodes the password `password` — do **not** ship it; generate your own. A non-empty `ARTIGATE_LOW_AUTH` that parses to zero valid credentials (for example a stray `;` or mis-escaped `$`) is a fatal startup error, so ArtiGate fails closed rather than silently leaving the dashboard open.

The high side is **never authenticated** — no auth variable applies to it. For cookie/reverse-proxy details (`ARTIGATE_LOW_COOKIE_SECURE`) and HTTPS, see [TLS / HTTPS](tls.md).

## systemd units

For a package/binary deployment, `examples/systemd/` contains reference units for both sides. Both run as `User=artigate` / `Group=artigate` with `Restart=always`, `RestartSec=5`, `NoNewPrivileges=true`, `PrivateTmp=true`, and `WantedBy=multi-user.target` after `network-online.target`.

Note the `--root` paths differ from compose: the units use the binary's real per-side defaults, `/var/lib/artigate-low` and `/var/lib/artigate-high`.

**`artigate-low.service`** runs `artigate low` and, because the low side needs `HOME` for the Go module cache, sets `ProtectHome=false`:

```ini
[Service]
User=artigate
Group=artigate
ExecStart=/usr/local/bin/artigate low \
  --listen :8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct \
  --goprivate github.com/your-org/* \
  --gonosumdb github.com/your-org/*
ProtectSystem=full
ProtectHome=false
ReadWritePaths=/var/lib/artigate-low /var/spool/diode-out /etc/artigate
```

!!! warning "Remove the `--export-interval 60s` line from the shipped example"
    The example unit as committed passes `--export-interval 60s`, but **no such flag exists**. The `low` subcommand uses `flag.ExitOnError`, so an unrecognised flag makes the process exit non-zero and the unit fails to start. Delete that line. The low side has **no export loop or interval** at all — it exports **synchronously at collect time**. The nearest real flag is `--watch-interval` (default `60s`), which controls the scheduled-watch scheduler, not exporting; see [Scheduling (watches)](scheduling.md). The `--goprivate` and `--gonosumdb` flags in the example are valid.

**`artigate-high.service`** runs `artigate high`. The high side needs no `HOME` or Go cache (consistent with the image note above), so it sets `ProtectHome=true`:

```ini
[Service]
User=artigate
Group=artigate
ExecStart=/usr/local/bin/artigate high \
  --listen :8080 \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --public-key /etc/artigate/high.ed25519.pub \
  --import-interval 10s
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/artigate-high /var/spool/diode-in
```

Install the units, drop the key material into `/etc/artigate/` (private key on the low host only, public key on the high host only), then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now artigate-low     # on the internet-side host
sudo systemctl enable --now artigate-high    # on the air-gapped host
```

Enabling HTTPS on either side is done entirely through environment variables in a drop-in (`systemctl edit`), never flags — see [TLS / HTTPS](tls.md).

## The real diode transfer

ArtiGate itself never moves bundles across the gap. The transport — the actual one-way path — is **out of scope**; ArtiGate only reads and writes files in two directories. Your job is to carry files from the low side's export directory (`--export-dir`, default `/var/spool/diode-out`) into the high side's landing directory (`--landing`, default `/var/spool/diode-in`).

### Carry three files per bundle

A bundle is **exactly three sibling files** sharing a bundle ID. All three must be carried across for a bundle to be importable:

```text
<bundleID>.tar.gz             # the artifact archive (payload)
<bundleID>.manifest.json      # the manifest (the exact signed bytes)
<bundleID>.manifest.json.sig  # detached base64 Ed25519 signature over the manifest bytes
```

The bundle ID is `<stream>-bundle-<seq>` zero-padded to six digits, e.g. `go-bundle-000001`, `python-bundle-000042`, `apt-bundle-000001`. Each of the eight **streams** — `go`, `python`, `maven`, `apt`, `rpm`, `containers`, `npm`, `hf` — has its own independent sequence counter, so a gap in one stream never blocks another. Bundles are written atomically (temp file + rename), so a partially-arrived bundle is simply "incomplete" and is skipped until all three files are present. See [Architecture](architecture.md) for the bundle format and signing model.

### Strict in-order import

The high side runs an import loop every `--import-interval` (default `10s`; `0` disables the background importer, leaving `POST /admin/import` for manual runs). Each pass:

1. **Sweeps the landing directory.** For each complete bundle, its sequence is compared to the next-expected value for its stream:
   - `seq > next` (a future bundle) → moved to the **quarantine** directory (`--quarantine`, default `<root>/quarantine`).
   - `seq ≤` the last-imported sequence → moved to `<landing>/duplicates`.
   - `seq == next` → left in place, ready to import.
2. **Drains each stream in order.** For every stream it repeatedly looks for the next sequence in the landing directory *and then* the quarantine directory; if that exact next sequence is missing, that stream stops (strict in-order) while the others continue.

### Gaps are quarantined and auto-filled

A missing bundle blocks **only its own stream**, and only until the gap is filled. Future bundles that arrive early are **retained in quarantine, never discarded**. When the missing predecessor finally arrives and imports, the very next pass picks the quarantined successor back up automatically — the gap bundle and its quarantined successors drain in the same pass, with no operator action.

Every imported bundle is verified before install: the Ed25519 signature over the exact on-disk manifest bytes, a chained-sequence check (`previous_sequence` must equal the high side's current position for that stream, so bundles import strictly consecutively), and a per-file SHA-256 check of every archive entry. The high side then **regenerates** all repository metadata from the artifacts actually present — it never trusts transferred indexes. See [High side](high-side.md) and [Security & trust](security.md).

Check where each stream stands with:

```bash
curl localhost:8081/admin/status
```

which reports, per stream, `last_imported_sequence`, `next_expected_sequence`, `missing_ranges`, `quarantined_sequences`, and any `blocking_missing_sequence`.

!!! note "The transport is yours to build — or use the built-in HTTP one"
    ArtiGate makes no assumptions about how the three files cross the gap — a hardware data diode, a manual sneakernet drive, or any one-way transfer works, because bundles are self-contained and self-verifying. The only requirement is that all three files of a bundle land in the high side's landing directory. ArtiGate never sends anything back from high to low; the flow is strictly one-way.

### Optional HTTP transport

For diodes or diode proxies that speak HTTP, ArtiGate can perform the transfer itself, configured entirely by environment variables:

| Variable | Side | Meaning |
|---|---|---|
| `ARTIGATE_DIODE_URL` | low | endpoint bundles are uploaded to after every export and re-export (`PUT <url>/<file>`, archive first) |
| `ARTIGATE_DIODE_INGEST` | high | `on` accepts uploads at `PUT/POST /diode/<file>` into the landing directory (default `off`) |
| `ARTIGATE_DIODE_TOKEN` | both | optional shared bearer token |

After a successful upload the low side clears the bundle from the export directory (it shows as *sent* on the Status page); a failed upload never loses a bundle — the collect still succeeds, the dashboard and a schedule's status report the error, and the bundle stays staged for a re-transmit. Uploads stream atomically into the landing directory (a half-received file is never visible under its final name), a completed bundle imports immediately rather than on the next scan tick, and only the three bundle-file name shapes are accepted. The transport carries no trust — signature, sequencing, and hash checks are unchanged; the token only protects the high side's disk. Anything that can `PUT` a file works as a sender:

```bash
curl -fT go-bundle-000042.tar.gz -H "Authorization: Bearer $TOKEN" \
  https://artigate-high.local/diode/go-bundle-000042.tar.gz
```

## State, volumes, and backups

Each side keeps durable state under its `--root`. Plan capacity and backups for these directories.

**Low side** (`--root`, default `/var/lib/artigate-low`):

| Path | Contents |
|---|---|
| `<root>/low-state.json` | Per-stream next-sequence counters (mode `0600`) |
| `<root>/exported.db` | SQLite content-dedup index — which file hashes have already been shipped per stream |
| `<root>/watches.db` | SQLite scheduled-watch definitions and history |
| `<root>/bundles` | Persistent archive of every generated bundle, retained for re-export |
| `<root>/gopath/...` | Go module download cache |
| `<export-dir>` (default `/var/spool/diode-out`) | Freshly written bundles staged for the diode transfer (cleared automatically after a successful HTTP diode upload) |

**High side** (`--root`, default `/var/lib/artigate-high`):

| Path | Contents |
|---|---|
| `<root>/import-state.json` | Per-stream last-imported sequence and timestamp |
| `<root>/cache/download` | The installed, immutable artifact tree served to clients |
| `<root>/quarantine` | Retained out-of-order future bundles awaiting their predecessor |
| `<root>/tmp/<bundleID>` | Staging area for archive extraction and hash verification |
| `<landing>` (default `/var/spool/diode-in`) | Incoming bundles; processed files move to `<landing>/imported`, replays to `<landing>/duplicates` |

!!! tip "Account for disk growth"
    Processed bundles accumulate in `<landing>/imported`, duplicates in `<landing>/duplicates`, future bundles in `<quarantine>`, and every generated bundle in the low side's `<root>/bundles` archive. Automatic retention/pruning is not yet built, so monitor these directories and prune old `imported`/`duplicates` files as needed. The low-side `bundles` archive is what powers re-export (`POST /admin/reexport`), so keep it as long as you may need to replay sequences.

!!! note "Backups"
    Back up each side's `<root>` to preserve state across host loss. On the low side the critical items are `low-state.json`, `exported.db`, `watches.db`, and the `bundles` archive; the Go cache is reconstructible. On the high side, `import-state.json` plus `cache/download` are the mirror itself. The Ed25519 private key (low) and public key (high) live outside `<root>` (for example `/etc/artigate/` or the `keys` volume) — back these up separately and keep the private key on the low side only.

## Related pages

- [Configuration reference](configuration.md) — every flag, default, and environment variable.
- [TLS / HTTPS](tls.md) — enabling HTTPS (same env vars for low and high).
- [High side](high-side.md) — operating the importer and repository server.
- [Security & trust](security.md) — the trust model and hardening guidance.
