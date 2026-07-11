# Getting started

ArtiGate is a single Go binary with four subcommands (`keygen`, `low`, `high`, `hashpw`). This page is the fastest path to a running stack: build it, bring up the demo low+high pipeline with Docker Compose, and mirror your first module end to end.

!!! note "The two sides"
    The **low side** sits on the internet, fetches artifacts with the native toolchains (`go`, `pip`, `mvn`, `npm`, …), and writes signed bundles into an export directory. The **high side** lives on the isolated network, imports those bundles across a one-way data diode, verifies every signature and hash, and serves clients read-only. See [Low side](low-side.md) and [High side](high-side.md) for the full operating guides.

## Build from source

ArtiGate leans heavily on the Go standard library, with a handful of small pure-Go modules: `modernc.org/sqlite` for watches and the export-dedup index, `hashicorp/go-version` for container tag constraints, `caddyserver/certmagic` for ACME/TLS, `gorilla/securecookie` for login sessions, `golang.org/x/crypto` for argon2id password hashing, and `klauspost/reedsolomon` for the built-in UDP diode's forward error correction. These are ordinary `go.mod` requires (no `vendor/` directory), so a build is quick.

```bash
# The default make target builds the binary into ./artigate
make build

# …which is exactly:
go build -o artigate ./cmd/artigate
```

Useful development targets from the `Makefile`:

| Target | Action |
|---|---|
| `make build` (default) | `go build -o artigate ./cmd/artigate` |
| `make test` | `go test ./... -race -coverprofile=coverage.out -covermode=atomic` |
| `make cover` | per-function coverage from the last test run |
| `make lint` | installs pinned `golangci-lint` (v2.5.0) if missing, then runs it |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w cmd` |
| `make ui` | recompiles the high-side TypeScript dashboard (`cmd/artigate/ui/app.ts` → `app.js`) |
| `make clean` | removes `artigate` and `coverage.out` |

Confirm the binary works:

```bash
./artigate --help
```

CI also publishes a ready-made container image on every push to `main`: `ghcr.io/define42/artigate` (tags `latest`, the commit SHA, and a semver tag). It bundles the low side's fetch toolchains; see [Deployment](deployment.md).

## Quick start with Docker Compose

The repository ships a `docker-compose.yml` that runs both sides on one host, wired together over the **HTTP diode transport**: the low side uploads each exported bundle to the high side's `/diode` ingest endpoint — it **stands in for the one-way data diode** so you can exercise the whole pipeline locally. (The classic folder flow works too: drop the `ARTIGATE_DIODE_*` variables and share one volume between the export and landing dirs.)

!!! warning "The demo diode is not one-way"
    Compose cannot enforce a one-way transfer: in the demo the low side simply HTTP-uploads to the high side over the shared Docker network. Only physically separate hardware enforces the diode in production. See [Deployment](deployment.md).

`docker-compose.yml` has no reusable credentials and fails closed until you
provide both an operator login and an independent random diode token. Copy the
template, generate the two values, and paste them into the gitignored `.env`
file. Keep the argon2id value single-quoted so its `$` characters stay literal.

```bash
cp .env.example .env
./artigate hashpw --user admin
openssl rand -hex 32
```

```bash
make run          # docker compose up --build   (foreground, low + high)
make run-detach   # docker compose up --build -d (background)
make stop         # docker compose down          (keeps state: keys, sequence, mirror)
make reset        # docker compose down -v        (wipes all volumes; sequence back to 1)
```

Once up, two dashboards are available:

| Dashboard | URL | What it is |
|---|---|---|
| **Low side** (exporter) | <http://localhost:8080/> | Pick an ecosystem, collect & export, schedule pulls |
| **High side** (repository) | <http://localhost:8081/> | Import status, browsable artifact tree, "Set me up" guides |

Both containers listen on `:8080` internally. Compose maps the high side to
host port `8081`, and binds both published ports to `127.0.0.1` by default.
Do not override `ARTIGATE_LOW_BIND` or `ARTIGATE_HIGH_BIND` with a remote
address until a TLS-authenticating reverse proxy and network policy protect it.

### Auto-generated keys

A one-shot `keygen` service runs first and creates the Ed25519 signing key pair
into separate `keys` (low/private) and `high-keys` (high/public) volumes:

```text
artigate keygen --private /low-keys/low.ed25519 --public /high-keys/high.ed25519.pub
```

It is **idempotent** and refuses to regenerate if only one side of the pair is
present. The low side mounts only `keys` read-only and signs bundles with it;
the high side mounts only `high-keys` and verifies with the public key. When
upgrading an older Compose installation, the one-shot service copies the
existing public key from the legacy `keys` volume into `high-keys`; it never
rotates the existing pair. `make stop` keeps both volumes so a later
`make run` continues the same sequence chain; `make reset` wipes both for a
clean start.

!!! note "The high side is never authenticated"
    The Compose low-side dashboard requires the `ARTIGATE_LOW_AUTH` login configured in `.env`. The high side has no auth of its own, which is why its published port is loopback-only — protect any remote exposure with network placement or a fronting TLS proxy. See [Security & trust](security.md).

## Your first end-to-end mirror

This walkthrough mirrors a Go module on the low side, watches it import on the high side, then points a real `go` client at the high side. Start the stack with `make run` (or `make run-detach`).

### 1. Collect a module on the low side

Open the low dashboard at <http://localhost:8080/>, sign in, select **Go**,
enter a module, and click **Collect & export**. An API client first obtains a
session cookie with the same credentials:

```bash
curl -c /tmp/artigate.cookies -XPOST localhost:8080/login \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=$ARTIGATE_PASSWORD"

curl -b /tmp/artigate.cookies -XPOST localhost:8080/admin/go/collect \
  -d '{"modules":["rsc.io/quote@latest"],"resolve_deps":true}'
```

The JSON body fields are `modules` (a list of `module@version` specs) and `resolve_deps` (fetch the transitive module graph too). The low side fetches with the bundled `go`/`git` toolchain, then writes a **signed three-file bundle** into its export dir:

```text
go-bundle-000001.tar.gz            # the artifact archive
go-bundle-000001.manifest.json     # the manifest (the signed bytes)
go-bundle-000001.manifest.json.sig # detached base64 Ed25519 signature
```

A successful response looks like:

```json
{
  "stream": "go",
  "sequence": 1,
  "exported_modules": 8,
  "bundle_id": "go-bundle-000001"
}
```

!!! tip "Live progress"
    The dashboard streams progress line-by-line. To get the same NDJSON stream from `curl`, append `?stream=1`:

    ```bash
    curl -b /tmp/artigate.cookies -XPOST 'localhost:8080/admin/go/collect?stream=1' \
      -d '{"modules":["rsc.io/quote@latest"],"resolve_deps":true}'
    ```

Other ecosystems follow the same shape, e.g. Python wheels:

```bash
curl -b /tmp/artigate.cookies -XPOST localhost:8080/admin/python/collect \
  -d '{"requirements":["requests"]}'
```

See [Ecosystems](ecosystems/index.md) for every collector's payload — Go, Python, Maven, npm, APT, RPM, containers, and AI models.

!!! note "Nothing new? Nothing sent."
    If every file in a collect was already exported on that stream, the low side reports `"skipped": true` with `"no new content since the last export"` and consumes **no** sequence number. If only *some* files are new, it writes a **delta bundle** carrying just those (the response's `prior_files` counts the rest) — a re-pull of a slowly-changing upstream ships only the churn across the diode. Add `"force": true` to any collect body to bypass this and produce a full, self-contained bundle. See [Low side](low-side.md).

### 2. Watch it import on the high side

In the demo, the low side uploads each bundle's three files straight to the high side's `/diode` ingest endpoint (the HTTP diode transport), and a completed upload is imported immediately. With a folder diode the high side instead scans its landing dir every `--import-interval` (10s in the demo). Either way, bundles import **strictly in sequence order, per stream**: for each bundle the high side verifies the Ed25519 signature over the manifest, re-hashes every file against the manifest, installs the artifacts immutably, and regenerates all repository metadata from the artifacts actually present.

Open the high dashboard at <http://localhost:8081/> and watch the Go tree populate. You can also query the import status directly:

```bash
curl localhost:8081/admin/status
```

```json
{
  "streams": [
    {
      "stream": "go",
      "last_imported_sequence": 1,
      "next_expected_sequence": 2,
      "ready_to_import": false
    }
  ]
}
```

### 3. Point `go` at the high side

The high side serves a read-only Go module proxy under `/go/`. Go clients set `GOPROXY` to that path with an `,off` fallback (so they never reach the internet) and disable checksum-DB lookups:

```bash
export GOPROXY=http://localhost:8081/go,off
export GOSUMDB=off
go get rsc.io/quote@latest
```

The high side serves **only** complete, verified versions that it has actually imported; anything not mirrored simply isn't found (the `,off` keeps the client from falling through to upstream). See [Go modules](ecosystems/go.md) for `go env`/CI setup, and the other [ecosystem pages](ecosystems/index.md) for the equivalent APT, RPM, PyPI, npm, Maven, OCI, and AI model client configuration.

## Generating signing keys manually

Docker Compose generates keys for you. For a non-Compose setup (systemd units, bare hosts), create the key pair yourself with the `keygen` subcommand:

```bash
artigate keygen --private low.ed25519 --public high.ed25519.pub
```

| Flag | Default | Meaning |
|---|---|---|
| `--private` | `low.ed25519` | Ed25519 private key output path (base64, mode `0600`) |
| `--public` | `high.ed25519.pub` | Ed25519 public key output path (base64, mode `0644`) |

!!! warning "Keep the private key on the low side only"
    Install `low.ed25519` on the low host and pass it with `--private-key`. Copy **only** `high.ed25519.pub` across to the high host and pass it with `--public-key`. The private key never leaves the low side.

Then run each side pointing at its key:

```bash
# Low side (internet-facing exporter)
artigate low \
  --listen :8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct

# High side (isolated read-only mirror)
artigate high \
  --listen :8080 \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --public-key /etc/artigate/high.ed25519.pub \
  --import-interval 10s
```

Carry all three files of each bundle from the low side's `--export-dir` across the diode into the high side's `--landing` directory; the high side does the rest.

!!! tip "Optional low-side login"
    To require a form login on the low dashboard, generate an argon2id hash and set `ARTIGATE_LOW_AUTH`. The `hashpw` subcommand reads the password from **stdin** (so it never lands in shell history):

    ```bash
    artigate hashpw --user user
    ```

    For the shipped Compose stack, paste the complete output into
    `ARTIGATE_LOW_AUTH` in the gitignored `.env` file and single-quote the
    value. This keeps each `$` literal without editing the generated hash.

## Where to next

- [Low side](low-side.md) — collectors, export dedup, streaming progress, re-export, status.
- [High side](high-side.md) — import loop, quarantine, serving clients.
- [Deployment](deployment.md) — real diode transfer, systemd units, hardening.
- [Ecosystems](ecosystems/index.md) — per-ecosystem collect payloads and client setup.
