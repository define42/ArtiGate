# ArtiGate

[![Go version](https://img.shields.io/github/go-mod/go-version/define42/ArtiGate)](go.mod)
[![CI](https://img.shields.io/github/actions/workflow/status/define42/ArtiGate/go.yml?branch=main)](https://github.com/define42/ArtiGate/actions/workflows/go.yml)
[![Coverage](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg)](https://codecov.io/gh/define42/ArtiGate)
[![License](https://img.shields.io/github/license/define42/ArtiGate)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-ArtiGate-green)](https://define42.github.io/ArtiGate/)

ArtiGate mirrors software dependencies, container images, AI models, and
vulnerability advisories into air-gapped networks through a one-way data diode.
It transfers signed bundles and serves their verified contents through native
package and registry protocols, so existing build tools can use the mirror.

[Full documentation](https://define42.github.io/ArtiGate/) ·
[Configuration](page/docs/configuration.md) ·
[HTTP API](page/docs/api.md) ·
[Deployment](page/docs/deployment.md)

## Demo

One binary runs on both sides of the boundary:

```text
Internet                One-way transfer                 Air-gapped network

Upstreams --> low --> signed bundles --> diode --> high --> package clients
              |                                    |
         collect + sign                       verify + serve
```

The **low side** accepts package specifications through a dashboard or HTTP API,
fetches the requested content, and exports numbered bundles. The **high side**
imports those bundles and serves a local mirror without fetching missing
content from upstream. Each ecosystem has its own sequence of bundles;
a missing Go bundle does not stop Python or container imports.

For example, collect `rsc.io/quote@v1.5.2` on the low side, wait for its import,
and download it through the high side:

```bash
GOPROXY=http://localhost:8081/go,off GOSUMDB=sum.golang.org \
  go mod download -json rsc.io/quote@v1.5.2
```

The local setup below provides both dashboards and the transfer between them.

## Getting started

### Run the local Docker Compose stack

You need Git, Docker with Docker Compose, OpenSSL, and Go **1.27.1 or newer**
for the credential command below. The containers include the tools used to
collect dependencies.

```bash
git clone https://github.com/define42/ArtiGate.git
cd ArtiGate
cp .env.example .env

go run ./cmd/artigate hashpw --user admin
openssl rand -hex 32
```

For `hashpw`, enter your chosen password on stdin and press Enter. Copy the
complete printed `admin:$argon2id$...` credential into `ARTIGATE_LOW_AUTH` in
`.env`, and the OpenSSL output into `ARTIGATE_DIODE_TOKEN`. Keep the credential
**single-quoted** so Compose preserves every `$` in the hash:

```dotenv
ARTIGATE_LOW_AUTH='PASTE_THE_COMPLETE_USERNAME_AND_HASH_HERE'
ARTIGATE_DIODE_TOKEN='PASTE_THE_RANDOM_TOKEN_HERE'
```

To generate the credential without installing Go on the host, use the local
container image instead of `go run`:

```bash
docker build -t artigate:local .
docker run --rm -it artigate:local hashpw --user admin
```

Start the stack after setting both values:

```bash
docker compose up --build -d
```

| Dashboard | Address | Use |
| --- | --- | --- |
| Low side | <http://localhost:8080/> | Sign in, collect dependencies, schedule updates, re-transmit bundles. |
| High side | <http://localhost:8081/> | Check imports, browse artifacts, copy client setup instructions. |

The stack generates an Ed25519 key pair once and stores the private and public
keys in separate volumes. The high side receives only the public key.

**This is a local demonstration of the transfer pipeline.** Compose uses HTTP
on a shared Docker network; it does not enforce a one-way boundary. Both
published ports bind to `127.0.0.1`. Before exposing them remotely, configure
TLS, authentication at the appropriate boundary, and network access controls.
See [deployment](page/docs/deployment.md) for separate hosts and services.

### Mirror your first dependency

1. Open the low-side dashboard and sign in with the password you hashed.
2. Select **Go**, enter `rsc.io/quote@v1.5.2`, and click **Collect & export**.
3. Wait for the Go bundle to appear on the high-side dashboard.
4. Run the `go mod download` command in the demo above.

The high side also serves captured Go checksum database records, so `GOSUMDB`
can remain enabled. `GOPROXY=...,off` prevents upstream fallback. If a collect
reports gaps in checksum capture, resolve those before using a fresh offline
client; older bundles without checksum records need recollection.

Use `docker compose logs -f low high` to follow activity. To stop while keeping
keys, sequences, and mirrored content:

```bash
docker compose down
```

`make run`, `make run-detach`, and `make stop` wrap these Compose operations.
**`make reset` deletes all Compose volumes**, including signing keys and mirror
state; reserve it for a deliberate fresh start.

### Build or run the binary

From a checkout, with the Go version required by [go.mod](go.mod):

```bash
make build
./artigate version
./artigate low --help
./artigate high --help
```

Without Make, use `go build -o artigate ./cmd/artigate`. The `make build` target
also embeds a version derived from Git; set `VERSION=v1.2.3` to override it.

The [release workflow](.github/workflows/go.yml) publishes
`ghcr.io/define42/artigate` with `latest`, commit, and release tags:

```bash
docker run --rm ghcr.io/define42/artigate:latest version
```

A native low-side deployment needs the tools used by its collectors: Go and
Git, Python/pip, Maven and a JDK, npm, and repository verification or compression
tools as applicable. The [Dockerfile](Dockerfile) lists the bundled tools.
Maven collection requires Maven 3.6.3+ and JDK 8+; npm collection requires npm
7+. The high side needs no fetch toolchains; GnuPG is needed if it signs served
APT or RPM repository metadata.

## Features and specification

### Supported ecosystems

ArtiGate has **23 independent streams**, including arbitrary file uploads.
The links below cover request fields, client setup, and ecosystem-specific
limitations. Paths are relative to the high-side base URL; `<mirror>` is the
repository name shown in its dashboard.

| Ecosystem | What to collect | High-side interface |
| --- | --- | --- |
| [Go](page/docs/ecosystems/go.md) | Module specs or `go.mod`, optionally with `go.sum`. A `go.mod` upload or `resolve_deps: true` fetches the full dependency graph. | GOPROXY at `/go`; checksum database records at `/go/sumdb/`. |
| [Python](page/docs/ecosystems/python.md) | Requirements and target-platform wheels; explicit `sdists` for source distributions. | PyPI simple index at `/simple/`, downloads at `/packages/`, provenance at `/integrity/`. |
| [Java / Maven](page/docs/ecosystems/maven.md) | Release coordinates or dependency information from a `pom.xml`. | Maven 2 repository at `/maven/`, including available detached `.asc` signatures. |
| [npm](page/docs/ecosystems/npm.md) | Package specs or `package.json`, optionally pinned by `package-lock.json`. | Registry at `/npm/`, with mirrored signatures, provenance, and OSV-backed `npm audit`. |
| [Rust crates](page/docs/ecosystems/crates.md) | Crate specs and normal/build dependencies; optional dependencies on request. | Cargo sparse registry at `/crates/index/`. |
| [Terraform / OpenTofu](page/docs/ecosystems/terraform.md) | Providers for selected platforms and registry modules. | Provider and module registry under `/terraform/`; discovery at `/.well-known/terraform.json`. |
| [Helm](page/docs/ecosystems/helm.md) | Charts from an `index.yaml` repository, including available `.prov` files. | Chart repositories at `/helm/<mirror>/`. |
| [NuGet](page/docs/ecosystems/nuget.md) | Package specs and dependencies from a v3 source. | NuGet v3 feed at `/nuget/v3/index.json`. |
| [APT](page/docs/ecosystems/apt.md) | deb822 sources, suites, components, and architectures. | Repositories at `/apt/<mirror>/`. |
| [RPM](page/docs/ecosystems/rpm.md) | Concrete `.repo` URLs; `x86_64` and `noarch` packages by default. | yum/dnf repositories at `/rpm/<mirror>/`. |
| [Alpine](page/docs/ecosystems/apk.md) | Mirror branches, repositories, and architectures, or an apk repositories file. | Repositories at `/apk/<mirror>/`; optional index-signing keys at `/apk/keys/`. |
| [Conda](page/docs/ecosystems/conda.md) | Channel, package specs, and platform subdirectories; `noarch` is included. | Channels at `/conda/<mirror>/`. |
| [RubyGems](page/docs/ecosystems/rubygems.md) | Gem specs and runtime dependencies. | Compact index and gems at `/rubygems/`. |
| [PHP Composer](page/docs/ecosystems/composer.md) | Stable package releases and their `require` dependencies. | Composer v2 repository at `/composer/`. |
| [VS Code extensions](page/docs/ecosystems/vsx.md) | Open VSX extension IDs, dependencies, and extension packs. | Gallery API at `/vsx/gallery`, plus `.vsix` downloads. |
| [Ansible Galaxy](page/docs/ecosystems/galaxy.md) | Collection specs and dependencies. | Galaxy v3 API under `/galaxy/`. |
| [R / CRAN](page/docs/ecosystems/cran.md) | Source packages and Depends/Imports/LinkingTo dependencies; archived versions can be pinned. | CRAN source repository at `/cran/`. |
| [Snap](page/docs/ecosystems/snap.md) | Channel revisions, store assertions, and declared base snaps. | `.snap` / `.assert` downloads under `/snap/` for `snap ack` and offline installation. |
| [Git](page/docs/ecosystems/git.md) | HTTP(S) clone URLs and selected branches or tags. | Read-only dumb HTTP repositories at `/git/<mirror>.git`. |
| [Containers](page/docs/ecosystems/containers.md) | OCI/Docker images, attached signatures, attestations, SBOMs, and opaque OCI artifacts. | Read-only registry at `/v2/`; pull names preserve the upstream registry namespace. |
| [AI models](page/docs/ecosystems/ai-models.md) | Hugging Face GGUF variants or full repositories pinned to a commit, with optional path exclusions. | Ollama-compatible `/v2/`, raw GGUF downloads under `/hf/`, and the Hub download API. |
| [OSV](page/docs/ecosystems/osv.md) | Advisory snapshots by OSV ecosystem name, such as `Go`, `PyPI`, or `npm`. | Snapshot ZIPs and individual advisories under `/osv/`; the `npm` snapshot enables npm audit responses. |
| [Uploads](page/docs/ecosystems/uploads.md) | Arbitrary files grouped into named folders. | Downloads at `/uploads/<folder>/<name>`; files can be replaced or deleted. |

### Collection and client constraints

- **Python:** pip runs with `--only-binary=:all:`. A requirement without a
  compatible wheel fails unless handled through the separate source-distribution
  flow. Source archives are fetched directly without running build hooks or
  resolving dependencies; collect their runtime and build requirements for
  clients that build them offline.
- **Maven:** SNAPSHOTs and version ranges are rejected. Uploaded POMs may supply
  dependency information; build sections, profiles, and repository overrides
  are rejected.
- **npm:** install scripts do not run during resolution. Dependencies that
  resolve to Git or file URLs are skipped and reported. `npm audit` requires
  the mirrored OSV `npm` database and npm's bulk-advisory protocol; otherwise
  its endpoint returns 404. Yarn classic's older audit protocol is not served.
- **Rust and Conda:** these collectors are not complete replacements for the
  native dependency solvers. Rust does not perform feature unification or fetch
  dev-dependencies; Conda resolves greedily. Large Conda channel indexes can
  require substantial low-side memory.
- **APT, RPM, and Alpine:** the dashboard defaults to the newest package
  version; turn off **Newest version only** to collect all versions. RPM URLs
  must have variables such as `$releasever` expanded; `.zck`-only indexes are
  unsupported. Alpine re-collects download packages again before export dedup.
- **Terraform:** provider platforms default to `linux_amd64`. Modules use HTTPS
  archives or `git::https` sources; publishing and `terraform login` APIs are
  not provided. Use host-prefixed source addresses, such as
  `artigate-high.local/hashicorp/aws`, with HTTPS on the high side. The
  `provider_installation.network_mirror` protocol is not implemented.
- **Helm:** the Helm collector accepts classic chart repositories. Use the
  container collector for OCI-hosted artifacts.
- **Containers:** image collection selects **linux/amd64**. Original image
  indexes are retained to preserve signed digests, but other platforms are not
  made available. Foreign layers and upstream registry names with explicit
  ports are unsupported; `--container-registry host=baseURL` can redirect a
  logical registry to a private endpoint. The high-side registry accepts no pushes.
- **AI models:** GGUF tags select quantizations; digest pins and split GGUFs are
  unsupported. Full snapshots expose the Hub download API, not search or write
  APIs. A refreshed branch points to its new commit while old commits remain
  downloadable.
- **Snap:** this is an offline download mirror, not a replacement Snap Store.
  On a fresh receiver, collect and install the `snapd` runtime, the base snap,
  and any content-interface prerequisites as needed; only declared bases are
  followed automatically.

Configure clients to use **only the high-side mirror**. Additional package
indexes or upstream fallbacks can introduce dependencies that were never
mirrored. The dashboard's **Set me up** guides and the ecosystem links above
provide client configuration using the actual mirror names and addresses.

### Signed bundles and import order

Each bundle consists of three files:

```text
go-bundle-000001.tar.gz
go-bundle-000001.manifest.json
go-bundle-000001.manifest.json.sig
```

The manifest binds artifact paths, sizes, hashes, metadata, and sequence
information to an Ed25519 signature. On import, the high side verifies the
signature, sequence chain, and each newly transferred file's size and SHA-256.
It regenerates repository indexes from verified artifacts and signed records,
and publishes complete versions. The transfer mechanism does not establish
trust in bundle contents.

Bundles are imported **consecutively within each stream**. Future bundles up to
10,000 positions ahead wait in quarantine and are imported when their missing
predecessors arrive. Duplicates do not advance state. Invalid bundles,
unsupported streams, and excessively far-future bundles are moved to
`<root>/rejected`; a blocked stream does not prevent imports for other
ecosystems. Bundles using a newer manifest format wait for a compatible
high-side version.

Artifact paths are generally immutable. Explicit update paths include uploads,
OSV snapshots, and Go checksum database latest/lookup records. Existing content
referenced by a delta bundle must already be present on the high side.

ArtiGate's bundle signature proves transfer integrity under the configured
signing key; it does not replace verification of the original publisher.
Available upstream verification material is carried alongside artifacts:
Go checksum records, Terraform checksums and GPG material, OCI attachments,
npm signatures and attestations, Maven `.asc`, Helm `.prov`, Python PEP 740
provenance, and Snap assertions. NuGet's embedded signatures travel unchanged.
Clients remain responsible for their publisher trust policies. Collection of
optional signatures and attachments can be incomplete; inspect warnings and
container discovery status. Conda content-trust metadata, Galaxy collection
signatures, and Open VSX signatures are not mirrored.

For regenerated APT/RPM/Alpine metadata, configure `--apt-gpg-key`,
`--rpm-gpg-key`, or `--apk-rsa-key` on the high side and install the matching
public keys on clients. These repositories are otherwise served unsigned and
need explicit client configuration to accept unsigned metadata. Original RPM
package signatures still require the publisher's key.

See [architecture](page/docs/architecture.md) for the bundle format and
[security](page/docs/security.md) for the trust model.

### Scheduling, estimates, and bandwidth

The low-side dashboard can turn a collection specification into a recurring
schedule. Schedules can be paused, run immediately, edited, or removed; due
schedules are checked every minute by default (`--watch-interval`). Uploads
cannot be scheduled because they have no upstream source.

Container tags may be pinned or expressed as version constraints, such as
`golang:1.26.x` or `golang:>=1.24, <2.0`. Schedules resolve the constraint again
on every run. Only plain numeric version tags participate; pin variant tags
such as `1.26.3-alpine` explicitly.

Export deduplication tracks previously forwarded paths and hashes per stream:

- If neither content nor export metadata changes, no bundle or sequence number
  is created.
- Delta bundles contain new files and reference earlier content through the
  signed manifest. Where upstream checksums permit it, collection can also
  skip downloading previously forwarded files.
- `"force": true` bypasses content deduplication and produces full content, but
  **does not reset the sequence or allow missing bundles to be skipped**.
- Uploads always send their files in full, so re-uploading restores a file
  deleted on the high side.

Use **Estimate size** or append `?dry_run=1` to a collect request to estimate
new bytes and bundle count without exporting, allocating a sequence, or
marking content as forwarded. Some collectors can estimate from metadata;
tool-driven collectors still fetch locally to determine sizes. Large exports
split into consecutive bundles, with ecosystem metadata in the final bundle.

The [scheduling guide](page/docs/scheduling.md),
[low-side guide](page/docs/low-side.md), and [API reference](page/docs/api.md)
cover stored specifications, jobs, cancellation, and streaming progress.

### Transfer options

| Transport | Configuration | Behavior |
| --- | --- | --- |
| Folder | Low `--export-dir`; high `--landing`. | Default. An external carrier transfers each bundle's three files. |
| HTTP | Low `ARTIGATE_DIODE_URL`; high `ARTIGATE_DIODE_INGEST=on`; shared `ARTIGATE_DIODE_TOKEN`. | Uploads to `PUT/POST /diode/<file>`; the token must be at least 32 bytes. Complete arrivals trigger import. |
| SFTP | `ARTIGATE_SFTP_URL` on each side, with SSH credentials and `ARTIGATE_SFTP_KNOWN_HOSTS`. | Low uploads to one endpoint; high polls another. Servers may be separate ends of a diode transfer service. |
| UDP diode | Low `ARTIGATE_PITCHER_INTERFACE`; high `ARTIGATE_CATCHER_INTERFACE`. | Rate-limited IPv6 multicast with Reed–Solomon forward error correction over a dedicated one-way link. |

Choose one automatic low-side sender: HTTP, SFTP, or UDP. HTTP and SFTP need
their local transport endpoint to support the protocol's bidirectional session;
the built-in UDP transport requires no return path.

HTTP and SFTP uploads remove successfully sent files from the export spool and
retain the archive copy. Failed sends stay staged for **re-transmit** from the
low-side Status page; collection success alone does not confirm delivery.
There is no automatic retry of failed HTTP/SFTP bundle uploads.

SFTP requires trusted host keys and pre-created remote directories. Use a
server supporting `posix-rename@openssh.com` for atomic replacement. Uploads
use a `.writing` suffix until complete; polling ignores unfinished files and
waits for all three bundle files. The high side leaves remote files in place,
so remote retention is an operator responsibility. SSH login keys are separate
from bundle-signing keys. See the
[SFTP configuration](page/docs/configuration.md#sftp-transport).

For UDP, the defaults are 800 Mbit/s, MTU 9000, and 32 data plus 8 parity shards.
Loss beyond the parity budget requires a re-transmission. Completed receive
blocks are retained for 24 hours so retries of identical files can resume.
The Docker examples use host networking, `NET_ADMIN`, and a root user for
automatic NIC setup. Preconfigured interfaces can use
`ARTIGATE_PITCHER_NETSETUP=off` / `ARTIGATE_CATCHER_NETSETUP=off` for
unprivileged operation within host socket-buffer limits. See the
[low-side](examples/docker-compose-diode-low.yml) and
[high-side](examples/docker-compose-diode-high.yml) Compose examples and the
[UDP guide](page/docs/data-diode.md).

Across all transports, a signed heartbeat advertises the low side's newest
sequence per stream every 30 seconds by default. It lets the high side show
bundles still awaiting arrival, including a final bundle lost entirely in
transit. Configure `ARTIGATE_DIODE_HEARTBEAT` or set it to `off` to disable it.

Ingress limits bound unverified data: archives up to 64 GiB, manifests up to
64 MiB, signatures up to 4 KiB, and 128 GiB total pending/quarantined/rejected
transport data. Export splitting also respects the configured UDP wire limit;
an individual file still has to fit its applicable bundle limit.

### Native deployment and configuration

Generate the signing pair once:

```bash
./artigate keygen --private low.ed25519 --public high.ed25519.pub
```

Keep `low.ed25519` on the low side and provision `high.ed25519.pub` on the high
side. Back up the keys with their associated state; do not regenerate them
when restarting an existing mirror.

For example, after installing the key files and preparing writable state and
spool directories, run these commands on their respective hosts. The loopback
listeners can sit behind local reverse proxies:

```bash
# Low host
./artigate low \
  --listen 127.0.0.1:8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519
```

```bash
# High host
./artigate high \
  --listen 127.0.0.1:8080 \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --public-key /etc/artigate/high.ed25519.pub \
  --import-interval 10s
```

Without an automatic transport, arrange for the external carrier to move
bundles from the low export directory to the high landing directory. An import
interval of `0` disables periodic scans; explicit imports and completed
HTTP/SFTP/UDP arrivals can still trigger importing.

Server paths, collectors, and upstreams use command-line flags. Authentication,
TLS, transports, upstream credentials, and webhooks use environment variables.
The binary does not load the Compose `.env` file itself. See
`low --help`, `high --help`, and the
[configuration reference](page/docs/configuration.md) for the complete surface.
[systemd examples](examples/systemd/) are also included.

| Setting | Purpose |
| --- | --- |
| `ARTIGATE_LOW_AUTH` | `username:argon2id-hash` credentials, separated by semicolons or newlines. Generate them with `hashpw`. |
| `ARTIGATE_LOW_COOKIE_SECURE=true` | Mark session cookies secure when HTTPS terminates at a reverse proxy. |
| `ARTIGATE_GO_AUTH` | Standing private Go host credentials; also marks those hosts private for Go resolution. |
| `ARTIGATE_CONTAINER_AUTH` | Standing private container registry credentials. |
| `ARTIGATE_UPSTREAM_AUTH` | Standing HTTP Basic credentials for Git, APT, RPM, Alpine, and Conda upstreams. |
| `ARTIGATE_HF_TOKEN` | Hugging Face token for gated or private model repositories. |
| `ARTIGATE_TLS_MODE` | `unencrypted` (default), `own-certificate`, `auto-generate-certificate`, or `acme`. |

The three host-credential variables use comma-separated `host=user:password`
entries. Per-collect logins are temporary and are not stored in schedules;
scheduled private fetches need standing credentials. Use the authentication
fields or environment variables rather than embedding credentials in upstream
URLs.

The low side holds the signing key and is a privileged control plane. Without
`ARTIGATE_LOW_AUTH`, startup refuses a non-loopback listener unless
`ARTIGATE_LOW_ALLOW_UNAUTHENTICATED=true` explicitly delegates authentication
to a trusted external layer. A loopback listener without credentials remains
unauthenticated.

The high side has no built-in client login, including for mirrored private
content. Restrict access through network placement or a proxy. Its
state-changing admin endpoints, including manual import and upload deletion,
accept only loopback callers by default. `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN=on`
relaxes that restriction; the demo Compose stack sets it because Docker port
forwarding changes the caller address, while keeping host ports loopback-only.

For native HTTPS, set `ARTIGATE_TLS_MODE=own-certificate` with
`ARTIGATE_TLS_CERT` and `ARTIGATE_TLS_KEY`, or use the other modes described in
the [TLS guide](page/docs/tls.md). Self-signed certificates need client trust.
ACME uses TLS-ALPN-01 and requires the certificate authority to reach the
listener. Docker and Ollama clients expect HTTPS unless explicitly configured
for a plain-HTTP mirror.

### Monitoring and alerting

Both sides expose the following on the dashboard listener, even when low-side
login is enabled:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Process liveness. |
| `GET /readyz` | Readiness: HTTP 200 when checks pass, HTTP 503 naming failures; `?verbose` includes successful checks. |
| `GET /metrics` | Prometheus metrics for sequences, transfer/import outcomes, schedules, jobs, disk space, and transport quota. |

Keep liveness probes on `/healthz`: a missing bundle should raise an alert, not
restart a server that can still serve previously imported content. Readiness
checks include failed staged transfers on the low side and stream gaps,
stalled or failing import passes, undrained backlog, and exhausted transport
quota on the high side. An active long-running import does not itself fail
readiness; supervise a hung import separately.

Useful high-side metrics include `artigate_high_import_lag`,
`artigate_high_stream_blocked`, `artigate_high_gap_age_seconds`,
`artigate_high_bundles_awaiting_from_low`, and
`artigate_high_diode_heartbeat_age_seconds`. Allow for normal transfer time
when alerting on bundles awaiting arrival. Counters reset when the process
restarts; retain history in your monitoring system.

Set `ARTIGATE_WEBHOOK_URL` and optionally `ARTIGATE_WEBHOOK_TOKEN` for
`schedule_failed` (low), `bundle_rejected` (high), and `gap_detected` (high)
notifications. Delivery is best-effort with no retries; gaps emit a notification
when detected, not on every scan.

### Recovery and retention

To recover a missing bundle:

1. Read the missing sequence or range from the high-side dashboard or
   `GET /admin/missing`.
2. Use **re-transmit** on the low-side Status page, or
   `POST /admin/reexport?stream=go&sequences=42,45-47`, to resend the retained
   bundles.
3. Let the high side import the missing predecessors and drain quarantine.

The low side retains bundles in `<root>/bundles` without automatic expiry.
Offline `backup`, `checkpoint`, and `retention` commands provide consistent
backups, signed receiver bootstrap, and explicit archive pruning after recovery
verification. See [backup, checkpoints, and retention](page/docs/recovery.md).
Back up that archive, stream sequence state, export index, and signing keys;
a fresh high side needs a verified checkpoint plus its subsequent bundles, or
its complete stream history replayed in order. A forced collect
does not bridge missing sequence history. High-side imported, duplicate, and
rejected files are reaped after seven days; quarantine waits for its gap to
fill. Plan disk capacity and retention on both sides.

For containers, the dashboard and `GET /admin/containers/discovery` distinguish
current reference coverage from retained history. Discovery status reports
attachment retrieval, not publisher-signature verification. With the high side
stopped, inspect stored OCI content without network access:

```bash
./artigate containers check --root /var/lib/artigate-high --json
```

`--repository registry/repo` limits the check; `--repair` rebuilds derived
indexes after content validation. Missing blobs and ambiguous aliases require
recollection. See [container operations](page/docs/ecosystems/containers.md#attachment-discovery-status),
[offline repair](page/docs/ecosystems/containers.md#offline-integrity-checks-and-repair),
and [troubleshooting](page/docs/troubleshooting.md).

## Contributing

Use the Go version in [go.mod](go.mod). From a checkout:

```bash
make build
make test       # unit tests, race detector, and coverage
make vet
make lint       # installs the golangci-lint version pinned by the Makefile
```

For dashboard changes, use `make ui` to compile the TypeScript and
`make ui-test` to run its behavior tests with Node.js 22+. Commit the generated
JavaScript with its source changes. `make help` lists the available targets.

The end-to-end suite runs real low/high processes, transfers signed bundles,
and consumes all 23 streams with native clients. Receiver clients use isolated
networks and fresh caches to check that the mirror supplies their dependencies.

```bash
make e2e         # local run; unavailable tools or upstreams may skip
make e2e-strict  # required-flow matrix, race detection, and no skips
```

End-to-end tests need Linux network namespaces, client toolchains, and network
access for provisioning and low-side collection. See [e2e/doc.go](e2e/doc.go)
for setup and environment options, and
[required_flows.json](e2e/required_flows.json) for the enforced matrix.

Keep changes focused, include relevant validation, and update the documentation
when behavior changes. The manual lives in [page/docs](page/docs/) and is built
with MkDocs Material using [page/mkdocs.yml](page/mkdocs.yml).

## Contributors

Thanks to everyone who contributes code, documentation, tests, and issue
reports. See the [contributors](https://github.com/define42/ArtiGate/graphs/contributors).

## License

ArtiGate is licensed under the [Apache License 2.0](LICENSE).
