# ArtiGate

[![codecov](https://codecov.io/gh/define42/ArtiGate/graph/badge.svg?token=RBKT8U26R8)](https://codecov.io/gh/define42/ArtiGate)

`ArtiGate` is a Go dependency mirror for one-way data-diode environments.

It contains two modes in one binary:

- `low`: internet-side GOPROXY pull-through server that can fetch from `proxy.golang.org`, `direct` VCS/GitHub, or private GitHub repos using normal `go`/`git` credentials. It records concrete `module@version` requests and exports signed bundle files.
- `high`: air-gapped, read-only GOPROXY server. It imports signed bundles in sequence, verifies all hashes, quarantines out-of-order future bundles until gaps are filled, and serves only complete module versions.

The implementation intentionally uses only the Go standard library. The low side invokes the installed `go` command to produce canonical `.info`, `.mod`, and `.zip` files in the normal Go module cache layout.

## Build

```bash
go build -o artigate ./cmd/artigate
```

## Create signing keys

```bash
./artigate keygen \
  --private ./low.ed25519 \
  --public ./high.ed25519.pub
```

Keep the private key only on the low side. Install the public key on the high side.

## Low side

```bash
./artigate low \
  --listen :8080 \
  --root /var/lib/artigate-low \
  --export-dir /var/spool/diode-out \
  --private-key /etc/artigate/low.ed25519 \
  --upstream-goproxy https://proxy.golang.org,direct \
  --goprivate github.com/your-org/* \
  --gonosumdb github.com/your-org/* \
  --export-interval 60s
```

Low-side Go clients:

```bash
go env -w GOPROXY=http://low-proxy:8080,off
```

For private GitHub modules, configure the service user's `git`/SSH credentials before starting the proxy, for example:

```bash
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"
ssh-keyscan github.com >> ~/.ssh/known_hosts
```

The low side writes these files for every export batch:

```text
go-bundle-000001.tar.gz
go-bundle-000001.manifest.json
go-bundle-000001.manifest.json.sig
```

The implementation uses `.tar.gz` because it is in the Go standard library. If you want `.tar.zst`, replace the gzip writer/reader with a zstd package such as `klauspost/compress/zstd`.

You can force an export immediately:

```bash
curl -XPOST http://127.0.0.1:8080/admin/export
```

You can list previously exported bundle sequences:

```bash
curl http://127.0.0.1:8080/admin/bundles
```

If the high side reports missing bundles, enter the missing number or range on the low side to regenerate those exact sequence numbers:

```bash
curl -XPOST 'http://127.0.0.1:8080/admin/reexport?sequences=42,45-47'
```

The same endpoint also accepts a raw body or JSON body:

```bash
curl -XPOST http://127.0.0.1:8080/admin/reexport \
  -H 'Content-Type: application/json' \
  -d '{"sequences":"42,45-47"}'
```

Re-exported bundles keep the original sequence number and `previous_sequence`. The manifest is signed again and the bundle files are rewritten in the export directory so they can be transferred through the diode again.

Protect the admin endpoints with firewall rules, a local-only listener, or a reverse proxy with authentication.

## Data diode

Transfer the three files together:

```text
go-bundle-NNNNNN.tar.gz
go-bundle-NNNNNN.manifest.json
go-bundle-NNNNNN.manifest.json.sig
```

The high side imports bundles strictly in sequence, but future bundles are **not rejected**. If bundle `000043` arrives while `000042` is missing, bundle `000043` is moved to the high-side quarantine directory. It stays there until `000042` arrives and is imported. The importer then automatically drains any consecutive quarantined bundles.

Duplicates and old replays are moved aside and are not imported.

## High side

```bash
./artigate high \
  --listen :8080 \
  --root /var/lib/artigate-high \
  --landing /var/spool/diode-in \
  --public-key /etc/artigate/high.ed25519.pub \
  --import-interval 10s
```

High-side Go clients:

```bash
go env -w GOPROXY=http://high-proxy:8080,off
go env -w GOSUMDB=off
```

For CI:

```bash
go build -mod=readonly ./...
go test -mod=readonly ./...
```

You can force an import immediately:

```bash
curl -XPOST http://127.0.0.1:8080/admin/import
```

You can ask the high side which bundle numbers/ranges are missing:

```bash
curl http://127.0.0.1:8080/admin/missing
```

The same status is available from:

```bash
curl http://127.0.0.1:8080/admin/status
```

Example response when bundle `42` is missing but `43`, `44`, and `47` are already quarantined:

```json
{
  "last_imported_sequence": 41,
  "next_expected_sequence": 42,
  "highest_seen_sequence": 47,
  "blocking_missing_sequence": 42,
  "missing_ranges": ["42", "45-46"],
  "landing_sequences": [],
  "quarantined_sequences": [43, 44, 47],
  "ready_to_import": false
}
```

After bundle `42` is received, `/admin/import` imports `42` and then automatically processes quarantined `43` and `44`. It will stop again at `45` until `45-46` are received.

## High-side latest/list behavior

The high side never trusts a transferred `list` or `latest` file as truth. It calculates them dynamically from completed module versions in its local repository.

A module version is visible only if these exist and a `.complete` marker has been written:

```text
<module>/@v/<version>.info
<module>/@v/<version>.mod
<module>/@v/<version>.zip
<module>/@v/<version>.complete
```

`@v/list` returns complete non-pseudo versions only.

`@latest` means "latest imported and approved in this mirror", selected as:

1. highest release version
2. else highest pre-release version
3. else newest pseudo-version by `.info` time

## Notes and limitations

- This is a production-oriented starter implementation, not a full artifact-management product.
- It does not implement sumdb mirroring. On the high side use `GOSUMDB=off` and rely on committed `go.sum`, signed bundles, and manifest hashes.
- It uses JSON state files to keep the implementation dependency-free. Use SQLite/PostgreSQL if you need multiple writers or a larger approval workflow.
- Admin endpoints are unauthenticated. Bind to localhost or protect them.
- High-side gaps and out-of-order future bundles are quarantined, not rejected. Check `/admin/missing` and re-export the requested range from the low side with `/admin/reexport`.
- Low-side fetching depends on the installed Go toolchain and Git/VCS tools.
- High side never invokes `go` and has no upstream fetcher.
