# Ansible Galaxy collections

ArtiGate mirrors **Ansible Galaxy collections** across a data diode. The low side resolves each collection (and, by default, its dependencies) through the Galaxy **v3 API**, downloading every artifact verified against the API-declared **SHA-256 and size**. The high side regenerates a Galaxy v3 API from each artifact's **own embedded `MANIFEST.json`** and serves it under `/galaxy/`, so `ansible-galaxy collection install -s <mirror>` works air-gapped.

!!! note "Metadata comes from the artifacts, not the upstream API"
    The high side never replays transferred API documents. Every served collection page, version list, and version detail is rebuilt from the `MANIFEST.json` inside each verified `.tar.gz` — with the artifact's SHA-256 and size recomputed from the file on disk.

## How it works

```text
  collection specs ("ansible.posix", "community.general@8.5.0")
        │
        ▼
  resolve via <server>/api/v3/collections/<ns>/<name>/[versions/…]
        │
        ▼
  download each artifact ──▶ verify API-declared SHA-256 + size
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        regenerate the Galaxy v3 API from each
                        artifact's embedded MANIFEST.json, under /galaxy/
```

## Low side: input

`POST /admin/galaxy/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "collections": ["ansible.posix", "community.general@8.5.0"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `collections` | `[]string` | **Required.** Collection specs: `namespace.name` for the newest version, `namespace.name@8.5.0` to pin — a pin must be a full three-part semver version |
| `no_deps` | bool | Mirror only the listed collections, skipping their dependencies |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

`--galaxy-server` points the collector at another Galaxy server (default `https://galaxy.ansible.com`). There is no auth field. Scheduled [watches](../scheduling.md) are supported.

### Resolution and download

A bare spec takes the collection's `highest_version` from the v3 API; a pinned spec fetches that version directly; dependency **constraints** from each collection's metadata (`==`, `!=`, `>=`, `<=`, `>`, `<`, `^`, `~`, comma-AND, `*`) are resolved against the paginated version list, newest satisfying version wins, prereleases matching only when the constraint itself names one. The closure is capped at 500 collections, first-requirement-wins per collection; per-collection failures are skipped into `skipped_modules`.

Each artifact must be named canonically (`<ns>-<name>-<version>.tar.gz`) and is downloaded verifying **both** the API-declared SHA-256 and exact size — a mismatch fails the collect without burning a sequence number.

## High side: v3 API regeneration

| Route | Response |
|---|---|
| `GET /galaxy/api/` | Discovery: `{"available_versions": {"v3": "v3/"}}` |
| `GET /galaxy/api/v3/collections/<ns>/<name>/` | Collection page with `highest_version` |
| `GET /galaxy/api/v3/collections/<ns>/<name>/versions/` | Version list, newest first (single page) |
| `GET /galaxy/api/v3/collections/<ns>/<name>/versions/<version>/` | Version detail: `artifact{filename,sha256,size}`, `download_url`, `metadata.dependencies` |
| `GET /galaxy/download/<ns>-<name>-<version>.tar.gz` | The collection artifact |

`download_url` is absolute and points back at the serving host. Only versions whose artifact is present are served — removing an artifact 404s every route for it.

## Client setup

```bash
ansible-galaxy collection install ansible.posix -s https://artigate-high.local/galaxy/
```

```ini
# ansible.cfg — make the mirror the standing server
[galaxy]
server_list = mirror

[galaxy_server.mirror]
url=https://artigate-high.local/galaxy/
```

The client verifies each downloaded artifact against the served `artifact.sha256`, which the high side recomputed from the verified file.

## Limitations

- **No collection signatures.** The served version detail's `signatures` list is always empty — Galaxy GPG signature verification is not mirrored; integrity comes from the recomputed SHA-256 plus ArtiGate's signed-bundle chain.
- **No search API, minimal pagination.** The version list is one page (`limit`/`offset` ignored); `ansible-galaxy` handles both fine for install flows.
- **Pins are exact three-part versions** (`@1.5` or ranges are rejected in a spec; ranges belong in dependency constraints).
- **Prereleases** are only selected by a constraint that names one.
- **No private-server auth** on this stream.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged re-collect is skipped without consuming a sequence number; `"force": true` bypasses it.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
