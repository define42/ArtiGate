# VS Code extensions (Open VSX)

ArtiGate mirrors **VS Code extensions** from [Open VSX](https://open-vsx.org) across a data diode. The low side fetches each extension's `.vsix` (verifying the registry-published SHA-256 when one is available) together with its dependencies and extension packs. The high side regenerates gallery metadata from each archive's **own embedded `extension/package.json`** and answers the VS Code **gallery query API** at `/vsx/gallery`, so VSCodium and other gallery-configurable editors install extensions air-gapped — or you download the `.vsix` files directly.

!!! note "Open VSX, not the Microsoft Marketplace"
    Extensions are fetched from Open VSX (`--vsx-registry` overrides the default `https://open-vsx.org`). Microsoft's marketplace terms do not permit mirroring; VSCodium and friends use Open VSX ids, which are usually identical (`golang.Go`, `redhat.vscode-yaml`, …).

## How it works

```text
  extension ids ("golang.Go", "redhat.vscode-yaml@1.14.0")
        │
        ▼
  fetch <registry>/api/<publisher>/<name>[/<version>]
        │
        ▼
  download each .vsix (verify SHA-256 when published)
  follow dependencies + extension packs (at newest)
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        regenerate gallery metadata from each archive's
                        embedded package.json; serve /vsx/gallery + /vsx/files/
```

## Low side: input

`POST /admin/vsx/collect` (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate). Body limit **1 MiB**.

```json
{
  "extensions": ["golang.Go", "redhat.vscode-yaml@1.14.0"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `extensions` | `[]string` | **Required.** Extension ids: `publisher.name` for the newest version, `publisher.name@1.14.0` to pin (`@latest` equals the bare form) |
| `no_deps` | bool | Mirror only the listed extensions, skipping dependencies and extension packs |
| `force` | bool | Bypass the export-dedup index (full, self-contained bundle) |

There is no auth field. Scheduled [watches](../scheduling.md) are supported.

### Resolution and download

Each id is resolved through the Open VSX API (`/api/<publisher>/<name>`, or `…/<version>` when pinned). Unless `no_deps` is set, the extension's **dependencies and `bundledExtensions` (extension packs)** are queued too — always at their newest version, like a fresh client install — capped at 300 extensions, first-version-wins per id. Individually unfetchable extensions are skipped into `skipped_modules` rather than aborting the batch.

The `.vsix` is downloaded from the API-declared download URL. When the registry publishes a **SHA-256** for the file it is verified during download (a mismatch fails that extension); when it publishes none, the download is TLS-trusted to the configured registry and hash-locked into the signed bundle from there.

## High side: gallery regeneration

On import, each archive's embedded `extension/package.json` is extracted (8 MiB cap) and must name exactly the manifest's publisher, name, and version — a mismatch is logged and that version stays out of the gallery, though the hash-verified `.vsix` itself remains downloadable. Serving:

| Route | Response |
|---|---|
| `POST /vsx/gallery/extensionquery` | The VS Code gallery query API (the one endpoint that accepts POST) |
| `GET /vsx/assets/<publisher>/<name>/<version>/<assetType>` | Gallery assets — the `.vsix` (`Microsoft.VisualStudio.Services.VSIXPackage`) and the manifest (`Microsoft.VisualStudio.Code.Manifest`) |
| `GET /vsx/files/<publisher>/<name>/<publisher>.<name>-<version>.vsix` | Direct `.vsix` download |

Query support covers what editors actually send: exact-id lookup (filterType 7), free-text search (filterType 10, case-insensitive substring), and pagination (default page size 50, max 200). Version entries carry the engine (`engines.vscode`), dependency, and extension-pack properties read from each `package.json`. Only versions whose `.vsix` is present are served.

## Client setup

```bash
# VSCodium / code-oss — point the gallery at the mirror
export VSCODE_GALLERY_SERVICE_URL=https://artigate-high.local/vsx/gallery
codium --install-extension golang.Go
```

```json
// …or permanently, in the editor's product.json
{ "extensionsGallery": { "serviceUrl": "https://artigate-high.local/vsx/gallery" } }
```

```bash
# …or download the .vsix directly and install it offline
curl -fL -o golang.Go.vsix \
  https://artigate-high.local/vsx/files/golang/Go/golang.Go-0.42.1.vsix
codium --install-extension ./golang.Go.vsix
```

## Limitations

- **Gallery subset.** No ratings/statistics, no README/changelog/icon assets, and search is a plain substring match — enough for install/update flows, not a marketplace browse experience.
- **Universal builds only.** The registry's platform-independent download is mirrored; target-platform-specific `.vsix` variants are not selected.
- **Dependencies and packs pull at newest** — pinning a root extension does not pin what it depends on.
- **Digest verification is upstream-dependent**: Open VSX publishes SHA-256s for most files; when absent, the low-side download is TLS-trusted.
- **No private-registry auth** on this stream.
- [Export dedup](../architecture.md#export-deduplication-and-delta-bundles) applies: an unchanged re-collect is skipped without consuming a sequence number; `"force": true` bypasses it.

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Scheduling (watches)](../scheduling.md) — recurring collects
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
