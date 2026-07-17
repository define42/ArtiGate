# Uploads (arbitrary files)

The **uploads** stream carries arbitrary files across the diode with no package ecosystem behind them — an installer, a dataset, a PDF, a model file. Pick a folder name, upload one or more files, and the high side serves them at `/uploads/<folder>/<name>`, lists them on its dashboard under **Uploads**, and — uniquely among the streams — lets the operator **delete** a file there again.

!!! note "The two deliberate exceptions"
    Uploads bend two rules every other stream follows. **Export dedup is never consulted** — every upload ships in full, so a file deleted on the high side comes back by simply uploading it again (an "already forwarded" skip would silently withhold it). And the `uploads/` tree is **mutable**: re-uploading a name replaces the file, and the high side's delete endpoint can remove one. Everything else ArtiGate serves stays immutable.

## How it works

```text
  folder name + files (multipart upload)
        │
        ▼
  stream each file to disk, SHA-256 it     (nothing buffered in memory)
        │
        ▼
  signed ArtiGate bundle ══ diode ══▶ high side import
                                          │
                                          ▼
                        serve verbatim at /uploads/<folder>/<name>
                        (dashboard listing, per-file delete)
```

Files are verified like every other stream's artifacts — Ed25519 manifest signature, per-file SHA-256 — and served exactly as verified; there is no index to regenerate.

## Low side: input

`POST /admin/uploads/collect` — **`multipart/form-data`**, not JSON (add `?stream=1` for streamed progress, `?dry_run=1` for an estimate):

```bash
curl -fsS -X POST \
  -F "folder=tools" \
  -F "file=@installer.run" \
  -F "file=@README.pdf" \
  https://artigate-low.local/admin/uploads/collect
```

| Form field | Meaning |
|---|---|
| `folder` | **Required.** The folder the files land in (one path segment, ≤ 128 chars, no leading `.`, no `/` or `\`, no control characters) |
| `file` | One or more file parts. Names are reduced to their base name and validated by the same rules; the same name twice in one upload is rejected |

Files are **streamed to disk while being hashed** — nothing is buffered in memory, so multi-gigabyte files are fine (use `?stream=1` for live progress on those). Staging imposes no size limit, but a single file must still fit one diode bundle — **64 GiB** by default; check [Limitations](#limitations) before uploading anything near that. One upload may carry up to 10,000 files. The dashboard's **Uploads** card wraps the same endpoint with a folder field and a file picker.

There is no `force` field — uploads always behave as if forced (full bundle, dedup bypassed), and `prior_files` is always 0.

!!! warning "Uploads cannot be scheduled"
    There is no upstream to re-pull, so the uploads stream has no watch support — the scheduler rejects it with `uploads cannot be scheduled; upload again when the content changes`.

## High side: serving, listing, deleting

| Route | Method | Response |
|---|---|---|
| `/uploads/<folder>/<name>` | GET/HEAD | The file bytes (range and conditional requests supported; `Content-Type` by extension) |
| `/admin/uploads` | GET | JSON listing: folders with their files' names, sizes, and modification times |
| `/admin/uploads/delete` | POST | Delete one file: JSON body `{"folder": "tools", "name": "installer.run"}` → `{"status": "ok"}` (404 if absent) |

Deleting a folder's last file removes the folder from the listing — folders live only through their files. The delete endpoint is the **only** mutation of served content on the whole high side, and it answers **loopback callers only** unless `ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN=on` (set that when a published-port or reverse-proxy hop makes local admin appear non-loopback, and keep the listener restricted at the host). The read-only listing is not restricted.

## Client usage

```bash
curl -fsS -o installer.run https://artigate-high.local/uploads/tools/installer.run
```

The high-side dashboard's **Uploads** tree shows every folder and file with size, modification time, SHA-256, and a download link.

## Limitations

- **No scheduling** — upload again when the content changes.
- **No dedup, ever**: identical re-uploads still produce (and transfer) a full bundle. That is the price of "delete on the high side, restore by re-uploading".
- **Replace semantics**: re-uploading a name overwrites the served file on import.
- **Flat namespace rules**: folder and file names are single path segments (≤ 128 chars, no leading dot, no separators); browser-style paths in a file part are reduced to their base name.
- **A single file must fit one bundle.** The upload as a whole is unbounded — content beyond the per-bundle transport limit ships as consecutive sequenced bundles — but one file can never split across bundles: if its estimated archive (raw size plus just under 1% packing overhead) exceeds the limit, the collect fails at export, *after* the file has been streamed and hashed (cleanly — no sequence number is burned). The limit is **64 GiB**, and a small [UDP-pitcher](../data-diode.md) block geometry can lower it; the refusal then says which pitcher knob to raise.
- Bounds: the folder field is capped at 4 KiB and one upload at 10,000 parts; staging imposes no per-file size cap (files stream to disk).

## Related pages

- [Low side](../low-side.md) — operating the exporter
- [High side](../high-side.md) — operating the read-only mirror
- [Security & trust](../security.md) — the signing/verification chain
- [HTTP API reference](../api.md) — the exact request/response contracts
