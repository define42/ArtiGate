# Scheduling (watches)

A **watch** is a recurring collect: it re-runs a stored collect for exactly one ecosystem stream on a fixed interval, so a dependency like Python `requests` or the `alpine:3.20` image can be pulled every hour or every day without an operator triggering it each time.

Watches live entirely on the [low side](low-side.md). They are configured from the same ecosystem pages you use for a one-off collect, persisted in SQLite, and driven by a small in-process scheduler.

## What a watch does

A watch stores the **exact JSON body its page's collect would POST** (the `spec`) and replays it on a schedule. When the scheduler fires a watch it hands the stored spec straight to the same `Collect*` method that the interactive `/admin/<stream>/collect` endpoint calls — so a watch is a stored replay of the page's collect, nothing more.

Because it re-runs the real collect every time, a watch inherits all of that collect's behaviour:

- Moving references re-resolve on each run (see [below](#version-constraint-re-resolution)).
- [Export dedup](architecture.md#export-deduplication-and-delta-bundles) still applies: if every resolved file was already forwarded on that stream, no bundle is produced and no sequence number is consumed — the watch just records a "skipped" run. If only some files are new, the run emits a **delta bundle** carrying just the churn (the watch message counts the already-forwarded files).
- Per-unit fetch failures are collected as skipped units, not fatal, so one broken reference never blocks the batch.

A watch can target any of the thirteen known streams:

```text
go   python   maven   apt   rpm   containers   npm   hf
crates   terraform   helm   nuget   apk
```

## Adding a schedule from an ecosystem page

Every ecosystem page — [Go](ecosystems/go.md), [Python](ecosystems/python.md), [Maven](ecosystems/maven.md), [NPM](ecosystems/npm.md), [APT](ecosystems/apt.md), [RPM](ecosystems/rpm.md), [Containers](ecosystems/containers.md), [AI models](ecosystems/ai-models.md), [Rust crates](ecosystems/crates.md), [Terraform / OpenTofu](ecosystems/terraform.md), [Helm charts](ecosystems/helm.md), [NuGet](ecosystems/nuget.md), and [Alpine (apk)](ecosystems/apk.md) — has a **"Schedule the above"** row beneath its collect form. Fill in the collect form as you would for a one-off export, then:

1. Enter a number in the **every** field.
2. Choose **hours** or **days** (days is the default).
3. Submit. The page builds the same spec its "Collect & export" button would send and POSTs it to `POST /admin/watches`.

The interval you pick is converted to seconds (`hours` × 3600, `days` × 86400) and sent as `interval_seconds`.

!!! note "The UI offers hours and days; the API accepts anything ≥ 1 minute"
    The scheduling row only exposes hours and days, but the underlying API accepts any `interval_seconds`. The enforced floor is **1 minute** (`minWatchInterval`); shorter intervals are rejected with HTTP 400.

A freshly created watch is always **enabled** and its next run time is set to *now*, so it fires on the next scheduler tick.

### Example: schedule a Python collect every hour

The spec is whatever the Python page would POST — here, a `requirements` collect. Sending it directly:

```bash
curl -X POST http://localhost:8080/admin/watches \
  -H 'Content-Type: application/json' \
  -d '{
        "stream": "python",
        "label": "requests hourly",
        "interval_seconds": 3600,
        "spec": { "requirements": ["requests==2.32.3"] }
      }'
```

The response is the created `Watch`, including its assigned `id`.

### Example: schedule a container image daily

```bash
curl -X POST http://localhost:8080/admin/watches \
  -H 'Content-Type: application/json' \
  -d '{
        "stream": "containers",
        "label": "alpine base",
        "interval_seconds": 86400,
        "spec": { "images": ["alpine:3.20"] }
      }'
```

!!! tip "The spec is the page's collect body"
    Anything the ecosystem page accepts is a valid spec: `{"modules": [...], "resolve_deps": true}` for Go, `{"coordinates": [...]}` or `{"pom_xml": "..."}` for Maven, `{"packages": [...]}` for NPM, `{"source_list": "...", "newest_only": true}` for APT, and so on. The spec is stored verbatim as text and replayed unchanged.

## Version-constraint re-resolution

The stored spec is replayed literally, but the *upstream resolution* happens fresh on every run. What that means depends on how pinned the spec is:

| Spec references | Behaviour on each run |
|---|---|
| Container version constraint (e.g. `golang:1.26.x`, `golang:>=1.24,<2.0`) | Re-resolved against the upstream tag list **at that run** — the schedule tracks new matching releases through the diode automatically |
| Moving container tag (e.g. `alpine:3.20`) | Re-resolved to whatever manifest/digest the tag points to **at that run** — new pushes are picked up |
| Pinned digest (e.g. `ghcr.io/org/app@sha256:…`) | Always the same content; dedup decides whether a new bundle is emitted |
| Go `module@latest` or `resolve_deps: true` | The module graph is re-resolved each run, so newly published versions are pulled |
| Hugging Face branch (e.g. `openai/gpt-oss-20b@main`) | Re-resolved to the branch's current commit; a moved branch adds the new snapshot |
| Bare crate / provider / chart / NuGet spec (e.g. `serde`, `hashicorp/aws`, `nginx`, `Serilog`) | Re-resolved to the newest release **at that run**, so the schedule tracks new versions through the diode automatically |
| Alpine branch/repo selection (e.g. `v3.22/main`) | The `APKINDEX` is re-fetched and its (newest-only by default) packages re-mirrored — note the index declares no whole-file hash, so unchanged `.apk`s are re-**downloaded** on the low side and deduped at export |
| Pinned version (e.g. `requests==2.32.3`) | Same content each run; only dedup decides whether anything is sent |

For containers specifically, every run re-parses the image refs and re-mirrors them. Only `linux/amd64` is mirrored; per-image fetch failures are collected as skipped units (surfaced in the watch message as "N skipped") rather than aborting the batch. A scheduled pull of a **private** upstream authenticates via the low side's standing-credential variables — `ARTIGATE_CONTAINER_AUTH` for containers, `ARTIGATE_UPSTREAM_AUTH` for git/APT/RPM/Alpine — never via the spec: specs are stored and echoed in plaintext, so any spec carrying an `auth` key is rejected with HTTP 400. See [Container images](ecosystems/containers.md#private-registries) for the container details.

In short: a watch on a moving reference keeps up with the upstream; a watch on a pinned reference is a no-op after its first successful run, cheaply skipped by dedup.

## Managing schedules

You can manage watches from two places in the low-side UI:

- **The ecosystem page** lists that stream's own watches.
- **The Overview** page ("Scheduled pulls") lists **every** watch across all ecosystems, with a Stream column, last run, status pill, next run, and per-row actions.

Both views back onto the same `/admin/watches*` API.

| Action | Effect |
|---|---|
| **Pause / disable** | Sets `enabled = 0`. The scheduler stops firing it; `next_run_at` is left untouched. |
| **Enable** | Sets `enabled = 1` **and** `next_run_at = now`, so re-enabling makes it due promptly. |
| **Run now** | Runs the watch immediately in the background, regardless of schedule. |
| **Edit** | Opens the watch's label, interval, and stored collect spec for editing in place. The id, stream, enabled state, and run history are kept. |
| **Delete** | Removes the watch permanently. |

### Editing a schedule

**Edit** (available in both views) opens a dialog with the watch's label, its interval, and the stored spec as editable JSON — so you can add a requirement to a Python schedule or bump an interval without deleting and recreating the watch (which would lose its run history). Saving POSTs `/admin/watches/update`.

Two things to know about an edit's timing:

- **The next run is re-spaced from the last run.** After an edit, a watch that has run before gets `next_run_at = last_run_at + interval`, so shortening the interval can make it due immediately; lengthening pushes the next run out. A watch that has never run keeps its next-run time (it is already due from creation).
- **An in-flight run keeps the old spec.** A run that is already queued or running uses the spec it was enqueued with; the edited spec applies from the next run.

The stream itself cannot be changed — a spec only makes sense for the stream it was written for. To move a schedule to a different ecosystem, delete it and create a new one from that ecosystem's page.

!!! warning "Run now returns immediately and is fire-and-forget"
    A collect can take minutes, so `POST /admin/watches/run` starts the run in the background on a detached context and returns `{"status":"started"}` right away. That response says nothing about the collect's eventual outcome — poll `GET /admin/watches` and read the status fields to see how it went. Because the run detaches from the request, it is **not** cancelled when the HTTP request ends or the server shuts down.

An **in-flight guard** prevents the same watch running twice at once: if a run-now overlaps a scheduler tick (or a slow run overlaps the next tick), the second attempt is a no-op. Different watches, and different streams, still run independently.

## Status fields

Each watch tracks the outcome of its last run and when it will next fire. These are the fields shown in the UI and returned by `GET /admin/watches`:

| Field | JSON | Meaning |
|---|---|---|
| Last run | `last_run_at` | When the watch last executed. Omitted until the first run. |
| Status | `last_status` | `"ok"` or `"error"` (omitted from the JSON, like `last_message`, until the first run — the stored DB value defaults to an empty string). |
| Message | `last_message` | Human-readable outcome (bundle summary, "skipped", or the error string). |
| Next run | `next_run_at` | When the scheduler will next fire it. Always set. |

The `last_message` is built from the run result:

| Outcome | Message |
|---|---|
| New content exported | `bundle <bundle-id>: <N> unit(s)` — with `, <n> file(s) already forwarded` appended for a delta bundle, and `, <n> skipped` if any units failed |
| Dedup skip (nothing new) | `no new content since last export; skipped` |
| No bundle produced | `no bundle produced` |
| HTTP diode upload failed | the success message plus `; diode upload failed: <error>` — the bundle is committed and staged for re-transmit |
| Failure | the error string |

!!! note "Next-run is computed from the run's finish time"
    After a run, `next_run_at = finish_time + interval`. Intervals therefore drift by the run duration and are not aligned to wall-clock boundaries. There is no catch-up: a watch that became due many times while the scheduler was down fires once, then re-schedules from now.

## Where watches are stored

Watches are persisted in a dedicated SQLite database at `<root>/watches.db`, where `<root>` is the low-side `--root` (default `/var/lib/artigate-low`). It is opened during low-side startup and is separate from the low side's other state (`exported.db`, the export-dedup index, and `low-state.json`, the sequence state).

- The driver is the pure-Go `modernc.org/sqlite` — no cgo.
- The connection pool is capped at a single writer (`SetMaxOpenConns(1)`) with `PRAGMA busy_timeout=5000`, so the scheduler and the UI serialize instead of hitting "database is locked".
- Timestamps are stored as fixed-width RFC3339 UTC text, which sorts and compares correctly as SQL text.

The `watches` table schema:

```sql
CREATE TABLE IF NOT EXISTS watches (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  stream           TEXT    NOT NULL,
  label            TEXT    NOT NULL,
  spec             TEXT    NOT NULL,
  interval_seconds INTEGER NOT NULL,
  enabled          INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT    NOT NULL,
  last_run_at      TEXT,
  last_status      TEXT    NOT NULL DEFAULT '',
  last_message     TEXT    NOT NULL DEFAULT '',
  next_run_at      TEXT    NOT NULL
)
```

## The scheduler and `--watch-interval`

The scheduler is a single in-process goroutine on the low side. It is controlled by one flag:

```bash
artigate low --watch-interval=60s   # default
```

| Flag | Default | Purpose |
|---|---|---|
| `--watch-interval` | `60s` | How often the scheduler checks for due watches. `0` disables scheduled watches entirely. |

The value is a Go duration, so `30s`, `5m`, and `1h` are all valid. On each tick the scheduler queries the watches whose `next_run_at` has arrived (`enabled = 1 AND next_run_at <= now`, ordered by ID) and runs them **sequentially, one at a time**.

!!! warning "The tick is the polling granularity, not the schedule"
    A watch fires on the first tick at or after its `next_run_at`, so the effective latency to a run is up to one `--watch-interval`. A too-coarse tick (say `1h`) means a watch scheduled "every 30 minutes" still only fires hourly. Because due watches run sequentially within a tick, a long collect delays the other watches due in the same tick.

!!! note "`--watch-interval 0` disables only the scheduler"
    With `--watch-interval 0` no scheduler goroutine starts, so **nothing fires automatically**. Manual **Run now** (`POST /admin/watches/run`) still works.

## The `/admin/watches*` API

The watch endpoints live under `/admin/` on the low side and are subject to the low-side auth middleware when `ARTIGATE_LOW_AUTH` is set. See the [HTTP API reference](api.md) for the full request/response schemas.

| Method + Path | Body | Response |
|---|---|---|
| `GET /admin/watches` | — | `{"watches":[…]}` |
| `POST /admin/watches` | `{stream, label, spec, interval_seconds}` | the created `Watch` (with `id`) |
| `POST /admin/watches/update` | `{id, label?, spec?, interval_seconds?}` | the updated `Watch` |
| `POST /admin/watches/run` | `{"id":<n>}` | `{"status":"started"}` |
| `POST /admin/watches/enable` | `{"id":<n>}` | `{"status":"ok"}` |
| `POST /admin/watches/disable` | `{"id":<n>}` | `{"status":"ok"}` |
| `POST /admin/watches/delete` | `{"id":<n>}` | `{"status":"ok"}` |

Notes on the request bodies:

- On **create**, `spec` is sent as a raw JSON object (not a string) and stored verbatim; `label` defaults to `stream` when blank; the watch is always created enabled. The body limit is 8 MiB. Validation rejects unknown streams, intervals below 1 minute, empty or invalid-JSON specs, and specs carrying an `auth` key (credentials must never be stored — use `ARTIGATE_CONTAINER_AUTH` / `ARTIGATE_UPSTREAM_AUTH`) with HTTP 400. The same `auth` check runs again at **run time**, so a spec stored before this guard existed fails its runs with the same message instead of ever using the stored login — recreate the watch without credentials and put the login in the standing-credential variable.
- On **update**, only `id` is required (unknown id → HTTP 404): a blank `label`, an omitted or `null` `spec`, and a zero `interval_seconds` each keep the watch's current value, and the merged result is validated like a create. The stream cannot be changed. The body limit is 8 MiB. See [Editing a schedule](#editing-a-schedule) for how the next run is re-spaced.
- The **run / enable / disable / delete** endpoints all take `{"id":<n>}` (read up to 64 KiB); a missing or non-positive `id` returns HTTP 400, and **run** returns HTTP 404 if no watch has that id.

### List watches

```bash
curl http://localhost:8080/admin/watches
```

```json
{
  "watches": [
    {
      "id": 1,
      "stream": "python",
      "label": "requests hourly",
      "spec": "{\"requirements\":[\"requests==2.32.3\"]}",
      "interval_seconds": 3600,
      "enabled": true,
      "created_at": "2026-07-05T09:00:00Z",
      "last_run_at": "2026-07-05T10:00:12Z",
      "last_status": "ok",
      "last_message": "no new content since last export; skipped",
      "next_run_at": "2026-07-05T11:00:12Z"
    }
  ]
}
```

### Edit a watch

```bash
# change the interval to 2 hours and swap the spec; blank/omitted fields keep
# their current value, and the stream stays fixed
curl -X POST http://localhost:8080/admin/watches/update \
  -H 'Content-Type: application/json' \
  -d '{
        "id": 1,
        "interval_seconds": 7200,
        "spec": { "requirements": ["requests==2.32.4", "urllib3"] }
      }'
```

The response is the updated `Watch`.

### Trigger, pause, resume, and remove a watch

```bash
# run it now (background; poll the list for the outcome)
curl -X POST http://localhost:8080/admin/watches/run     -d '{"id":1}'

# pause it (scheduler stops firing it)
curl -X POST http://localhost:8080/admin/watches/disable -d '{"id":1}'

# resume it (also makes it due immediately)
curl -X POST http://localhost:8080/admin/watches/enable  -d '{"id":1}'

# delete it permanently
curl -X POST http://localhost:8080/admin/watches/delete  -d '{"id":1}'
```

## Related pages

- [Low side](low-side.md) — the server that hosts watches and runs the scheduler.
- [Ecosystems](ecosystems/index.md) — the collect forms each watch replays.
- [Container images (OCI)](ecosystems/containers.md) — moving-tag re-resolution in detail.
- [HTTP API reference](api.md) — full `/admin/watches*` schemas.
- [Troubleshooting & limitations](troubleshooting.md) — scheduler gotchas consolidated.
