# Python (PyPI)

ArtiGate mirrors Python packages by running `pip download` on the low side and serving the resulting distributions through the PEP 503 "Simple Repository API" on the high side. It mirrors **wheels by default**; packages that publish no wheel can be **opted into source distributions (sdists)** per package, fetched straight from the index's JSON API — never through pip — and verified against the API-declared SHA-256.

!!! note "Wheels first, and no build hooks either way"
    Every pip invocation passes `--only-binary=:all:`, and opted-in sdists bypass pip entirely (a plain HTTP download of the index-declared file). Either way no package-controlled build backend or metadata hook ever runs beside the low-side signing key and credentials. Wheel-based installs stay build-free on the high side; an opted-in sdist is built by the *client* at install time, exactly as it would be against PyPI.

For the shared bundle/diode model see [Architecture](../architecture.md); for running the two sides see [Low side](../low-side.md) and [High side](../high-side.md).

## Data flow

```text
  low side                                    diode              high side
  ─────────                                   ─────              ─────────
  pip download        →  *.whl     ┐
                                   ├──  signed bundle  ──▶  verify + store  →  /simple/ + /packages/
  index JSON API      →  *.tar.gz  ┘         (python stream)    (regenerated index HTML)
  (opted-in sdists)
```

- **Low side is collect-only.** It runs `python3 -m pip download` for the requirements, fetches any opted-in sdists from the index JSON API, and packs the distribution files into a numbered, Ed25519-signed ArtiGate bundle on the `python` sequence stream.
- **High side serves them** through the Simple Repository API: HTML index pages under `/simple/` plus file downloads under `/packages/`. It regenerates all index HTML from the distribution files actually present on disk — it trusts no transferred index metadata.

## Low side — inputs

### From the UI

The low-side dashboard has a **"Mirror Python packages (requirements)"** card. You paste requirements one per line (requirements.txt format) or load a `.txt` file:

```text
requests==2.32.4
urllib3>=2,<3
certifi
```

The client-side parser (`parseRequirements`) prepares the list before sending:

- Blank lines and `#` comment lines are dropped.
- Inline `# …` comments and trailing line-continuation backslashes are stripped.
- **pip option lines** — anything starting with `-` (e.g. `-r other.txt`, `--hash=…`, `--index-url …`) — are **set aside, not sent**. They are reported back as "Skipped N pip option line(s)".

Only the remaining PEP 508 requirement specifiers are POSTed to the collect endpoint.

### From the HTTP API

Endpoint: **`POST /admin/python/collect`** (add `?stream=1` for streamed progress). The JSON body is read with a **1 MiB limit**.

```json
{
  "requirements": ["requests==2.32.4", "urllib3>=2,<3"],
  "sdists": ["some-source-only-pkg", "another==1.2.3"],
  "target": {
    "python_version": "3.12",
    "abi": "cp312",
    "implementation": "cp",
    "platforms": ["manylinux_2_28_x86_64", "manylinux_2_34_x86_64"],
    "only_binary": true
  }
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `requirements` | `[]string` | PEP 508 requirement specifiers — the same content as `requirements.txt` lines. Resolved with pip, wheels only. At least one of `requirements` and `sdists` must be non-empty, else `no python requirements provided`. |
| `sdists` | `[]string` | [Opt-in sdist](#opt-in-sdists-for-packages-that-publish-no-wheel) specs, `name` (current release) or `name==1.2.3`. Fetched from the index JSON API, never through pip. |
| `target` | object | Optional [cross-target](#cross-target-a-different-interpreter-or-platform) selector. Omit to download for the low-side host's own interpreter. |
| `target.python_version` | string | pip `--python-version` (e.g. `3.12`). |
| `target.implementation` | string | pip `--implementation` (e.g. `cp`). |
| `target.abi` | string | pip `--abi` (e.g. `cp312`). |
| `target.platforms` | `[]string` | one pip `--platform` per entry (e.g. `manylinux_2_28_x86_64`). |
| `target.only_binary` | bool | Compatibility field: omit or set `true`. `false` is rejected because wheels-only collection is mandatory. |
| `force` | bool | bypass the export-dedup index for this collect — pack every wheel even if already forwarded (full, self-contained bundle). |

See the full HTTP surface in the [API reference](../api.md).

!!! warning "Argument-injection defense"
    Every caller-supplied string that becomes a pip argument — each requirement plus `python_version`, `implementation`, `abi`, and each platform — is validated (each `sdists` spec is checked against its own strict `name`/`name==version` grammar too). A value is **rejected if it starts with `-`**, is empty/whitespace-only, or contains a control character. This blocks smuggling a flag in as a requirement (e.g. `-r/etc/passwd` or `--index-url=http://attacker/`). Spaces are allowed on purpose, because PEP 508 environment markers contain them (e.g. `requests; python_version < "3.9"`).

## Wheels-only pip policy

Every pip invocation includes `--only-binary=:all:`. If any *requirement* has no compatible wheel, pip fails the collect before ArtiGate writes or signs a bundle. Pin a version that publishes a wheel, select the correct cross-target, exclude that package — or, for a package that publishes no wheel at all, list it in [`sdists`](#opt-in-sdists-for-packages-that-publish-no-wheel) instead.

As defense in depth, ArtiGate also ignores and reports any recognized source-distribution archive (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.zip`) produced by a broken or substituted pip executable. Only sdists that were explicitly opted in — fetched by ArtiGate itself, never by pip — are bundled. If no distributions result, the collect errors rather than writing an empty bundle.

## Opt-in sdists (for packages that publish no wheel)

Some projects publish no wheel at all. Rather than failing those forever, a collect can name them in the request's `sdists` list (an API-level field — the dashboard's requirements card does not expose it): `name` mirrors the current release's sdist, `name==1.2.3` pins one. Specs are validated against `^name(==version)?$` form — anything else is rejected with `invalid sdist spec … (use name or name==version)`.

How the fetch works — pip is deliberately not involved, because downloading an sdist with pip runs the package's own metadata build hooks:

1. The release is resolved through the index's **JSON API** (`<base>/<name>/json`, or `<base>/<name>/<version>/json` when pinned). The base defaults to `https://pypi.org/pypi`; `--pypi-json` points it at another index.
2. The release's sdist is selected (preferring the `.tar.gz` form over `.zip`), its filename validated as a plain, path-safe archive name belonging to the requested project.
3. The file is downloaded and verified against the **API-declared SHA-256**. A release whose index declares no sha256 is refused: an unverifiable file is never mirrored.
4. The sdist's `Requires-Python` metadata is read from the archive (bounded scan, nothing is executed) so the served index can carry `data-requires-python`.

Each failed sdist is skipped and reported in the result's `skipped_modules` — the wheels already collected are never at stake. Sdists are fetched **exactly as named**: their build dependencies are only mirrored if they resolve as wheels via `requirements` or are listed in `sdists` themselves.

!!! warning "Clients build opted-in sdists locally"
    An sdist installs by building on the *client* — `pip install` runs the package's build backend there, exactly as it would against PyPI, so those clients need the build toolchain (and any native compilers) the package requires. The wheels-only guarantee that nothing package-controlled runs applies to the **low side**, not to consumers of an opted-in sdist.

## Cross-target (a different interpreter or platform)

By default pip downloads wheels for the **low-side host's own** interpreter. To mirror wheels for the *high-side* target instead, set a cross-target. The UI exposes it under **"Cross-target for a different interpreter (optional)"** with fields for Python version (`3.12`), Implementation (`cp`), ABI (`cp312`), and Platforms (comma-separated).

pip renders these in this order:

```text
--only-binary=:all:              # always present
--python-version 3.12
--implementation cp
--abi cp312
--platform manylinux_2_28_x86_64
--platform manylinux_2_34_x86_64
```

Wheels-only applies equally to native and cross-target collects, including an `implementation`-only target.

## Internals — how collection runs

`pip download` is executed as:

```bash
<python> -m pip download --dest <dest> [target flags…] <requirement…>
```

- **Binary**: the `--python` flag (`PipBinary`), defaulting to **`python3`** when unset. So the full exec is typically `python3 -m pip download …`. See the [Configuration reference](../configuration.md).
- **Working directory**: the low-side `--root`.
- **Timeout**: a hard **10-minute** limit per invocation. A large dependency closure can time out.
- On failure the error wraps the combined stdout+stderr.

Collection then:

- Holds the **per-stream lock** for the `python` stream across the whole download → write → commit, so a concurrent Python collect cannot claim the same sequence number. Other ecosystem streams run in parallel.
- Stages into `<root>/python/staging/collect-*` (removed on return); pip's `--dest` is `<stage>/python/packages`, and opted-in sdists are fetched into the same directory afterwards.
- Hashes each distribution file with SHA-256 and records the manifest path `python/packages/<filename>`.
- Applies **export dedup**: a failed collect burns no sequence number; if every file was already forwarded on the `python` stream the collect skips entirely (no bundle written), and if only some are new the bundle is a [delta](../architecture.md#export-deduplication-and-delta-bundles) carrying just those (the rest ride as `prior` manifest references). `"force": true` bypasses the index.

The signed bundle manifest carries a `python` block grouping distribution files per `project@version` — a project can carry wheels and an sdist in one bundle — with each file's filename, path, SHA-256, and `requires_python` (read from the wheel's or sdist's own metadata; nothing is executed). The manifest's `yanked` field exists but is not populated by the collector.

## High side — serving the Simple Repository API

Distribution files live flat on disk at `<root>/python/packages`. The high side lists every file there that parses as a wheel — plus every source distribution mirrored through the sdist opt-in — and regenerates all index HTML on each request.

!!! note "Routes sit at the server root"
    Unlike npm (`/npm/`) or Maven (`/maven/`), the Python routes are **un-namespaced** — `/simple/` and `/packages/` at the server root, not under a `/python/` prefix.

Only `GET`/`HEAD` are allowed (else `405`). The dispatch:

| Path | Output |
|------|--------|
| `/simple` or `/simple/` | Root index — one `<a>` per distinct, sorted project name. |
| `/simple/<project>/` | Per-project links to that project's distribution files (wheels and opted-in sdists). |
| `/packages/<filename>` | The distribution file bytes. |

### Root index — `/simple/`

```http
GET /simple/
```

```html
<!DOCTYPE html>
<html>
  <body>
    <a href="/simple/requests/">requests</a>
    <a href="/simple/urllib3/">urllib3</a>
  </body>
</html>
```

Served as legacy PEP 503 **HTML** with `Content-Type: text/html; charset=utf-8` (not the PEP 691 JSON API).

### Project page — `/simple/<project>/`

The path segment is PEP 503-normalized (lowercase; runs of `-`, `_`, `.` collapse to a single `-`), so lookups are **case- and separator-insensitive**: `/simple/typing_extensions/`, `/simple/Typing-Extensions/`, and `/simple/typing.extensions/` all resolve to the same project (`typing-extensions`). If no distribution file matches, it returns `404 not found`.

Each link's `href` includes the SHA-256 as a URL fragment (the PEP 503 hash), computed live from the file on disk, and a `data-requires-python` attribute when the distribution's own metadata declares `Requires-Python`:

```html
<h1>Links for requests</h1>
<a href="/packages/requests-2.32.4-py3-none-any.whl#sha256=<64-hex>" data-requires-python="&gt;=3.8">requests-2.32.4-py3-none-any.whl</a>
```

### File download — `/packages/<filename>`

The store is flat: the filename must be non-empty and contain **no `/`** (else `404`), and the resolved path is traversal-guarded (an unsafe path returns `400 unsafe path`). Files are served with `HEAD` and range support.

## Client (pip) configuration

Point pip at the mirror as its **only** index. The high side's "Set me up" guide renders this with the live host filled in:

```ini
# /etc/pip.conf   (or ~/.config/pip/pip.conf)
[global]
index-url = https://artigate-high.local/simple/
disable-pip-version-check = true
```

```bash
pip install --only-binary=:all: -r requirements.txt   # wheel-only mirrors
pip install -r requirements.txt                       # if sdists were opted in
```

!!! warning "Do not add `--extra-index-url`"
    Mixing in another index reopens dependency-confusion risk. This mirror is the single source of truth. Client-side `--only-binary=:all:` is recommended when the mirror holds only wheels — it needs no compilers or build backends and matches exactly what the mirror holds. Leave it off for packages mirrored through the sdist opt-in: those must build on the client.

Note the mirror is set as `index-url`, not `--extra-index-url`. For scheduled/recurring mirroring of a requirements set see [Scheduling (watches)](../scheduling.md); for the trust model see [Security & trust](../security.md).

## Limitations

- **Wheels through pip; sdists only by explicit opt-in.** A *requirement* with no compatible wheel still fails the collect — pin a wheel-bearing version, choose the correct target, or list the package in `sdists` instead. Opted-in sdists are fetched exactly as named (no dependency resolution) and require an index-declared SHA-256.
- **10-minute pip timeout.** A large dependency closure can exceed it; split the requirements or run a narrower target.
- **No `yanked` metadata.** The manifest field exists but is never populated, and the `/simple/` HTML emits no `data-yanked` attribute. (`Requires-Python` *is* served, as `data-requires-python`, read from each distribution's own metadata.)
- **Legacy HTML Simple API only.** ArtiGate serves PEP 503 HTML, not the PEP 691 JSON API. Hashes are attached as live-computed `#sha256=` fragments.

See consolidated limitations and fixes in [Troubleshooting & limitations](../troubleshooting.md).

## See also

- [Ecosystems overview](index.md) — the hub for every mirrored ecosystem.
- [Go modules](go.md), [Java (Maven)](maven.md), [NPM](npm.md), [APT (Debian/Ubuntu)](apt.md), [RPM (RHEL/Fedora)](rpm.md), [Container images (OCI)](containers.md), [AI models (Hugging Face)](ai-models.md) — sibling ecosystem pages.
- [Low side](../low-side.md) · [High side](../high-side.md) · [Architecture](../architecture.md) · [Configuration reference](../configuration.md) · [HTTP API reference](../api.md) · [Deployment](../deployment.md).
