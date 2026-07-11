# Python (PyPI)

ArtiGate mirrors Python packages by running `pip download` on the low side and serving the resulting wheels through the PEP 503 "Simple Repository API" on the high side. It mirrors **wheels only** — source distributions (sdists) are never served.

!!! note "Wheels only, by design"
    ArtiGate always passes `--only-binary=:all:` to pip and never mirrors sdists. This keeps package-controlled build backends and metadata hooks away from the low-side signing key and credentials. Air-gapped installs receive prebuilt wheels with no compilers or build backends required.

For the shared bundle/diode model see [Architecture](../architecture.md); for running the two sides see [Low side](../low-side.md) and [High side](../high-side.md).

## Data flow

```text
  low side                         diode              high side
  ─────────                        ─────              ─────────
  pip download  →  *.whl  →  signed bundle  ──▶  verify + store  →  /simple/ + /packages/
                (python stream)                  (regenerated index HTML)
```

- **Low side is collect-only.** It runs `python3 -m pip download`, collects the `.whl` files, and packs them into a numbered, Ed25519-signed ArtiGate bundle on the `python` sequence stream.
- **High side serves them** through the Simple Repository API: HTML index pages under `/simple/` plus wheel downloads under `/packages/`. It regenerates all index HTML from the wheels actually present on disk — it trusts no transferred index metadata.

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
| `requirements` | `[]string` | PEP 508 requirement specifiers — the same content as `requirements.txt` lines. **Required**; an empty list returns `no python requirements provided`. |
| `target` | object | Optional [cross-target](#cross-target-a-different-interpreter-or-platform) selector. Omit to download for the low-side host's own interpreter. |
| `target.python_version` | string | pip `--python-version` (e.g. `3.12`). |
| `target.implementation` | string | pip `--implementation` (e.g. `cp`). |
| `target.abi` | string | pip `--abi` (e.g. `cp312`). |
| `target.platforms` | `[]string` | one pip `--platform` per entry (e.g. `manylinux_2_28_x86_64`). |
| `target.only_binary` | bool | Compatibility field: omit or set `true`. `false` is rejected because wheels-only collection is mandatory. |
| `force` | bool | bypass the export-dedup index for this collect — pack every wheel even if already forwarded (full, self-contained bundle). |

See the full HTTP surface in the [API reference](../api.md).

!!! warning "Argument-injection defense"
    Every caller-supplied string that becomes a pip argument — each requirement plus `python_version`, `implementation`, `abi`, and each platform — is validated. A value is **rejected if it starts with `-`**, is empty/whitespace-only, or contains a control character. This blocks smuggling a flag in as a requirement (e.g. `-r/etc/passwd` or `--index-url=http://attacker/`). Spaces are allowed on purpose, because PEP 508 environment markers contain them (e.g. `requests; python_version < "3.9"`).

## Mandatory wheels-only policy

Every invocation includes `--only-binary=:all:`. If any requirement has no compatible wheel, pip fails the collect before ArtiGate writes or signs a bundle. Pin a version that publishes a wheel, select the correct cross-target, or exclude that package.

As defense in depth, ArtiGate also ignores and reports any recognized source-distribution archive (`.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.zip`) produced by a broken or substituted pip executable. Those files are never bundled. If no wheels result, the collect errors rather than writing an empty bundle.

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
- Stages into `<root>/python/staging/collect-*` (removed on return); pip's `--dest` is `<stage>/python/packages`.
- Hashes each wheel with SHA-256 and records the manifest path `python/packages/<filename>`.
- Applies **export dedup**: a failed collect burns no sequence number; if every wheel was already forwarded on the `python` stream the collect skips entirely (no bundle written), and if only some are new the bundle is a [delta](../architecture.md#export-deduplication-and-delta-bundles) carrying just those (the rest ride as `prior` manifest references). `"force": true` bypasses the index.

The signed bundle manifest carries a `python` block grouping wheels per `project@version`, with each file's filename, path, and SHA-256. (The manifest's `requires_python` and `yanked` fields exist but are not populated by the collector.)

## High side — serving the Simple Repository API

Wheels live flat on disk at `<root>/python/packages`. The high side lists every file there that parses as a wheel (`scanPyFiles`) and regenerates all index HTML on each request.

!!! note "Routes sit at the server root"
    Unlike npm (`/npm/`) or Maven (`/maven/`), the Python routes are **un-namespaced** — `/simple/` and `/packages/` at the server root, not under a `/python/` prefix.

Only `GET`/`HEAD` are allowed (else `405`). The dispatch:

| Path | Output |
|------|--------|
| `/simple` or `/simple/` | Root index — one `<a>` per distinct, sorted project name. |
| `/simple/<project>/` | Per-project links to that project's wheel files. |
| `/packages/<filename>` | The wheel file bytes. |

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

The path segment is PEP 503-normalized (lowercase; runs of `-`, `_`, `.` collapse to a single `-`), so lookups are **case- and separator-insensitive**: `/simple/typing_extensions/`, `/simple/Typing-Extensions/`, and `/simple/typing.extensions/` all resolve to the same project (`typing-extensions`). If no wheel matches, it returns `404 not found`.

Each link's `href` includes the SHA-256 as a URL fragment (the PEP 503 hash), computed live from the file on disk:

```html
<h1>Links for requests</h1>
<a href="/packages/requests-2.32.4-py3-none-any.whl#sha256=<64-hex>">requests-2.32.4-py3-none-any.whl</a>
```

### Wheel download — `/packages/<filename>`

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
pip install --only-binary=:all: -r requirements.txt
```

!!! warning "Do not add `--extra-index-url`"
    Mixing in another index reopens dependency-confusion risk. This mirror is the single source of truth. Client-side `--only-binary=:all:` is recommended for air-gapped installs — it needs no compilers or build backends and matches exactly what the mirror holds.

Note the mirror is set as `index-url`, not `--extra-index-url`. For scheduled/recurring mirroring of a requirements set see [Scheduling (watches)](../scheduling.md); for the trust model see [Security & trust](../security.md).

## Limitations

- **Wheels only, period.** Sdist-only packages fail collection. Pin a version that ships a compatible wheel, choose the correct target, or exclude the package.
- **10-minute pip timeout.** A large dependency closure can exceed it; split the requirements or run a narrower target.
- **No `requires-python` / `yanked` metadata.** These manifest fields exist but are never populated, and the `/simple/` HTML emits no `data-requires-python` or `data-yanked` attributes.
- **Legacy HTML Simple API only.** ArtiGate serves PEP 503 HTML, not the PEP 691 JSON API. Hashes are attached as live-computed `#sha256=` fragments.

See consolidated limitations and fixes in [Troubleshooting & limitations](../troubleshooting.md).

## See also

- [Ecosystems overview](index.md) — the hub for all eight ecosystems.
- [Go modules](go.md), [Java (Maven)](maven.md), [NPM](npm.md), [APT (Debian/Ubuntu)](apt.md), [RPM (RHEL/Fedora)](rpm.md), [Container images (OCI)](containers.md), [AI models (Hugging Face)](ai-models.md) — sibling ecosystem pages.
- [Low side](../low-side.md) · [High side](../high-side.md) · [Architecture](../architecture.md) · [Configuration reference](../configuration.md) · [HTTP API reference](../api.md) · [Deployment](../deployment.md).
