# TLS / HTTPS

Both the low side and the high side serve **plain HTTP by default**. HTTPS is enabled entirely through environment variables — there are no TLS flags — and the *same* variables apply to `artigate low` and `artigate high`, since both call the identical `tlsConfigFromEnv()` code path. TLS is terminated on each side's single `--listen` port; there is no separate `:80` listener and no HTTP→HTTPS redirect.

!!! note "Same knobs, two processes"
    The low and high sides are separate processes that read the *same* variable names. You configure each independently by setting the environment for that process — you cannot give one process two different TLS configs. See the [Configuration reference](configuration.md) for the full command-line and environment surface.

## Enabling HTTPS

Set `ARTIGATE_TLS_MODE` to one of four values. Every other TLS/ACME variable is trimmed of surrounding whitespace; `ARTIGATE_TLS_DOMAINS` is comma-split with empty entries dropped. If `ARTIGATE_TLS_MODE` is unset it defaults to `unencrypted`.

```bash
export ARTIGATE_TLS_MODE=own-certificate
export ARTIGATE_TLS_CERT=/etc/artigate/tls/fullchain.pem
export ARTIGATE_TLS_KEY=/etc/artigate/tls/privkey.pem
./artigate high --public-key /etc/artigate/high.ed25519.pub --listen :443
```

Startup **fails fast** on any invalid TLS configuration (an unknown mode, or a mode whose required variables are missing) — the process exits before it begins serving.

## The `ARTIGATE_TLS_MODE` matrix

| Variable | Modes | Meaning |
|---|---|---|
| `ARTIGATE_TLS_MODE` | all | `unencrypted` / `acme` / `own-certificate` / `auto-generate-certificate` |
| `ARTIGATE_TLS_DOMAINS` | `acme`, `auto-generate-certificate` | comma-separated domains/IPs (ACME cert names; self-signed SANs) |
| `ARTIGATE_TLS_CERT`, `ARTIGATE_TLS_KEY` | `own-certificate` | PEM certificate and private-key paths |
| `ARTIGATE_ACME_EMAIL` | `acme` | ACME account email |
| `ARTIGATE_ACME_DIRECTORY` | `acme` | ACME server directory URL (defaults to Let's Encrypt) |
| `ARTIGATE_ACME_CA_ROOT` | `acme` | PEM root CA to trust, for a private ACME server |
| `ARTIGATE_ACME_STORAGE` | `acme` | certificate cache directory (default `<root>/acme`) |

!!! warning "Non-obvious variable names"
    Two ACME variables map to differently-named fields internally: `ARTIGATE_ACME_DIRECTORY` sets the ACME **CA directory URL**, and `ARTIGATE_ACME_CA_ROOT` is a **filesystem path** to a PEM file (not a URL). Both are only consulted in `acme` mode.

### Mode × variable summary

| Mode | Required | Optional / used | Ignored | Cert lifecycle |
|---|---|---|---|---|
| `unencrypted` (default) | — | — | all TLS/ACME vars | none — plain HTTP |
| `own-certificate` | `ARTIGATE_TLS_CERT`, `ARTIGATE_TLS_KEY` | — | `ARTIGATE_TLS_DOMAINS`, all `ARTIGATE_ACME_*` | static, loaded once at startup |
| `auto-generate-certificate` | — | `ARTIGATE_TLS_DOMAINS` (SANs) | all `ARTIGATE_ACME_*`, `ARTIGATE_TLS_CERT`/`KEY` | in-memory, regenerated each start |
| `acme` | `ARTIGATE_TLS_DOMAINS` | `ARTIGATE_ACME_EMAIL`, `ARTIGATE_ACME_DIRECTORY`, `ARTIGATE_ACME_CA_ROOT`, `ARTIGATE_ACME_STORAGE` | `ARTIGATE_TLS_CERT`/`KEY` | auto obtain + renew (certmagic) |

The exact startup errors are:

- `own-certificate` without both cert and key → `ARTIGATE_TLS_MODE=own-certificate requires ARTIGATE_TLS_CERT and ARTIGATE_TLS_KEY`
- `acme` with no domains → `ARTIGATE_TLS_MODE=acme requires ARTIGATE_TLS_DOMAINS`
- Any unrecognized mode → `invalid ARTIGATE_TLS_MODE "..." (want unencrypted, acme, own-certificate, or auto-generate-certificate)`

## `unencrypted` (default)

Plain HTTP on the listen port. No certificate is loaded. This is the right choice when ArtiGate sits behind a TLS-terminating reverse proxy (see below) or on a trusted, isolated network segment.

## `own-certificate`

Loads a static certificate/key pair once at startup with `tls.LoadX509KeyPair`, and serves with `MinVersion` TLS 1.2. This is the mode to use with certificates from your own PKI, an internal CA, or a manually-obtained public certificate.

```bash
export ARTIGATE_TLS_MODE=own-certificate
export ARTIGATE_TLS_CERT=/etc/artigate/tls/fullchain.pem   # cert + intermediate chain
export ARTIGATE_TLS_KEY=/etc/artigate/tls/privkey.pem
```

!!! warning "No hot reload"
    The keypair is read **once at startup**. There is no renewal or reload — after rotating the certificate on disk you must restart the process to pick up the new one. A load failure aborts startup with `load certificate: ...`.

## `auto-generate-certificate` (self-signed)

Generates a fresh **in-memory, self-signed** certificate on every startup — nothing is written to disk. It is an ECDSA P-256 key, serial number random 128-bit, subject organization `ArtiGate`, valid from one hour ago to one year ahead, with `ServerAuth` extended key usage. `MinVersion` is TLS 1.2.

The SANs come from `ARTIGATE_TLS_DOMAINS`: each entry that parses as an IP becomes an `IPAddresses` SAN, otherwise a `DNSNames` SAN. The first DNS name (if any) is also used as the certificate's Common Name.

```bash
export ARTIGATE_TLS_MODE=auto-generate-certificate
export ARTIGATE_TLS_DOMAINS=mirror.internal,10.0.0.5
```

If `ARTIGATE_TLS_DOMAINS` yields no names and no IPs, the certificate falls back to a single SAN, `artigate.local`.

!!! tip "For testing or proxied setups only"
    Clients will not trust a self-signed certificate. Use this mode for local testing, or behind a proxy that ignores upstream certificate validity. Because it is regenerated on each restart, it is unsuitable for anything that pins or caches the certificate.

## `acme` — automatic certificates

In `acme` mode ArtiGate obtains and renews certificates automatically in the background using [certmagic](https://github.com/caddyserver/certmagic). The ACME **Terms of Service are auto-accepted** (`Agreed = true`) — no operator interaction is required.

```bash
export ARTIGATE_TLS_MODE=acme
export ARTIGATE_TLS_DOMAINS=mirror.example.com
export ARTIGATE_ACME_EMAIL=ops@example.com
./artigate high --public-key /etc/artigate/high.ed25519.pub --listen :443
```

With no `ARTIGATE_ACME_DIRECTORY` set, certmagic uses its built-in default CA (Let's Encrypt production). The certificate cache defaults to `<root>/acme` (i.e. `/var/lib/artigate-low/acme` or `/var/lib/artigate-high/acme`) unless you override it with `ARTIGATE_ACME_STORAGE`.

### Challenge type: TLS-ALPN-01 on the listen port

ArtiGate answers the ACME challenge with **TLS-ALPN-01 on its own single HTTPS listen port** — the same port that serves normal traffic. certmagic wires the challenge solver into the listener's `tls.Config` and appends the `acme-tls/1` ALPN protocol; ArtiGate prepends `h2` and `http/1.1` so HTTP/2 is advertised for ordinary requests.

!!! warning "Reachability requirements"
    There is **no separate `:80` HTTP-01 listener and no separate challenge server**. For the challenge to succeed:

    - every name in `ARTIGATE_TLS_DOMAINS` must resolve to this host, and
    - the ACME CA must be able to reach the **exact listen port** directly (typically `:443`).

    If ArtiGate listens on a non-443 port that the CA cannot reach, TLS-ALPN-01 cannot complete.

### Private ACME servers (step-ca / smallstep)

For an internal ACME server, point `ARTIGATE_ACME_DIRECTORY` at its directory URL and give `ARTIGATE_ACME_CA_ROOT` the path to a PEM file containing the ACME server's root CA — ArtiGate loads it into certmagic's `TrustedRoots` so it trusts the private server's certificate chain.

```bash
export ARTIGATE_TLS_MODE=acme
export ARTIGATE_TLS_DOMAINS=mirror.internal
export ARTIGATE_ACME_EMAIL=ops@internal
export ARTIGATE_ACME_DIRECTORY=https://ca.internal/acme/acme/directory
export ARTIGATE_ACME_CA_ROOT=/etc/artigate/ca-root.pem
```

If the PEM at `ARTIGATE_ACME_CA_ROOT` cannot be read, startup fails with `read root CA: ...`; if it contains no parseable certificates, `no certificates found in <path>`. `ARTIGATE_ACME_EMAIL` may be left empty.

!!! note "Single ACME configuration per process"
    certmagic is driven through global singletons, so one process serves exactly one ACME configuration.

## Reverse-proxy termination and `ARTIGATE_LOW_COOKIE_SECURE`

A common topology is to run ArtiGate with `ARTIGATE_TLS_MODE=unencrypted` (plain HTTP) behind a reverse proxy (nginx, Caddy, Traefik, an ingress controller) that terminates TLS. In that case ArtiGate never sees TLS, which affects the **low-side session cookie** when authentication is enabled.

`ARTIGATE_LOW_COOKIE_SECURE` controls the `Secure` attribute of the low-side session cookie. It only has any effect when low-side auth is on (`ARTIGATE_LOW_AUTH` is set); the high side is never authenticated and issues no session cookie. Values (case-insensitive):

| Value | Effect on the cookie `Secure` flag |
|---|---|
| `auto` (default) or empty | follows whether **ArtiGate itself** terminates TLS (`true` unless mode is `unencrypted`) |
| `1` / `true` / `yes` / `on` | force `Secure=true` |
| `0` / `false` / `no` / `off` | force `Secure=false` |
| anything else | fatal: `invalid ARTIGATE_LOW_COOKIE_SECURE "..." (want auto, true, or false)` |

!!! warning "Set `true` behind a TLS-terminating proxy"
    With `auto` and `ARTIGATE_TLS_MODE=unencrypted`, ArtiGate marks the cookie `Secure=false`. A browser talking HTTPS to the front proxy will then **drop** the session cookie. In that topology set `ARTIGATE_LOW_COOKIE_SECURE=true` so the cookie is still marked `Secure`.

    ```bash
    export ARTIGATE_LOW_AUTH='alice:$argon2id$v=19$...'
    export ARTIGATE_TLS_MODE=unencrypted     # proxy terminates TLS
    export ARTIGATE_LOW_COOKIE_SECURE=true    # keep the cookie Secure
    ```

See [Security & trust](security.md) for the full authentication and session model.

## Container registries require HTTPS

Docker and Podman refuse to talk to a remote registry over plain HTTP. To serve container images from the high side to `docker pull` / `podman pull`, either enable TLS on the high side (any of `acme`, `own-certificate`, or a trusted `auto-generate-certificate`), or explicitly configure the client to trust a plain-HTTP mirror. The high-side **"Set me up"** guide renders a ready-to-copy client block with the actual host and port filled in.

See [Container images (OCI)](ecosystems/containers.md) for the client-side registry configuration, including the insecure-registry escape hatch and the required `systemctl restart docker`.

## Related pages

- [Configuration reference](configuration.md) — every flag and environment variable.
- [Security & trust](security.md) — low-side auth, sessions, and the signing trust chain.
- [Container images (OCI)](ecosystems/containers.md) — why registries need HTTPS and how clients trust ArtiGate.
- [Deployment](deployment.md) — putting a low/high pair into production.
