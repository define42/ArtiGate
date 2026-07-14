# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Build stage: compile a static ArtiGate binary (pure-Go dependencies only).
# -----------------------------------------------------------------------------
FROM golang:1.26.5-alpine AS build

WORKDIR /src

# Copy module metadata first so the download layer is cached independently of
# source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is disabled to produce a fully static binary that runs on any base image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/artigate ./cmd/artigate

# -----------------------------------------------------------------------------
# Runtime stage.
#
# The `low` mode shells out to `go` and `git` (Go modules), `pip` (Python
# wheels), `mvn` (Java/Maven artifacts), `npm` (NPM dependency resolution),
# `gpgv` (verifying upstream APT/RPM repositories), `xz` (decompressing
# some RPM indexes), and `zstd` (decompressing conda repodata), so the
# runtime image ships the Go toolchain, git, python3/pip, Maven + a JDK,
# nodejs/npm, gnupg, xz, and zstd. APT, RPM, NPM, conda, RubyGems, Composer,
# VS Code extension, Galaxy, CRAN, raw-git, and container content is fetched
# over HTTP with the Go standard library (git mirroring speaks the smart
# protocol in pure Go — the git binary here serves only the Go-module VCS
# fallback). The `high` mode uses gnupg only when signing regenerated APT/RPM
# repositories (--apt-gpg-key / --rpm-gpg-key); otherwise it needs none of
# them, so a high-only deployment can use a slimmer image with just the
# binary + gnupg.
# -----------------------------------------------------------------------------
FROM golang:1.26.5-alpine

RUN apk add --no-cache git ca-certificates openssh-client python3 py3-pip maven openjdk17-jre-headless nodejs npm gnupg xz zstd \
    && addgroup -S artigate \
    && adduser -S -G artigate -h /home/artigate artigate

COPY --from=build /out/artigate /usr/local/bin/artigate

# Writable locations for the Go module cache and ArtiGate working directories.
ENV HOME=/home/artigate \
    GOCACHE=/home/artigate/.cache/go-build \
    GOMODCACHE=/home/artigate/go/pkg/mod
RUN mkdir -p /var/lib/artigate /var/spool/diode-out /var/spool/diode-in /keys /low-keys /high-keys \
             "$GOCACHE" "$GOMODCACHE" \
    && chown -R artigate:artigate /home/artigate /var/lib/artigate /var/spool/diode-out /var/spool/diode-in /keys /low-keys /high-keys

USER artigate
WORKDIR /home/artigate

EXPOSE 8080

ENTRYPOINT ["artigate"]
# Default to printing usage; override with `low ...` or `high ...` flags.
CMD ["--help"]
