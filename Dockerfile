# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Build stage: compile a static ArtiGate binary using only the Go stdlib.
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine AS build

WORKDIR /src

# Copy module metadata first so the download layer is cached independently of
# source changes. ArtiGate has no third-party dependencies, so this is quick.
COPY go.mod ./
RUN go mod download

COPY . .

# CGO is disabled to produce a fully static binary that runs on any base image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/artigate ./cmd/artigate

# -----------------------------------------------------------------------------
# Runtime stage.
#
# The `low` mode shells out to `go` and `git` (Go modules) and to `pip` (Python
# wheels), so the runtime image ships the Go toolchain, git, and python3/pip. The
# `high` mode uses none of them; if you only deploy the high side you can base a
# slimmer image on `alpine` or `scratch` and copy just the binary.
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine

RUN apk add --no-cache git ca-certificates openssh-client python3 py3-pip \
    && addgroup -S artigate \
    && adduser -S -G artigate -h /home/artigate artigate

COPY --from=build /out/artigate /usr/local/bin/artigate

# Writable locations for the Go module cache and ArtiGate working directories.
ENV HOME=/home/artigate \
    GOCACHE=/home/artigate/.cache/go-build \
    GOMODCACHE=/home/artigate/go/pkg/mod
RUN mkdir -p /var/lib/artigate /var/spool/diode-out /var/spool/diode-in /keys \
             "$GOCACHE" "$GOMODCACHE" \
    && chown -R artigate:artigate /home/artigate /var/lib/artigate /var/spool/diode-out /var/spool/diode-in /keys

USER artigate
WORKDIR /home/artigate

EXPOSE 8080

ENTRYPOINT ["artigate"]
# Default to printing usage; override with `low ...` or `high ...` flags.
CMD ["--help"]
