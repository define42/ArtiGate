# ArtiGate — build, test, and lint targets.

# Pin golangci-lint to the same version CI uses (.github/workflows/go.yml).
GOLANGCI_LINT_VERSION ?= v2.12.2
GOBIN                  := $(shell go env GOPATH)/bin
GOLANGCI_LINT         := $(GOBIN)/golangci-lint
GO_VERSION             := $(shell go env GOVERSION)

# Version stamp reported by `artigate version`, the startup logs, and both
# dashboards. Defaults to git describe; release builds override it, e.g.
# `make build VERSION=v1.2.3`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# docker compose v2 (`docker compose`) with a fallback to the legacy binary.
COMPOSE ?= $(shell docker compose version >/dev/null 2>&1 && echo 'docker compose' || echo 'docker-compose')

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the artigate binary
	go build -ldflags "-X main.version=$(VERSION)" -o artigate ./cmd/artigate

.PHONY: test
test: ## Run unit tests with the race detector and coverage
	go test ./... -race -coverprofile=coverage.out -covermode=atomic

.PHONY: cover
cover: test ## Show per-function coverage from the last test run
	go tool cover -func=coverage.out

.PHONY: e2e
e2e: ## Run the end-to-end suite (real upstreams + real client tools; see e2e/doc.go)
	go test -tags e2e -v -count=1 -timeout 25m ./e2e

.PHONY: lint
lint: ## Run golangci-lint using .golangci.yml
	@if ! $(GOLANGCI_LINT) version 2>/dev/null | grep -q \
		"version $(patsubst v%,%,$(GOLANGCI_LINT_VERSION)) built with $(GO_VERSION)"; then \
		GOTOOLCHAIN=$(GO_VERSION) go install \
			github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi
	$(GOLANGCI_LINT) run ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format the code (gofmt)
	gofmt -w cmd

.PHONY: ui
ui: ## Compile the high-side TypeScript UI (cmd/artigate/ui/app.ts -> app.js)
	cd cmd/artigate/ui && npx -y -p typescript tsc -p tsconfig.json

.PHONY: run
run: ## Build and start the low+high stack with docker compose
	$(COMPOSE) up --build

.PHONY: run-detach
run-detach: ## Start the low+high stack in the background
	$(COMPOSE) up --build -d

.PHONY: stop
stop: ## Stop the stack, keeping state (sequence, keys, mirror) so restart continues
	$(COMPOSE) down

.PHONY: reset
reset: ## Stop the stack AND wipe all volumes (fresh start: sequence back to 1)
	$(COMPOSE) down -v

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -f artigate coverage.out

.PHONY: help
help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
