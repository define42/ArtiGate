// Package e2e holds ArtiGate's end-to-end suite. It builds the real
// artigate binary, starts a low+high pair wired over the HTTP diode
// transport, collects from the real upstreams (PyPI, proxy.golang.org,
// Maven Central, registry.npmjs.org, crates.io, registry.terraform.io,
// charts.jetstack.io, api.nuget.org, cli.github.com, Docker Hub,
// huggingface.co, conda.anaconda.org, rubygems.org, repo.packagist.org,
// open-vsx.org, galaxy.ansible.com, cloud.r-project.org, github.com, and —
// via a one-package miniature repository built from real
// dl-cdn.alpinelinux.org artifacts — Alpine), and validates every stream
// with its real client tool: pip, go, mvn+java, npm+node, cargo, terraform
// (or tofu), helm, dotnet, apt-get+dpkg-deb, dnf+rpm, apk (inside an Alpine
// container), docker, huggingface_hub's CLI, micromamba (or conda),
// bundler, composer, ansible-galaxy, Rscript, git, and curl.
//
// Everything except this file is behind the "e2e" build tag, so the default
// `go build ./...`, `go vet ./...`, `go test ./...`, and golangci-lint runs
// are unaffected. Run the suite with:
//
//	make e2e    # == go test -tags e2e -v -count=1 -timeout 25m ./e2e
//
// The suite needs network access and the client toolchains on PATH. A
// missing tool skips its test locally; in CI, ARTIGATE_E2E_REQUIRE_ALL=1
// turns those skips into failures so a runner-image change cannot silently
// hollow out coverage. Knobs (all environment variables):
//
//	ARTIGATE_E2E_BIN         use this artigate binary instead of building one
//	ARTIGATE_E2E_WORKDIR     server roots/logs here instead of a temp dir
//	ARTIGATE_E2E_KEEP        "1" keeps the temp workdir after a green run
//	ARTIGATE_E2E_REQUIRE_ALL "1" fails (not skips) when a client tool is missing
//	ARTIGATE_E2E_HF_GGUF     override the GGUF model ref ("org/name:quant")
package e2e
