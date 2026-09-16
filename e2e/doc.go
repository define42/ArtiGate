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
// (or tofu), helm, dotnet, apt-get+dpkg, dnf+rpm, apk (inside an Alpine
// container), docker, huggingface_hub's CLI, micromamba (or conda),
// bundler, composer, ansible-galaxy, Rscript, git, oras, cosign, Ollama,
// VSCodium, snap, and curl. Conda and CRAN require their real clients in strict
// mode. Package assertions check installed content and run the installed
// software where appropriate; GGUF coverage includes CPU inference, and VSX
// coverage installs and lists the exact mirrored extension version.
//
// On Linux, receiver clients run in fresh network and PID namespaces with a
// bridge to only the high-side HTTP endpoint. They receive a clean environment
// and private HOME/cache directories; inherited proxy and extra-index settings
// cannot supply missing mirror content. TestReceiverIsolation checks successful
// high-side access, blocked upstream/redirect access, and environment isolation.
// Container clients run with Docker's network disabled. Image pulls use a fresh
// Docker daemon and layer store; APT/RPM/APK use prepared base containers. Snap
// installs, verifies assertions, and executes in an Ubuntu VM with no network
// device. Downloading tools, container bases and the pinned VM image is setup;
// the subsequent receiver operations cannot reach those upstreams. The Python
// source-distribution flow also fetches its build requirements from the mirror.
// OCI artifact tests use a pinned local Distribution registry container,
// native referrer graphs, and temporary cosign keys: signing and verification
// need no external identity provider or transparency-log service.
// TestOCIDistributionConformance runs the official distribution-spec v1.1.1
// pull and discovery workflows, including native referrers and tag pagination.
// Its fixture gateway sends setup writes to a pinned local Zot registry, then
// transfers those fixtures through the signed diode before forwarding read
// assertions to the high side. Push and management workflows remain disabled.
// HTML, JUnit, and command logs are written to WORKDIR/oci-conformance and
// uploaded by CI. The standalone oci-distribution-conformance binary is built
// from the pinned upstream module in .github/workflows/e2e.yml; its dependencies
// are separate from ArtiGate's go.mod. Set ARTIGATE_E2E_WORKDIR or
// ARTIGATE_E2E_KEEP=1 to retain reports after a successful local run.
//
// Beyond the per-stream client round-trips, the suite exercises the parts of
// the system that sit between the low and high sides. These do not lean on any
// one upstream and several build their own dedicated low+high pair (see
// pair_test.go) so they can inject faults or reconfigure the transport:
//
//   - the trust boundary (tamper_test.go): a delivered bundle with a flipped
//     signature byte or a corrupted archive byte is rejected while prior
//     content keeps serving; an out-of-order (future) bundle is quarantined
//     and then imported once its predecessor arrives.
//   - re-export and re-import idempotency (reimport_test.go): a re-transmitted
//     already-imported bundle is filed as a duplicate, not re-imported.
//   - multi-version index regeneration across separate bundles
//     (multiversion_test.go): two versions collected as two bundles both
//     appear in the regenerated npm/rubygems index, and the older artifact
//     still installs after the newer bundle imported on top of it.
//   - the scheduled-collect subsystem (watch_test.go), the low-side session
//     login (auth_test.go), and the low/high dashboards (ui_test.go).
//
// TestUDPDiode additionally uses real low/high processes and the built-in UDP
// pitcher/catcher transport over an isolated IPv6 multicast link, then retrieves
// imported content with an isolated curl receiver. The cmd/artigate integration
// tests in diode_udp_test.go provide further transport coverage.
// TestLowToHighOverUDPDiode runs the whole loop over the real
// pitcher/catcher socket path — the low side collects and pitches, the catcher
// listening on loopback lands the bundle and kicks the import, and the high
// side verifies (signature, sequence, hashes) and serves it;
// TestPitcherToCatcherOverLoopback sends a full three-file bundle the same way.
// Link-local multicast cannot route across loopback (no fe80 source address
// there), so those tests carry the identical datagram path over ::1 unicast,
// with the multicast group join itself covered separately
// (TestJoinDiodeGroupOnLoopback) and on real fiber. They run wherever an IPv6
// loopback is available and skip only where the kernel has no IPv6 stack.
//
// Everything except this file is behind the "e2e" build tag, so the default
// `go build ./...`, `go vet ./...`, `go test ./...`, and golangci-lint runs
// are unaffected. Run the suite with:
//
//	make e2e         # local run, optional unavailable flows may skip
//	make e2e-strict  # race detector, complete required matrix, zero skips
//
// Setup and low-side collection need network access and client toolchains on
// PATH. Missing tools or transient upstream failures after the retry skip
// locally; ARTIGATE_E2E_REQUIRE_ALL=1 makes both fail. CI runs with -json -race
// and uses check_report.py to reject every skipped test/subtest, missing required
// flow, and incomplete result stream. required_flows.json records the explicit
// required matrix; its regression test requires every top-level E2E test to be
// listed. CI uploads the raw JSON events and coverage report and adds the flow
// results to its job summary. make e2e-strict writes those reports to /tmp by
// default (override E2E_RESULTS and E2E_REPORT make variables).
// Knobs (all environment variables):
//
//	ARTIGATE_E2E_BIN         use this artigate binary instead of building one
//	ARTIGATE_E2E_WORKDIR     server roots/logs here instead of a temp dir
//	ARTIGATE_E2E_KEEP        "1" keeps the temp workdir after a green run
//	ARTIGATE_E2E_REQUIRE_ALL "1" fails on missing tools or unavailable upstreams
//	ARTIGATE_E2E_HF_GGUF     override the GGUF model ref ("org/name:quant")
package e2e
