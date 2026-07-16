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
// The built-in UDP data-diode transport (pitcher/catcher) is covered by the
// integration tests in cmd/artigate (diode_udp_test.go) rather than by this
// suite. TestLowToHighOverUDPDiode runs the whole loop over the real
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
