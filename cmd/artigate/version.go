package main

// Version identity for the two air-gapped binaries. Release builds stamp the
// package-level version variable through the linker:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/artigate
//
// (the Makefile and Dockerfile pass the stamp); unstamped builds fall back to
// the module/VCS metadata the Go toolchain embeds on its own, so even a plain
// `go build` reports a usable identity. The version is surfaced everywhere an
// operator on either side of the diode might look: `artigate version`, the
// startup log, both dashboards, both status JSON endpoints, /metrics
// (artigate_build_info), and every exported manifest (generator_version).

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is the release stamp injected with -ldflags "-X main.version=...".
// The name is load-bearing: it is the identifier gochecknoglobals permits for
// exactly this linker-injection pattern, and -X can only target a variable.
var version string

// versionString reports the binary's best-known version: the linker stamp
// when present, otherwise the toolchain-embedded build info, otherwise "dev".
func versionString() string {
	return versionOrBuildInfo(version)
}

func versionOrBuildInfo(stamped string) string {
	if stamped != "" {
		return stamped
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		return buildInfoVersion(info)
	}
	return "dev"
}

// buildInfoVersion renders the toolchain-embedded identity: the main module's
// version when it carries one (builds via `go install module@version`), else
// the VCS revision `go build` records from a checked-out working tree, else
// "dev".
func buildInfoVersion(info *debug.BuildInfo) string {
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return "dev-" + rev
}

// versionSummary is the one-line identity printed by `artigate version` and
// logged at startup on both sides: the version, the newest bundle wire format
// this binary writes/imports, and the toolchain it was built with. The
// manifest format is included because it answers the fleet-upgrade question
// directly: a high side imports a low side's bundles only when its own format
// is at least the low side's.
func versionSummary() string {
	return fmt.Sprintf("%s (manifest format %d, %s, %s/%s)",
		versionString(), manifestFormatCurrent, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
