//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// cfgIfVersion pins an immutable crates.io release with no enabled
// dependencies (its only ones are rustc-internal optionals, which the
// collector skips by default), so the collect and the cargo build ask for
// exactly one crate.
const cfgIfVersion = "1.0.0"

// TestCrates mirrors a crate from the real crates.io sparse index across the
// diode and builds+runs a program against the high side with the real cargo:
// source replacement points crates-io at the mirror's sparse registry, so
// resolution, download, and checksum verification all go through ArtiGate.
func TestCrates(t *testing.T) {
	stack.Prepare(t)
	cargo := requireTool(t, "cargo")

	res := stack.Collect(t, "crates", map[string]any{
		"crates": []string{"cfg-if@" + cfgIfVersion},
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned crate, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "crates", res.Sequence)

	// The sparse registry the client will use: config.json names the dl
	// endpoint, and the crate's index line must carry its checksum.
	code, body := httpGet(t, stack.HighURL+"/crates/index/config.json")
	if code != 200 || !strings.Contains(string(body), "/crates/dl") {
		t.Fatalf("registry config.json = %d %s", code, body)
	}
	code, body = httpGet(t, stack.HighURL+"/crates/index/cf/g-/cfg-if")
	if code != 200 || !strings.Contains(string(body), `"vers":"`+cfgIfVersion+`"`) {
		t.Fatalf("sparse index entry = %d %s", code, body)
	}

	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Cargo.toml"), fmt.Sprintf(`[package]
name = "artigate-e2e"
version = "0.0.0"
edition = "2021"

[dependencies]
cfg-if = "=%s"
`, cfgIfVersion))
	writeFile(t, filepath.Join(tmp, "src", "main.rs"), `fn main() {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            println!("cfg-if via mirror: unix");
        } else {
            println!("cfg-if via mirror: other");
        }
    }
}
`)
	// Source replacement makes the mirror the only registry cargo consults.
	writeFile(t, filepath.Join(tmp, ".cargo", "config.toml"), fmt.Sprintf(`[source.crates-io]
replace-with = "artigate"

[source.artigate]
registry = "sparse+%s/crates/index/"
`, stack.HighURL))

	cargoEnv := []string{
		"CARGO_HOME=" + filepath.Join(tmp, "cargo-home"), // fresh index/download caches
		"CARGO_TERM_COLOR=never",
	}
	out := runStdout(t, tmp, cargoEnv, cargo, "run", "--quiet")
	if strings.TrimSpace(out) != "cfg-if via mirror: unix" {
		t.Fatalf("cargo run printed %q", strings.TrimSpace(out))
	}
}
