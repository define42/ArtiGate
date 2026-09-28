package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionOrBuildInfo(t *testing.T) {
	if got := versionOrBuildInfo("v1.2.3"); got != "v1.2.3" {
		t.Errorf("stamped version = %q, want v1.2.3", got)
	}
	// Unstamped falls back to build info; whatever the test binary embeds, the
	// identity must never be empty.
	if got := versionOrBuildInfo(""); got == "" {
		t.Error("unstamped versionOrBuildInfo returned an empty identity")
	}
	if versionString() == "" {
		t.Error("versionString returned an empty identity")
	}
}

func TestBuildInfoVersion(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"module version", &debug.BuildInfo{Main: debug.Module{Version: "v0.9.1"}}, "v0.9.1"},
		{"devel with revision", &debug.BuildInfo{
			Main: debug.Module{Version: "(devel)"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "0123456789abcdef"},
				{Key: "vcs.modified", Value: "false"},
			},
		}, "dev-0123456789ab"},
		{"dirty tree", &debug.BuildInfo{
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "feedface"},
				{Key: "vcs.modified", Value: "true"},
			},
		}, "dev-feedface-dirty"},
		{"no metadata", &debug.BuildInfo{}, "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildInfoVersion(tt.info); got != tt.want {
				t.Errorf("buildInfoVersion = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionSummary(t *testing.T) {
	s := versionSummary()
	if !strings.HasPrefix(s, versionString()) {
		t.Errorf("summary %q must start with the version %q", s, versionString())
	}
	if want := fmt.Sprintf("manifest format %d", manifestFormatCurrent); !strings.Contains(s, want) {
		t.Errorf("summary %q must state %q — it answers whether a high side can import a low side's bundles", s, want)
	}
}

// TestMarshalManifestStampsFormatAndVersion pins the export-side half of the
// wire-format contract: every manifest that leaves the low side carries the
// current format and the producing binary's version, and the caller's value
// is not mutated in the process.
func TestMarshalManifestStampsFormatAndVersion(t *testing.T) {
	in := BundleManifest{Type: manifestType, BundleID: bundleIDFor(streamGo, 1)}
	b, err := marshalManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	var out BundleManifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Format != manifestFormatCurrent {
		t.Errorf("format = %d, want %d", out.Format, manifestFormatCurrent)
	}
	if out.GeneratorVersion != versionString() {
		t.Errorf("generator_version = %q, want %q", out.GeneratorVersion, versionString())
	}
	if in.Format != 0 || in.GeneratorVersion != "" {
		t.Errorf("caller's manifest was mutated: %+v", in)
	}
}

func TestMarshalManifestCompactJSON(t *testing.T) {
	in := BundleManifest{Generator: `builder<&>`, Files: []ManifestFile{{Path: `uploads/docs/a&b<1>.txt`}}}
	body, err := marshalManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, compact.Bytes()) {
		t.Fatal("manifest contains JSON formatting whitespace")
	}
	if !bytes.Contains(body, []byte(in.Generator)) || !bytes.Contains(body, []byte(in.Files[0].Path)) {
		t.Fatal("standalone manifest unnecessarily HTML-escapes metadata")
	}
	var decoded BundleManifest
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Generator != in.Generator || len(decoded.Files) != 1 || decoded.Files[0].Path != in.Files[0].Path {
		t.Fatalf("metadata did not survive encoding: %+v", decoded)
	}
	again, err := marshalManifest(in)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatalf("manifest encoding is not deterministic: %v", err)
	}
}
