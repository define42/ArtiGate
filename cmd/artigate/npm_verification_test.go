package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
)

// The registry fixture changes only upstream metadata; every collection resolves
// the same package version and integrity-pinned tarball.
type npmVerificationState struct {
	versionOverride    json.RawMessage
	omitVersion        bool
	signatures         []NpmRegistrySignature
	keys               []NpmRegistryKey
	predicate          string
	attestations       string
	tags               map[string]string
	packumentStatus    int
	keysStatus         int
	attestationsStatus int
}

type npmVerificationFixture struct {
	mu     sync.Mutex
	state  npmVerificationState
	low    *LowServer
	high   *HighServer
	server *httptest.Server
}

const (
	npmVerificationPredicate    = "https://slsa.dev/provenance/v1"
	npmVerificationAttestations = `{"attestations":[{"bundle":{"fixture":"original"}}]}`
)

func newNpmVerificationFixture(t *testing.T) *npmVerificationFixture {
	t.Helper()
	tarball := makeNpmTgz(t, "package", "lodash", "4.17.21")
	fx := &npmVerificationFixture{state: npmVerificationState{
		signatures:   []NpmRegistrySignature{{KeyID: "SHA256:key1", Sig: "signature1"}},
		keys:         []NpmRegistryKey{{KeyID: "SHA256:key1", KeyType: "ecdsa-sha2-nistp256", Scheme: "ecdsa-sha2-nistp256", Key: "publickey1"}},
		predicate:    npmVerificationPredicate,
		attestations: npmVerificationAttestations,
		tags:         map[string]string{"latest": "4.17.21"},
	}}
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		defer fx.mu.Unlock()
		st := fx.state
		switch r.URL.Path {
		case "/lodash/-/lodash-4.17.21.tgz":
			_, _ = w.Write(tarball)
		case "/lodash":
			if st.packumentStatus != 0 {
				w.WriteHeader(st.packumentStatus)
				return
			}
			dist := map[string]any{"signatures": st.signatures}
			if st.predicate != "" {
				dist["attestations"] = map[string]any{
					"provenance": map[string]string{"predicateType": st.predicate},
				}
			}
			var version any = map[string]any{"dist": dist}
			if st.versionOverride != nil {
				version = st.versionOverride
			}
			versions := map[string]any{}
			if !st.omitVersion {
				versions["4.17.21"] = version
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dist-tags": st.tags,
				"versions":  versions,
			})
		case "/-/npm/v1/keys":
			if st.keysStatus != 0 {
				w.WriteHeader(st.keysStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": st.keys})
		case "/-/npm/v1/attestations/lodash@4.17.21":
			if st.attestationsStatus != 0 {
				w.WriteHeader(st.attestationsStatus)
				return
			}
			_, _ = io.WriteString(w, st.attestations)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(registry.Close)
	lock := fmt.Sprintf(`{"lockfileVersion":3,"packages":{
        "":{"name":"artigate-collect"},
        "node_modules/lodash":{"version":"4.17.21","resolved":"%s/lodash/-/lodash-4.17.21.tgz","integrity":"%s"}
    }}`, registry.URL, sriFor(tarball))
	pub, priv := newTestKeys(t)
	low, err := NewLowServer(LowConfig{
		Root: t.TempDir(), ExportDir: filepath.Join(t.TempDir(), "out"), NpmBinary: writeFakeNpm(t, lock),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	fx.low = low
	t.Cleanup(func() { _ = low.Close() })
	fx.high = newTestHighServer(t, pub)
	fx.server = httptest.NewServer(fx.high)
	t.Cleanup(fx.server.Close)
	return fx
}

func (fx *npmVerificationFixture) change(fn func(*npmVerificationState)) {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	fn(&fx.state)
}

func (fx *npmVerificationFixture) collect(t *testing.T) ExportResult {
	t.Helper()
	result, err := fx.low.CollectNpm(context.Background(), NpmCollectRequest{Packages: []string{"lodash"}})
	if err != nil {
		t.Fatalf("CollectNpm: %v", err)
	}
	return result
}

func (fx *npmVerificationFixture) importBundle(t *testing.T, result ExportResult) {
	t.Helper()
	if result.Skipped || result.BundleID == "" {
		t.Fatalf("metadata change did not produce a bundle: %+v", result)
	}
	for _, suffix := range bundleSuffixes() {
		name := result.BundleID + suffix
		data, err := os.ReadFile(filepath.Join(fx.low.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(fx.high.cfg.Landing, name), data)
	}
	if _, err := fx.high.ImportNext(); err != nil {
		t.Fatalf("ImportNext: %v", err)
	}
}

func (fx *npmVerificationFixture) assertPriorTarball(t *testing.T, result ExportResult) {
	t.Helper()
	manifest := readBundleManifest(t, fx.low, result.BundleID)
	const tarball = "npm/packages/lodash/lodash-4.17.21.tgz"
	found := false
	for _, file := range manifest.Files {
		if file.Path == tarball {
			found = true
			if !file.Prior {
				t.Errorf("unchanged tarball is not a prior reference: %+v", file)
			}
		}
	}
	if !found {
		t.Fatalf("metadata bundle omitted its package tarball reference: %+v", manifest.Files)
	}
	if names := listArchiveEntries(t, fx.low.cfg.ExportDir, result.BundleID); slices.Contains(names, tarball) {
		t.Fatalf("unchanged tarball was retransmitted: %v", names)
	}
}

type npmVerificationWant struct {
	signatures []NpmRegistrySignature
	keys       []NpmRegistryKey
	predicate  string
}

func (fx *npmVerificationFixture) assertServed(t *testing.T, want npmVerificationWant) {
	t.Helper()
	code, body := httpGet(t, fx.server.URL+"/npm/lodash/4.17.21")
	if code != http.StatusOK {
		t.Fatalf("version metadata HTTP %d: %s", code, body)
	}
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    struct {
			Signatures   []NpmRegistrySignature `json:"signatures"`
			Attestations struct {
				URL        string `json:"url"`
				Provenance struct {
					PredicateType string `json:"predicateType"`
				} `json:"provenance"`
			} `json:"attestations"`
		} `json:"dist"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Name != "lodash" || doc.Version != "4.17.21" {
		t.Errorf("served package identity = %s@%s", doc.Name, doc.Version)
	}
	if !slices.Equal(doc.Dist.Signatures, want.signatures) {
		t.Errorf("served signatures = %+v, want %+v", doc.Dist.Signatures, want.signatures)
	}
	if got := doc.Dist.Attestations.Provenance.PredicateType; got != want.predicate {
		t.Errorf("served predicate = %q, want %q", got, want.predicate)
	}
	if want.predicate == "" && doc.Dist.Attestations.URL != "" {
		t.Errorf("cleared attestations still advertised: %s", doc.Dist.Attestations.URL)
	}
	code, body = httpGet(t, fx.server.URL+"/npm/-/npm/v1/keys")
	if len(want.keys) == 0 {
		if code != http.StatusNotFound {
			t.Errorf("cleared keys HTTP %d: %s", code, body)
		}
		return
	}
	if code != http.StatusOK {
		t.Fatalf("keys HTTP %d: %s", code, body)
	}
	var keysDoc struct {
		Keys []NpmRegistryKey `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &keysDoc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keysDoc.Keys, want.keys) {
		t.Errorf("served keys = %+v, want %+v", keysDoc.Keys, want.keys)
	}
}

func TestNpmVerificationMetadataUpdates(t *testing.T) {
	tests := []struct {
		name   string
		change func(*npmVerificationState, *npmVerificationWant)
	}{
		{"signature replacement", func(st *npmVerificationState, want *npmVerificationWant) {
			st.signatures = []NpmRegistrySignature{{KeyID: "SHA256:key1", Sig: "replacement"}}
			want.signatures = st.signatures
		}},
		{"registry key rotation", func(st *npmVerificationState, want *npmVerificationWant) {
			st.keys = []NpmRegistryKey{{KeyID: "SHA256:key2", Key: "publickey2"}}
			want.keys = st.keys
		}},
		{"attestation predicate change", func(st *npmVerificationState, want *npmVerificationWant) {
			st.predicate = "https://slsa.dev/provenance/v0.2"
			want.predicate = st.predicate
		}},
		{"empty signatures clear", func(st *npmVerificationState, want *npmVerificationWant) {
			st.signatures = []NpmRegistrySignature{}
			want.signatures = nil
		}},
		{"empty keys clear", func(st *npmVerificationState, want *npmVerificationWant) {
			st.keys = []NpmRegistryKey{}
			want.keys = nil
		}},
		{"absent attestations clear", func(st *npmVerificationState, want *npmVerificationWant) {
			st.predicate = ""
			want.predicate = ""
		}},
		{"packument failure preserves verification during key rotation", func(st *npmVerificationState, want *npmVerificationWant) {
			st.packumentStatus = http.StatusServiceUnavailable
			st.keys = []NpmRegistryKey{{KeyID: "SHA256:key2", Key: "publickey2"}}
			want.keys = st.keys
		}},
		{"attestation failure preserves predicate during tag update", func(st *npmVerificationState, _ *npmVerificationWant) {
			st.attestationsStatus = http.StatusServiceUnavailable
			st.tags = map[string]string{"latest": "4.17.21", "stable": "4.17.21"}
		}},
		{"key fetch failure preserves keys during signature update", func(st *npmVerificationState, want *npmVerificationWant) {
			st.keysStatus = http.StatusServiceUnavailable
			st.signatures = []NpmRegistrySignature{{KeyID: "SHA256:key1", Sig: "replacement"}}
			want.signatures = st.signatures
		}},
		{"missing version preserves verification during tag update", func(st *npmVerificationState, _ *npmVerificationWant) {
			st.omitVersion = true
			st.tags = map[string]string{"latest": "4.17.21", "stable": "4.17.21"}
		}},
		{"null version preserves verification during tag update", func(st *npmVerificationState, _ *npmVerificationWant) {
			st.versionOverride = json.RawMessage(`null`)
			st.tags = map[string]string{"latest": "4.17.21", "stable": "4.17.21"}
		}},
		{"missing dist preserves verification during tag update", func(st *npmVerificationState, _ *npmVerificationWant) {
			st.versionOverride = json.RawMessage(`{}`)
			st.tags = map[string]string{"latest": "4.17.21", "stable": "4.17.21"}
		}},
		{"null dist preserves verification during tag update", func(st *npmVerificationState, _ *npmVerificationWant) {
			st.versionOverride = json.RawMessage(`{"dist":null}`)
			st.tags = map[string]string{"latest": "4.17.21", "stable": "4.17.21"}
		}},
		{"malformed attestation pointer preserves predicate during signature update", func(st *npmVerificationState, want *npmVerificationWant) {
			st.versionOverride = json.RawMessage(`{"dist":{
				"signatures":[{"keyid":"SHA256:key1","sig":"replacement"}],
				"attestations":{}
			}}`)
			want.signatures = []NpmRegistrySignature{{KeyID: "SHA256:key1", Sig: "replacement"}}
		}},
		{"malformed signatures preserve signatures during tag update", func(st *npmVerificationState, _ *npmVerificationWant) {
			st.versionOverride = json.RawMessage(`{"dist":{
				"signatures":[{"keyid":"","sig":"invalid"}],
				"attestations":{"provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}
			}}`)
			st.tags = map[string]string{"latest": "4.17.21", "stable": "4.17.21"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newNpmVerificationFixture(t)
			first := fx.collect(t)
			fx.importBundle(t, first)
			want := npmVerificationWant{
				signatures: fx.state.signatures, keys: fx.state.keys, predicate: fx.state.predicate,
			}
			fx.assertServed(t, want)
			fx.change(func(st *npmVerificationState) { tt.change(st, &want) })
			changed := fx.collect(t)
			fx.importBundle(t, changed)
			fx.assertPriorTarball(t, changed)
			if files := listArchiveEntries(t, fx.low.cfg.ExportDir, changed.BundleID); len(files) != 0 {
				t.Errorf("metadata-only update retransmitted files: %v", files)
			}
			fx.assertServed(t, want)
			if repeated := fx.collect(t); !repeated.Skipped {
				t.Errorf("unchanged metadata exported again: %+v", repeated)
			}
		})
	}
}

func TestNpmVerificationReorderedListsDoNotExport(t *testing.T) {
	fx := newNpmVerificationFixture(t)
	fx.change(func(st *npmVerificationState) {
		st.signatures = append(st.signatures, NpmRegistrySignature{KeyID: "SHA256:key2", Sig: "signature2"})
		st.keys = append(st.keys, NpmRegistryKey{KeyID: "SHA256:key2", Key: "publickey2"})
	})
	fx.importBundle(t, fx.collect(t))
	sequence := fx.low.peekSequence(streamNpm)
	fx.change(func(st *npmVerificationState) {
		slices.Reverse(st.signatures)
		slices.Reverse(st.keys)
	})
	result := fx.collect(t)
	if !result.Skipped || result.BundleID != "" {
		t.Fatalf("reordering metadata exported a bundle: %+v", result)
	}
	if got := fx.low.peekSequence(streamNpm); got != sequence {
		t.Fatalf("reordering consumed sequence %d, next = %d", sequence, got)
	}
}

func TestNpmAttestationsDocumentUpdatesAndReverts(t *testing.T) {
	fx := newNpmVerificationFixture(t)
	fx.importBundle(t, fx.collect(t))
	documents := []string{
		`{"attestations":[{"bundle":{"fixture":"replacement"}}]}`,
		npmVerificationAttestations,
	}
	for _, document := range documents {
		fx.change(func(st *npmVerificationState) { st.attestations = document })
		result := fx.collect(t)
		fx.importBundle(t, result)
		fx.assertPriorTarball(t, result)
		wantEntries := []string{npmAttestationsRel("lodash", "4.17.21")}
		if got := listArchiveEntries(t, fx.low.cfg.ExportDir, result.BundleID); !slices.Equal(got, wantEntries) {
			t.Errorf("attestations update archive = %v, want %v", got, wantEntries)
		}
		code, body := httpGet(t, fx.server.URL+"/npm/-/npm/v1/attestations/lodash@4.17.21")
		if code != http.StatusOK || body != document {
			t.Fatalf("served attestations HTTP %d: %s, want %s", code, body, document)
		}
	}
}

// Derived metadata can always be rebuilt from the verified tarball, even when
// the upstream observation is unavailable and no prior metadata can be read.
func TestNpmVerificationRebuildsCorruptStoredMetadata(t *testing.T) {
	fx := newNpmVerificationFixture(t)
	fx.importBundle(t, fx.collect(t))
	metadataPath := filepath.Join(fx.high.npmMetadataDir(), "lodash", "4.17.21.json")
	writeFile(t, metadataPath, []byte("invalid JSON"))
	keys := []NpmRegistryKey{{KeyID: "SHA256:key2", Key: "publickey2"}}
	fx.change(func(st *npmVerificationState) {
		st.packumentStatus = http.StatusServiceUnavailable
		st.keys = keys
	})
	result := fx.collect(t)
	fx.importBundle(t, result)
	fx.assertPriorTarball(t, result)
	fx.assertServed(t, npmVerificationWant{keys: keys})
}
