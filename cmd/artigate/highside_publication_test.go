package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type publicationFixture struct {
	high         *HighServer
	publicKey    ed25519.PublicKey
	stream       string
	deliver      func(sequence int64) string
	faultPath    string
	partial      string
	afterFailure func(t *testing.T, high *HighServer)
	assertFeed   func(t *testing.T, high *HighServer)
}

// Every fixture goes through collection, signed transfer and ImportNext. The
// first release establishes metadata that must survive a failed later import.
func TestPublicationRepairRetriesSignedBundle(t *testing.T) {
	cases := []struct {
		name string
		new  func(t *testing.T) publicationFixture
	}{
		{name: "nuget nuspec after JSON", new: newNugetPublicationFixture},
		{name: "npm release metadata", new: newNpmPublicationFixture},
		{name: "crates accumulated index read", new: newCratesPublicationFixture},
		{name: "crates index write", new: func(t *testing.T) publicationFixture {
			fx := newCratesPublicationFixture(t)
			fx.faultPath += ".tmp"
			return fx
		}},
		{name: "composer release metadata", new: newComposerPublicationFixture},
		{name: "rubygems accumulated metadata read", new: newRubyGemsPublicationFixture},
		{name: "rubygems metadata write", new: func(t *testing.T) publicationFixture {
			fx := newRubyGemsPublicationFixture(t)
			fx.faultPath += ".tmp"
			return fx
		}},
		{name: "rubygems per-gem index", new: func(t *testing.T) publicationFixture {
			fx := newRubyGemsPublicationFixture(t)
			fx.faultPath = filepath.Join(fx.high.rubygemsIndexDir(), "info", "mylib")
			fx.afterFailure = func(t *testing.T, high *HighServer) {
				stored, err := high.readGemStored("mylib")
				if err != nil || len(stored.Lines) != 2 {
					t.Fatalf("expected both releases stored before index failure: %+v, %v", stored, err)
				}
				srv := httptest.NewServer(high)
				defer srv.Close()
				if got := rubygemsFetchVersions(t, srv.URL); len(got) != 1 || got["mylib"][0] != "0.9.0" {
					t.Fatalf("failed info regeneration overwrote the existing versions index: %v", got)
				}
			}
			return fx
		}},
	}
	for _, tc := range cases {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%v", tc.name, restart), func(t *testing.T) {
				t.Parallel()
				fx := tc.new(t)
				fx.deliver(1)
				mustImportNext(t, fx.high)
				assertPublicationSequence(t, fx.high, fx.stream, 1)
				id := fx.deliver(2)

				// A directory where a file belongs deterministically fails either
				// the previous-metadata read or an atomic write, even as root.
				repair := blockPublicationFile(t, fx.faultPath)
				for attempt := 0; attempt < 2; attempt++ {
					assertPublicationFailure(t, fx.high, fx.stream, id, 1)
				}
				if fx.partial != "" && !fileExists(fx.partial) {
					t.Fatalf("expected metadata published before the failure at %s", fx.partial)
				}
				if fx.afterFailure != nil {
					fx.afterFailure(t, fx.high)
				}
				if restart {
					reopened, err := NewHighServer(fx.high.cfg, fx.publicKey)
					if err != nil {
						t.Fatal(err)
					}
					fx.high = reopened
					assertPublicationFailure(t, fx.high, fx.stream, id, 1)
				}
				repair()
				runPublicationRetryLoop(t, fx.high, fx.stream, 2)
				assertPublicationSequence(t, fx.high, fx.stream, 2)
				if !bundleCompleteInDir(filepath.Join(fx.high.cfg.Landing, "imported"), id) {
					t.Fatal("repaired bundle was not marked imported")
				}
				fx.assertFeed(t, fx.high)
				if result := mustImportNext(t, fx.high); result.Imported {
					t.Fatalf("successful retry imported again: %+v", result)
				}
			})
		}
	}
}

// This is the original failure shape: bytes reach the high side, but a regular
// file prevents the metadata directory from being created on the first import.
func TestPublicationNugetMetadataDirectoryRepair(t *testing.T) {
	t.Parallel()
	up := fakeNugetService(t)
	payload := nugetTestNupkg(t, "Repair.Pkg", "1.0.0")
	up.add("Repair.Pkg", "1.0.0", payload)
	low, privateKey := nugetTestLowServer(t, up.url())
	req := NugetCollectRequest{Packages: []string{"Repair.Pkg@1.0.0"}}
	exported, err := low.CollectNuget(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	high := newTestHighServer(t, privateKey.Public().(ed25519.PublicKey))
	transferAptBundle(t, low, high, exported.BundleID)
	if err := os.MkdirAll(filepath.Dir(high.nugetMetadataDir()), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, high.nugetMetadataDir(), []byte("blocks metadata directory"))
	for attempt := 0; attempt < 2; attempt++ {
		assertPublicationFailure(t, high, streamNuget, exported.BundleID, 0)
	}
	if !fileExists(filepath.Join(high.downloadDir, filepath.FromSlash(nugetPackageRel("Repair.Pkg", "1.0.0")))) {
		t.Fatal("failure did not reach publication after installing the package")
	}
	if err := os.Remove(high.nugetMetadataDir()); err != nil {
		t.Fatal(err)
	}
	runPublicationRetryLoop(t, high, streamNuget, 1)
	assertPublicationSequence(t, high, streamNuget, 1)
	srv := httptest.NewServer(high)
	defer srv.Close()
	nugetTestAssertVersions(t, srv.URL, "repair.pkg", []string{"1.0.0"})
	assertPublicationDownload(t, srv.URL+"/nuget/v3-flatcontainer/repair.pkg/1.0.0/repair.pkg.1.0.0.nupkg", payload)
	// Ordinary recollection remains deduplicated: recovery depended solely on
	// retaining and retrying the original signed bundle.
	recollected, err := low.CollectNuget(t.Context(), req)
	if err != nil || !recollected.Skipped {
		t.Fatalf("repeat collect = %+v, %v; want deduplicated", recollected, err)
	}
}

func assertPublicationFailure(t *testing.T, high *HighServer, stream, id string, previous int64) {
	t.Helper()
	result, err := high.ImportNext()
	if err == nil {
		t.Fatalf("publication failure was acknowledged: %+v", result)
	}
	var invalid *invalidBundleError
	if errors.As(err, &invalid) {
		t.Fatalf("storage failure classified as invalid bundle: %v", err)
	}
	if result.Imported || slices.Contains(result.ImportedBundles, id) || slices.Contains(result.RejectedBundles, id) {
		t.Fatalf("failed bundle was imported or rejected: %+v, %v", result, err)
	}
	assertPublicationSequence(t, high, stream, previous)
	if !bundleCompleteInDir(high.cfg.Landing, id) && !bundleCompleteInDir(high.cfg.Quarantine, id) {
		t.Fatalf("failed bundle %s was not retained for retry", id)
	}
}

func assertPublicationSequence(t *testing.T, high *HighServer, stream string, want int64) {
	t.Helper()
	high.mu.Lock()
	inMemory := high.state.Imported[stream]
	high.mu.Unlock()
	if inMemory != want {
		t.Fatalf("in-memory sequence = %d, want %d", inMemory, want)
	}
	data, err := os.ReadFile(high.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var durable HighState
	if err := json.Unmarshal(data, &durable); err != nil {
		t.Fatal(err)
	}
	if got := durable.Imported[stream]; got != want {
		t.Fatalf("durable sequence = %d, want %d", got, want)
	}
}

func blockPublicationFile(t *testing.T, name string) func() {
	t.Helper()
	backup := filepath.Join(t.TempDir(), "original")
	_, err := os.Stat(name)
	hadOriginal := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if hadOriginal {
		if err := os.Rename(name, backup); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(name, 0o755); err != nil {
		t.Fatal(err)
	}
	// Atomic writers remove stale temporary files before opening them. A
	// nonempty directory also prevents that cleanup from removing the fault.
	writeFile(t, filepath.Join(name, "block"), []byte("publication obstruction"))
	return func() {
		if err := os.RemoveAll(name); err != nil {
			t.Fatal(err)
		}
		if hadOriginal {
			if err := os.Rename(backup, name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func runPublicationRetryLoop(t *testing.T, high *HighServer, stream string, sequence int64) {
	t.Helper()
	high.cfg.ImportInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		high.importLoop(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("background import loop did not stop")
		}
	}()
	waitForImportedState(t, high, stream, sequence)
}

func assertPublicationDownload(t *testing.T, url string, want []byte) {
	t.Helper()
	status, body := httpGet(t, url)
	if status != http.StatusOK || body != string(want) {
		t.Errorf("GET %s = %d, %d bytes; want 200, %d original bytes", url, status, len(body), len(want))
	}
}

func newNugetPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	up := fakeNugetService(t)
	payloads := map[string][]byte{}
	for _, version := range []string{"1.0.0", "2.0.0"} {
		payloads[version] = nugetTestNupkg(t, "Repair.Pkg", version)
		up.add("Repair.Pkg", version, payloads[version])
	}
	low, privateKey := nugetTestLowServer(t, up.url())
	pub := privateKey.Public().(ed25519.PublicKey)
	high := newTestHighServer(t, pub)
	return publicationFixture{
		high: high, publicKey: pub, stream: streamNuget,
		deliver: func(sequence int64) string {
			exported, err := low.CollectNuget(t.Context(), NugetCollectRequest{
				Packages: []string{fmt.Sprintf("Repair.Pkg@%d.0.0", sequence)},
			})
			if err != nil {
				t.Fatal(err)
			}
			transferAptBundle(t, low, high, exported.BundleID)
			return exported.BundleID
		},
		faultPath: filepath.Join(high.nugetMetadataDir(), "repair.pkg", "2.0.0.nuspec"),
		partial:   filepath.Join(high.nugetMetadataDir(), "repair.pkg", "2.0.0.json"),
		assertFeed: func(t *testing.T, high *HighServer) {
			srv := httptest.NewServer(high)
			defer srv.Close()
			nugetTestAssertVersions(t, srv.URL, "repair.pkg", []string{"1.0.0", "2.0.0"})
			for version, data := range payloads {
				assertPublicationDownload(t, srv.URL+"/nuget/v3-flatcontainer/repair.pkg/"+version+"/repair.pkg."+version+".nupkg", data)
				if code, _ := httpGet(t, srv.URL+"/nuget/v3-flatcontainer/repair.pkg/"+version+"/repair.pkg.nuspec"); code != http.StatusOK {
					t.Errorf("nuspec %s status = %d, want 200", version, code)
				}
			}
		},
	}
}

func newNpmPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	fx := newNpmMetadataFixture(t)
	return publicationFixture{
		high: fx.high, publicKey: fx.priv.Public().(ed25519.PublicKey), stream: streamNpm,
		deliver: func(sequence int64) string {
			version := fmt.Sprintf("%d.0.0", sequence)
			fx.selectVersions(t, version)
			fx.setTags(t, map[string]string{"latest": version})
			exported := fx.collect(t)
			transferAptBundle(t, fx.low, fx.high, exported.BundleID)
			return exported.BundleID
		},
		faultPath: filepath.Join(fx.high.npmMetadataDir(), "tagpkg", "2.0.0.json"),
		assertFeed: func(t *testing.T, high *HighServer) {
			srv := httptest.NewServer(high)
			defer srv.Close()
			code, body := httpGet(t, srv.URL+"/npm/tagpkg")
			if code != http.StatusOK {
				t.Fatalf("packument status = %d: %s", code, body)
			}
			var doc struct {
				Versions map[string]json.RawMessage `json:"versions"`
				Tags     map[string]string          `json:"dist-tags"`
			}
			if err := json.Unmarshal([]byte(body), &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Versions) != 2 || doc.Versions["1.0.0"] == nil || doc.Versions["2.0.0"] == nil || doc.Tags["latest"] != "2.0.0" {
				t.Fatalf("packument lost versions or tags after retry: %s", body)
			}
			for _, version := range []string{"1.0.0", "2.0.0"} {
				assertPublicationDownload(t, srv.URL+"/npm/tagpkg/-/"+npmTarballFilename("tagpkg", version), fx.tarballs["tagpkg@"+version])
			}
		},
	}
}

func newCratesPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	_, low, privateKey := cratesTestSetup(t)
	pub := privateKey.Public().(ed25519.PublicKey)
	high := newTestHighServer(t, pub)
	return publicationFixture{
		high: high, publicKey: pub, stream: streamCrates,
		deliver: func(sequence int64) string {
			version := []string{"0.9.0", "1.0.0"}[sequence-1]
			resolveDeps := false
			exported, err := low.CollectCrates(t.Context(), CratesCollectRequest{
				Crates: []string{"mylib@" + version}, ResolveDeps: &resolveDeps,
			})
			if err != nil {
				t.Fatal(err)
			}
			transferAptBundle(t, low, high, exported.BundleID)
			return exported.BundleID
		},
		faultPath: filepath.Join(high.cratesIndexDir(), filepath.FromSlash(crateIndexPath("mylib"))),
		assertFeed: func(t *testing.T, high *HighServer) {
			srv := httptest.NewServer(high)
			defer srv.Close()
			cratesAssertServedIndex(t, srv.URL, "mylib", "0.9.0", "1.0.0")
		},
	}
}

func newComposerPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	repo := newComposerTestRepo(t)
	payloads := map[string][]byte{}
	for _, version := range []string{"1.0.0", "2.0.0"} {
		payloads[version] = repo.add("acme/repair", version, version+".0", nil)
	}
	low, privateKey := newComposerLowServer(t, repo.srv.URL)
	pub := privateKey.Public().(ed25519.PublicKey)
	high := newTestHighServer(t, pub)
	return publicationFixture{
		high: high, publicKey: pub, stream: streamComposer,
		deliver: func(sequence int64) string {
			exported, err := low.CollectComposer(t.Context(), ComposerCollectRequest{
				Packages: []string{fmt.Sprintf("acme/repair:%d.0.0", sequence)}, NoDeps: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			transferAptBundle(t, low, high, exported.BundleID)
			return exported.BundleID
		},
		faultPath: filepath.Join(high.composerMetadataDir(), "acme", "repair", "2.0.0.0.json"),
		assertFeed: func(t *testing.T, high *HighServer) {
			srv := httptest.NewServer(high)
			defer srv.Close()
			code, body := httpGet(t, srv.URL+"/composer/p2/acme/repair.json")
			if code != http.StatusOK {
				t.Fatalf("p2 status = %d: %s", code, body)
			}
			versions := composerP2Versions(t, body, "acme/repair")
			if len(versions) != 2 || composerString(versions[0], "version_normalized") != "2.0.0.0" || composerString(versions[1], "version_normalized") != "1.0.0.0" {
				t.Fatalf("p2 lost versions after retry: %s", body)
			}
			for version, data := range payloads {
				assertPublicationDownload(t, srv.URL+"/composer/dist/acme/repair/"+version+".0.zip", data)
			}
		},
	}
}

func newRubyGemsPublicationFixture(t *testing.T) publicationFixture {
	t.Helper()
	reg, low, privateKey := rubygemsTestSetup(t)
	pub := privateKey.Public().(ed25519.PublicKey)
	high := newTestHighServer(t, pub)
	return publicationFixture{
		high: high, publicKey: pub, stream: streamRubyGems,
		deliver: func(sequence int64) string {
			version := []string{"0.9.0", "1.0.0"}[sequence-1]
			exported, err := low.CollectRubyGems(t.Context(), RubyGemsCollectRequest{
				Gems: []string{"mylib@" + version}, NoDeps: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			transferAptBundle(t, low, high, exported.BundleID)
			return exported.BundleID
		},
		faultPath: filepath.Join(high.rubygemsMetadataDir(), "mylib.json"),
		assertFeed: func(t *testing.T, high *HighServer) {
			srv := httptest.NewServer(high)
			defer srv.Close()
			versions := rubygemsFetchVersions(t, srv.URL)
			if len(versions) != 1 || versions["mylib"][0] != "0.9.0,1.0.0" {
				t.Fatalf("gem versions after retry = %v", versions)
			}
			code, body := httpGet(t, srv.URL+"/rubygems/info/mylib")
			want := "---\n" + reg.line(t, "mylib", "0.9.0") + "\n" + reg.line(t, "mylib", "1.0.0") + "\n"
			if code != http.StatusOK || body != want {
				t.Errorf("gem info after retry = %d %q, want %q", code, body, want)
			}
			code, body = httpGet(t, srv.URL+"/rubygems/names")
			if code != http.StatusOK || !strings.HasSuffix(body, "---\nmylib\n") {
				t.Errorf("gem names after retry = %d %q", code, body)
			}
			for _, version := range []string{"0.9.0", "1.0.0"} {
				assertPublicationDownload(t, srv.URL+"/rubygems/gems/mylib-"+version+".gem", gemTestPayload("mylib", version))
			}
		},
	}
}
