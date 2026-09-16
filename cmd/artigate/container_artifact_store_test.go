package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
)

const artifactStoreRepo = "docker.io/library/artifact-store"

func artifactStoreWithSubject(t *testing.T, art fakeArtifact, subject ociDescriptor) fakeArtifact {
	t.Helper()
	var manifest map[string]any
	if err := json.Unmarshal(art.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["subject"] = subject
	var err error
	art.manifest, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	art.digest = containerSHA(art.manifest)
	return art
}

func artifactStoreStageImage(t *testing.T, hs *HighServer, fix fakeImage, tag string) ContainerImage {
	t.Helper()
	for _, body := range [][]byte{fix.manifest, fix.config, fix.layer} {
		covR2WriteFile(t, hs.containerBlobPath(containerSHA(body)), body)
	}
	return ContainerImage{
		Tag: tag, Digest: fix.manifestDigest, MediaType: mtDockerManifest, Size: int64(len(fix.manifest)),
		Blobs: []ContainerBlob{
			{Digest: containerSHA(fix.config), Size: int64(len(fix.config))},
			{Digest: containerSHA(fix.layer), Size: int64(len(fix.layer))},
		},
	}
}

func artifactStoreStageArtifact(t *testing.T, hs *HighServer, art fakeArtifact, subject, tag string) ContainerArtifact {
	t.Helper()
	for _, body := range [][]byte{art.manifest, art.config, art.layer} {
		covR2WriteFile(t, hs.containerBlobPath(containerSHA(body)), body)
	}
	return ContainerArtifact{
		Subject: subject, Tag: tag, Digest: art.digest, MediaType: mtOCIManifest, Size: int64(len(art.manifest)),
		Blobs: []ContainerBlob{
			{Digest: containerSHA(art.config), Size: int64(len(art.config))},
			{Digest: containerSHA(art.layer), Size: int64(len(art.layer))},
		},
	}
}

func artifactStoreMerge(t *testing.T, hs *HighServer, images ...ContainerImage) {
	t.Helper()
	if err := hs.mergeContainerRepo(ContainerRepo{
		Registry: "docker.io", Repository: "library/artifact-store", Images: images,
	}); err != nil {
		t.Fatal(err)
	}
}

func artifactStoreRequest(hs *HighServer, resource string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	hs.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/"+artifactStoreRepo+"/"+resource, nil))
	return rec
}

func artifactStoreAssertBody(t *testing.T, hs *HighServer, resource string, want []byte) {
	t.Helper()
	resp := artifactStoreRequest(hs, resource)
	if resp.Code != http.StatusOK || resp.Body.String() != string(want) {
		t.Errorf("GET %s = %d %s, want stored content", resource, resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Docker-Content-Digest"); got != containerSHA(want) {
		t.Errorf("GET %s digest = %q, want %q", resource, got, containerSHA(want))
	}
}

func artifactStoreAssertReferrers(t *testing.T, hs *HighServer, subject string, want ...string) []ociDescriptor {
	t.Helper()
	resp := artifactStoreRequest(hs, "referrers/"+subject)
	if resp.Code != http.StatusOK {
		t.Fatalf("referrers/%s = %d %s", subject, resp.Code, resp.Body.String())
	}
	var index ociReferrersIndex
	if err := json.Unmarshal(resp.Body.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(index.Manifests))
	for _, desc := range index.Manifests {
		got = append(got, desc.Digest)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("referrers/%s = %v, want %v", subject, got, want)
	}
	return index.Manifests
}

func TestContainerArtifactStoreRetainsReferrersAfterDiscoveryFailure(t *testing.T) {
	img := makeFakeImage("artifact-store-refresh")
	subject := containerSHA(img.index)
	art := artifactStoreWithSubject(t,
		makeFakeArtifact("application/vnd.in-toto+json", "stored-attestation", "application/vnd.in-toto+json", nil),
		ociDescriptor{MediaType: mtDockerList, Digest: subject, Size: int64(len(img.index))})
	mux, requireToken, upstream := newFakeRegistry(t)
	registerFakeImage(mux, "library/artifact-store", "latest", img, requireToken)
	registerFakeArtifact(mux, "library/artifact-store", "", art, requireToken)
	var discoveryUnavailable atomic.Bool
	mux.HandleFunc("/v2/library/artifact-store/referrers/"+subject, func(w http.ResponseWriter, _ *http.Request) {
		if discoveryUnavailable.Load() {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", mtOCIIndex)
		_ = json.NewEncoder(w).Encode(ociReferrersIndex{
			SchemaVersion: 2, MediaType: mtOCIIndex,
			Manifests: []ociDescriptor{{MediaType: mtOCIManifest, Digest: art.digest, Size: int64(len(art.manifest)), ArtifactType: "application/vnd.in-toto+json"}},
		})
	})
	ls, priv := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	collectAndImport := func() {
		t.Helper()
		res, err := ls.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"artifact-store:latest"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Skipped {
			t.Fatal("metadata refresh must produce an importable bundle")
		}
		transferAptBundle(t, ls, hs, res.BundleID)
		if _, err := hs.ImportNext(); err != nil {
			t.Fatal(err)
		}
	}
	collectAndImport()
	artifactStoreAssertReferrers(t, hs, subject, art.digest)
	discoveryUnavailable.Store(true)
	collectAndImport()
	artifactStoreAssertReferrers(t, hs, subject, art.digest)
	artifactStoreAssertBody(t, hs, "manifests/"+art.digest, art.manifest)
	artifactStoreAssertBody(t, hs, "blobs/"+containerSHA(art.layer), art.layer)
}

func TestContainerArtifactStoreMovesLegacyTagAcrossImageAliases(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	fix := makeFakeImage("artifact-store-alias")
	oldArt := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "old-signatures", "", nil)
	newArt := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "new-signatures", "", nil)
	sigTag := cosignArtifactTag(fix.manifestDigest, ".sig")
	oldRecord := artifactStoreStageArtifact(t, hs, oldArt, fix.manifestDigest, sigTag)
	newRecord := artifactStoreStageArtifact(t, hs, newArt, fix.manifestDigest, sigTag)
	image := artifactStoreStageImage(t, hs, fix, "1.0")
	image.Artifacts = []ContainerArtifact{oldRecord}
	latest := image
	latest.Tag = "latest"
	artifactStoreMerge(t, hs, image, latest)
	latest.Artifacts = []ContainerArtifact{newRecord}
	artifactStoreMerge(t, hs, latest)
	artifactStoreAssertBody(t, hs, "manifests/"+sigTag, newArt.manifest)
	// An unrelated refresh of another alias must not restore its stale tag mapping.
	image.Artifacts = nil
	artifactStoreMerge(t, hs, image)
	restarted, err := NewHighServer(hs.cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	artifactStoreAssertBody(t, restarted, "manifests/"+sigTag, newArt.manifest)
	for _, art := range []fakeArtifact{oldArt, newArt} {
		artifactStoreAssertBody(t, restarted, "manifests/"+art.digest, art.manifest)
		artifactStoreAssertBody(t, restarted, "blobs/"+containerSHA(art.layer), art.layer)
	}
	artifactStoreAssertReferrers(t, restarted, fix.manifestDigest)
}

func TestContainerArtifactStoreAdvertisesOnlyNativeSubjects(t *testing.T) {
	hs, fix := collectAndImportSignedContainer(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	base := srv.URL + "/v2/docker.io/library/signed/"
	_, refs := fetchReferrersIndex(t, base+"referrers/"+fix.indexDigest)
	if len(refs.Manifests) != 0 {
		t.Errorf("legacy cosign signature advertised as native OCI referrer: %+v", refs.Manifests)
	}
	_, refs = fetchReferrersIndex(t, base+"referrers/"+fix.img.manifestDigest)
	if len(refs.Manifests) != 1 || refs.Manifests[0].Digest != fix.refAtt.digest {
		t.Errorf("native referrers = %+v, want only native attestation %s", refs.Manifests, fix.refAtt.digest)
	}
	assertHTTPBody(t, base+"manifests/"+cosignArtifactTag(fix.indexDigest, ".sig"), string(fix.sig.manifest))
	assertHTTPBody(t, base+"manifests/"+fix.att.digest, string(fix.att.manifest))
}

func TestContainerArtifactStoreMigratesLegacyIndex(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	fix := makeFakeImage("artifact-store-migration")
	image := artifactStoreStageImage(t, hs, fix, "latest")
	legacy := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "legacy-signature", "", nil)
	native := artifactStoreWithSubject(t,
		makeFakeArtifact("application/vnd.in-toto+json", "native-attestation", "application/vnd.in-toto+json", map[string]string{"source": "manifest"}),
		ociDescriptor{MediaType: mtDockerManifest, Digest: fix.manifestDigest, Size: int64(len(fix.manifest))})
	wrongSubject := containerSHA([]byte("incorrect legacy metadata"))
	sigTag := cosignArtifactTag(fix.manifestDigest, ".sig")
	legacyRecord := artifactStoreStageArtifact(t, hs, legacy, fix.manifestDigest, sigTag)
	nativeRecord := artifactStoreStageArtifact(t, hs, native, wrongSubject, "")
	nativeRecord.ArtifactType = "application/vnd.example.incorrect"
	nativeRecord.Annotations = map[string]string{"source": "incorrect metadata"}
	image.Artifacts = []ContainerArtifact{legacyRecord, nativeRecord}
	oldIndex := ContainerRepo{Registry: "docker.io", Repository: "library/artifact-store", Images: []ContainerImage{image}}
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), oldIndex, 0o644); err != nil {
		t.Fatal(err)
	}
	verify := func(server *HighServer) {
		t.Helper()
		artifactStoreAssertBody(t, server, "manifests/"+sigTag, legacy.manifest)
		artifactStoreAssertBody(t, server, "manifests/"+native.digest, native.manifest)
		artifactStoreAssertBody(t, server, "blobs/"+containerSHA(legacy.layer), legacy.layer)
		refs := artifactStoreAssertReferrers(t, server, fix.manifestDigest, native.digest)
		if len(refs) == 1 && (refs[0].ArtifactType != "application/vnd.in-toto+json" || refs[0].Annotations["source"] != "manifest") {
			t.Errorf("native descriptor must use actual manifest metadata: %+v", refs[0])
		}
		artifactStoreAssertReferrers(t, server, wrongSubject)
		filtered := artifactStoreRequest(server, "referrers/"+fix.manifestDigest+"?artifactType="+url.QueryEscape("application/vnd.in-toto+json"))
		var index ociReferrersIndex
		if err := json.Unmarshal(filtered.Body.Bytes(), &index); err != nil {
			t.Fatal(err)
		}
		if filtered.Code != http.StatusOK || len(index.Manifests) != 1 || index.Manifests[0].Digest != native.digest {
			t.Errorf("filtered migrated referrers = %d %+v", filtered.Code, index)
		}
	}
	verify(hs)
	image.Artifacts = nil
	artifactStoreMerge(t, hs, image)
	restarted, err := NewHighServer(hs.cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	verify(restarted)
}

func TestContainerArtifactStoreMigratesConflictingLegacyTags(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	fix := makeFakeImage("artifact-store-conflicting-aliases")
	first := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "first-signature", "", nil)
	second := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "second-signature", "", nil)
	sigTag := cosignArtifactTag(fix.manifestDigest, ".sig")
	versioned := artifactStoreStageImage(t, hs, fix, "1.0")
	versioned.Artifacts = []ContainerArtifact{artifactStoreStageArtifact(t, hs, first, fix.manifestDigest, sigTag)}
	latest := artifactStoreStageImage(t, hs, fix, "latest")
	latest.Artifacts = []ContainerArtifact{artifactStoreStageArtifact(t, hs, second, fix.manifestDigest, sigTag)}
	oldIndex := ContainerRepo{
		Registry: "docker.io", Repository: "library/artifact-store", Images: []ContainerImage{versioned, latest},
	}
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), oldIndex, 0o644); err != nil {
		t.Fatal(err)
	}
	// Old indexes have no import chronology, so migration preserves the
	// previously effective first mapping until a new import supplies one.
	artifactStoreAssertBody(t, hs, "manifests/"+sigTag, first.manifest)
	artifactStoreMerge(t, hs, latest)
	artifactStoreAssertBody(t, hs, "manifests/"+sigTag, second.manifest)
	artifactStoreAssertBody(t, hs, "manifests/"+first.digest, first.manifest)
	artifactStoreAssertBody(t, hs, "manifests/"+second.digest, second.manifest)
}

func TestContainerArtifactStoreSharesTagNamespaceWithImages(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	fix := makeFakeImage("artifact-store-shared-tag")
	first := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "discovered-signature", "", nil)
	second := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "directly-collected-signature", "", nil)
	sigTag := cosignArtifactTag(fix.manifestDigest, ".sig")
	firstRecord := artifactStoreStageArtifact(t, hs, first, fix.manifestDigest, sigTag)
	secondRecord := artifactStoreStageArtifact(t, hs, second, fix.manifestDigest, sigTag)
	image := artifactStoreStageImage(t, hs, fix, "latest")
	image.Artifacts = []ContainerArtifact{firstRecord}
	artifactStoreMerge(t, hs, image)
	// A signature reference can also be collected directly through the
	// container collector, which stores it as a top-level image record.
	direct := ContainerImage{
		Tag: sigTag, Digest: second.digest, MediaType: mtOCIManifest,
		Size: int64(len(second.manifest)), Blobs: secondRecord.Blobs,
	}
	artifactStoreMerge(t, hs, direct)
	artifactStoreAssertBody(t, hs, "manifests/"+sigTag, second.manifest)
	// A later attachment observation must be able to move that same tag back.
	artifactStoreMerge(t, hs, image)
	artifactStoreAssertBody(t, hs, "manifests/"+sigTag, first.manifest)
	artifactStoreAssertBody(t, hs, "manifests/"+first.digest, first.manifest)
	artifactStoreAssertBody(t, hs, "manifests/"+second.digest, second.manifest)
}
