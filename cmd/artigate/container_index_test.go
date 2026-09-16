package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
)

func TestContainerIndexConcurrentMigrationAndImports(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	const imports = 12
	images := make([]ContainerImage, 0, imports+1)
	for i := 0; i <= imports; i++ {
		fix := makeFakeImage(fmt.Sprintf("concurrent-image-%d", i))
		img := artifactStoreStageImage(t, hs, fix, fmt.Sprintf("version-%d", i))
		art := artifactStoreWithSubject(t,
			makeFakeArtifact("application/vnd.in-toto+json", fmt.Sprintf("concurrent-attestation-%d", i), "application/vnd.in-toto+json", nil),
			ociDescriptor{MediaType: mtDockerManifest, Digest: fix.manifestDigest, Size: int64(len(fix.manifest))})
		img.Artifacts = []ContainerArtifact{artifactStoreStageArtifact(t, hs, art, fix.manifestDigest, cosignArtifactTag(fix.manifestDigest, ".att"))}
		images = append(images, img)
	}
	legacy := ContainerRepo{Registry: "docker.io", Repository: "library/artifact-store", Images: images[:1]}
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	ready := make(chan struct{}, imports*2)
	results := make(chan error, imports*2)
	for i := 1; i <= imports; i++ {
		go func() {
			ready <- struct{}{}
			<-start
			results <- hs.mergeContainerRepo(ContainerRepo{Registry: legacy.Registry, Repository: legacy.Repository, Images: []ContainerImage{images[i]}})
		}()
		go func() {
			ready <- struct{}{}
			<-start
			_, err := hs.loadContainerRepoIndex(artifactStoreRepo)
			results <- err
		}()
	}
	for range imports * 2 {
		<-ready
	}
	close(start)
	for range imports * 2 {
		if err := <-results; err != nil {
			t.Errorf("concurrent repository operation: %v", err)
		}
	}
	restarted, err := NewHighServer(hs.cfg, pub)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := restarted.loadContainerRepoIndex(artifactStoreRepo)
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.Images) != len(images) || len(repo.artifactIndex.Artifacts) != len(images) || len(repo.artifactIndex.Tags) != len(images) {
		t.Fatalf("concurrent operations lost records: images=%d artifacts=%d tags=%d, want %d each", len(repo.Images), len(repo.artifactIndex.Artifacts), len(repo.artifactIndex.Tags), len(images))
	}
	for _, img := range images {
		doc, ok := findContainerManifestDoc(repo, img.Tag)
		if !ok || doc.Digest != img.Digest {
			t.Errorf("image tag %s missing after concurrent import", img.Tag)
		}
		art := img.Artifacts[0]
		doc, ok = findContainerManifestDoc(repo, art.Tag)
		if !ok || doc.Digest != art.Digest {
			t.Errorf("artifact tag %s missing after concurrent import", art.Tag)
		}
		artifactStoreAssertReferrers(t, restarted, img.Digest, art.Digest)
		for _, blob := range art.Blobs {
			if !containerRepoReferencesBlob(repo, blob.Digest) {
				t.Errorf("artifact blob %s lost its repository reference", blob.Digest)
			}
		}
	}
}

func TestContainerIndexFailedMigrationPreservesLegacyIndex(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt func(*testing.T, *HighServer, *ContainerArtifact)
	}{
		{
			name: "missing manifest blob",
			corrupt: func(t *testing.T, hs *HighServer, art *ContainerArtifact) {
				if err := os.Remove(hs.containerBlobPath(art.Digest)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "manifest digest mismatch",
			corrupt: func(t *testing.T, hs *HighServer, art *ContainerArtifact) {
				covR2WriteFile(t, hs.containerBlobPath(art.Digest), []byte(`{"schemaVersion":2,"subject":{"digest":"`+containerSHA([]byte("fabricated-subject"))+`"}}`))
			},
		},
		{
			name: "invalid manifest JSON",
			corrupt: func(t *testing.T, hs *HighServer, art *ContainerArtifact) {
				body := []byte(`{"schemaVersion":`)
				art.Digest = containerSHA(body)
				covR2WriteFile(t, hs.containerBlobPath(art.Digest), body)
			},
		},
		{
			name: "unrecorded artifact blob",
			corrupt: func(_ *testing.T, _ *HighServer, art *ContainerArtifact) {
				art.Blobs = nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, _ := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			fix := makeFakeImage("failed-migration-image")
			img := artifactStoreStageImage(t, hs, fix, "existing")
			art := artifactStoreWithSubject(t,
				makeFakeArtifact("application/vnd.in-toto+json", "failed-migration-attestation", "application/vnd.in-toto+json", nil),
				ociDescriptor{MediaType: mtDockerManifest, Digest: fix.manifestDigest, Size: int64(len(fix.manifest))})
			record := artifactStoreStageArtifact(t, hs, art, containerSHA([]byte("fabricated-subject")), "")
			tc.corrupt(t, hs, &record)
			legacySignature := makeFakeArtifact("application/vnd.dev.cosign.simplesigning.v1+json", "legacy-recovery-signature", "", nil)
			sigTag := cosignArtifactTag(fix.manifestDigest, ".sig")
			legacyRecord := artifactStoreStageArtifact(t, hs, legacySignature, fix.manifestDigest, sigTag)
			img.Artifacts = []ContainerArtifact{record, legacyRecord}
			legacy := ContainerRepo{Registry: "docker.io", Repository: "library/artifact-store", Images: []ContainerImage{img}}
			indexPath := hs.containerRepoIndexPath(artifactStoreRepo)
			if err := writeJSONAtomic(indexPath, legacy, 0o644); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := hs.loadContainerRepoIndex(artifactStoreRepo); err == nil {
				t.Error("corrupt artifact must fail migration")
			}
			for _, subject := range []string{fix.manifestDigest, record.Subject} {
				response := artifactStoreRequest(hs, "referrers/"+subject)
				if response.Code == http.StatusOK {
					var index ociReferrersIndex
					if err := json.Unmarshal(response.Body.Bytes(), &index); err != nil {
						t.Fatal(err)
					}
					if len(index.Manifests) != 0 {
						t.Errorf("failed migration published referrers: %+v", index.Manifests)
					}
				}
			}
			newImage := artifactStoreStageImage(t, hs, makeFakeImage("new-import-image"), "new")
			if err := hs.mergeContainerRepo(ContainerRepo{Registry: legacy.Registry, Repository: legacy.Repository, Images: []ContainerImage{newImage}}); err == nil {
				t.Error("import must not replace a legacy index whose migration failed")
			}
			after, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Error("failed migration or import overwrote the original index")
			}
			if tc.name == "missing manifest blob" || tc.name == "manifest digest mismatch" {
				// Repairing the manifest permits a later read to migrate the
				// original index without restoring the fabricated metadata subject.
				covR2WriteFile(t, hs.containerBlobPath(art.digest), art.manifest)
				artifactStoreAssertBody(t, hs, "manifests/"+sigTag, legacySignature.manifest)
				artifactStoreAssertBody(t, hs, "manifests/"+art.digest, art.manifest)
				artifactStoreAssertReferrers(t, hs, fix.manifestDigest, art.digest)
				artifactStoreAssertReferrers(t, hs, record.Subject)
			}
		})
	}
}
