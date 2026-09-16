package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A referrers response is mutable discovery metadata. Only the downloaded
// manifest can establish the native OCI subject relationship.
func TestCollectContainersReferrerSubjects(t *testing.T) {
	for _, discovery := range []string{"api", "fallback"} {
		t.Run(discovery, func(t *testing.T) {
			for _, subjectCase := range []string{"matching", "mismatched", "absent"} {
				t.Run(subjectCase, func(t *testing.T) {
					img := makeFakeImage("subject-validation-root")
					art := makeFakeArtifact(
						"application/vnd.in-toto+json",
						"subject-validation-attestation",
						"application/vnd.in-toto+json",
						map[string]string{"org.example.source": "manifest"},
					)
					if subjectCase != "absent" {
						subjectImage := img
						if subjectCase == "mismatched" {
							subjectImage = makeFakeImage("another-subject")
						}
						art = fakeArtifactWithSubject(t, art, ociDescriptor{
							MediaType: mtDockerManifest,
							Digest:    subjectImage.manifestDigest,
							Size:      int64(len(subjectImage.manifest)),
						})
					}

					mux, requireToken, srv := newFakeRegistry(t)
					const repo = "library/subject-validation"
					registerFakeImage(mux, repo, "1.0", img, requireToken)
					registerFakeArtifact(mux, repo, "", art, requireToken)
					referrers, err := json.Marshal(ociReferrersIndex{
						SchemaVersion: 2,
						MediaType:     mtOCIIndex,
						Manifests: []ociDescriptor{{
							MediaType: mtOCIManifest, Digest: art.digest, Size: int64(len(art.manifest)),
							ArtifactType: "application/vnd.example.spoofed+json",
							// An upstream descriptor cannot opt out of subject
							// validation by claiming to be a BuildKit entry.
							Annotations: map[string]string{
								"org.example.source":          "mutable discovery",
								"vnd.docker.reference.type":   "attestation-manifest",
								"vnd.docker.reference.digest": img.manifestDigest,
							},
						}},
					})
					if err != nil {
						t.Fatal(err)
					}
					endpoint := "/v2/" + repo + "/referrers/" + img.manifestDigest
					if discovery == "fallback" {
						endpoint = "/v2/" + repo + "/manifests/" + cosignArtifactTag(img.manifestDigest, "")
					}
					mux.HandleFunc(endpoint, fakeRegistryServe(referrers, mtOCIIndex, requireToken))
					ls, _ := newContainerLowServer(t, map[string]string{"docker.io": srv.URL})
					progress := []string{}
					ctx := withProgress(context.Background(), func(line string) { progress = append(progress, line) })
					res, err := ls.CollectContainers(ctx, ContainerCollectRequest{Images: []string{"subject-validation:1.0"}})
					if err != nil || res.ExportedModules != 1 {
						t.Fatalf("image collection = %+v, %v", res, err)
					}
					manifest := readBundleManifest(t, ls, res.BundleID)
					artifacts := manifest.Containers.Repos[0].Images[0].Artifacts
					if subjectCase == "matching" {
						if len(artifacts) != 1 || artifacts[0].Digest != art.digest || artifacts[0].Subject != img.manifestDigest {
							t.Fatalf("native referrer missing its verified subject: %+v", artifacts)
						}
						if artifacts[0].Annotations["org.example.source"] != "manifest" || len(artifacts[0].Annotations) != 1 {
							t.Fatalf("mutable discovery metadata replaced native annotations: %+v", artifacts[0].Annotations)
						}
						if artifacts[0].ArtifactType != "application/vnd.in-toto+json" {
							t.Fatalf("mutable discovery metadata replaced native type: %s", artifacts[0].ArtifactType)
						}
						return
					}
					if len(artifacts) != 0 {
						t.Fatalf("invalid native referrer was collected: %+v", artifacts)
					}
					for _, file := range manifest.Files {
						if file.Path == containerBlobRel(art.digest) || file.Path == containerBlobRel(containerSHA(art.layer)) {
							t.Fatalf("rejected artifact was included in the signed bundle: %s", file.Path)
						}
					}
					warned := false
					for _, line := range progress {
						if strings.Contains(line, "⚠ artifact ") && strings.Contains(line, "subject") {
							warned = true
						}
					}
					if !warned {
						t.Fatalf("missing subject warning: %v", progress)
					}
				})
			}
		})
	}
}

func TestCollectContainersNativeArtifactTypes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		manifestType string
		configType   string
		want         string
	}{
		{
			name: "manifest type", manifestType: "application/vnd.example.sbom.v1+json",
			configType: "application/vnd.example.config.v1+json", want: "application/vnd.example.sbom.v1+json",
		},
		{
			name: "config fallback", configType: "application/vnd.example.config.v1+json",
			want: "application/vnd.example.config.v1+json",
		},
		{name: "missing native type is not replaced by descriptor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := makeFakeImage("native-artifact-type-root")
			art := makeFakeArtifact("application/octet-stream", "native-artifact-type-layer", tc.manifestType, nil)
			var manifest map[string]any
			if err := json.Unmarshal(art.manifest, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["config"].(map[string]any)["mediaType"] = tc.configType
			var err error
			art.manifest, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			art = fakeArtifactWithSubject(t, art, ociDescriptor{
				MediaType: mtDockerManifest, Digest: img.manifestDigest, Size: int64(len(img.manifest)),
			})
			mux, requireToken, srv := newFakeRegistry(t)
			const repo = "library/native-type"
			registerFakeImage(mux, repo, "1.0", img, requireToken)
			registerFakeArtifact(mux, repo, "", art, requireToken)
			referrers, err := json.Marshal(ociReferrersIndex{
				SchemaVersion: 2, MediaType: mtOCIIndex,
				Manifests: []ociDescriptor{{
					MediaType: mtOCIManifest, Digest: art.digest, Size: int64(len(art.manifest)),
					ArtifactType: "application/vnd.example.spoofed+json",
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			mux.HandleFunc("/v2/"+repo+"/referrers/"+img.manifestDigest, fakeRegistryServe(referrers, mtOCIIndex, requireToken))
			ls, _ := newContainerLowServer(t, map[string]string{"docker.io": srv.URL})
			res, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"native-type:1.0"}})
			if err != nil {
				t.Fatal(err)
			}
			artifacts := readBundleManifest(t, ls, res.BundleID).Containers.Repos[0].Images[0].Artifacts
			if len(artifacts) != 1 || artifacts[0].ArtifactType != tc.want {
				t.Fatalf("native artifact metadata = %+v, want type %q", artifacts, tc.want)
			}
		})
	}
}

func TestCollectContainersKeepsLegacyArtifactAssociations(t *testing.T) {
	fix, srv := newSignedImageRegistry(t)
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": srv.URL})
	res, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"signed:1.0"}})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := readBundleManifest(t, ls, res.BundleID).Containers.Repos[0].Images[0].Artifacts
	if len(artifacts) != 3 {
		t.Fatalf("artifacts = %+v, want native referrer, legacy cosign signature and BuildKit attestation", artifacts)
	}
	byDigest := map[string]ContainerArtifact{}
	for _, artifact := range artifacts {
		byDigest[artifact.Digest] = artifact
	}
	if sig := byDigest[fix.sig.digest]; sig.Subject != fix.indexDigest || sig.Tag != cosignArtifactTag(fix.indexDigest, ".sig") {
		t.Fatalf("legacy cosign association changed: %+v", sig)
	}
	if att := byDigest[fix.att.digest]; att.Subject != fix.img.manifestDigest {
		t.Fatalf("legacy BuildKit association changed: %+v", att)
	}
	for _, legacy := range []fakeArtifact{fix.sig, fix.att} {
		var manifest ociManifest
		if err := json.Unmarshal(legacy.manifest, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Subject != nil {
			t.Fatalf("legacy test artifact unexpectedly carries a native subject: %+v", manifest.Subject)
		}
	}
}
