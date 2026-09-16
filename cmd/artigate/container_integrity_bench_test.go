package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkContainerIntegrityHistory models repeated attachment collection:
// eight repository indexes retain the same 256 historical artifacts, each
// with 4 KiB of annotations. Shared blobs are hashed once per complete scan.
func BenchmarkContainerIntegrityHistory(b *testing.B) {
	root, size := integrityBenchmarkHistory(b, 8, 256)
	b.ReportAllocs()
	b.SetBytes(size)
	for b.Loop() {
		report, err := checkContainerIntegrity(b.Context(), containerIntegrityOptions{Root: root})
		if err != nil || !report.OK || len(report.Repositories) != 8 {
			b.Fatalf("integrity scan: %+v (%v)", report, err)
		}
	}
}

func integrityBenchmarkHistory(b *testing.B, repositories, artifacts int) (string, int64) {
	b.Helper()
	root := b.TempDir()
	image := makeFakeImage("integrity-benchmark-image")
	for _, body := range [][]byte{image.manifest, image.config, image.layer} {
		integrityBenchmarkBlob(b, root, body)
	}
	img := ContainerImage{
		Tag: "latest", Digest: image.manifestDigest, MediaType: mtDockerManifest, Size: int64(len(image.manifest)),
		Blobs: []ContainerBlob{
			{Digest: containerSHA(image.config), Size: int64(len(image.config))},
			{Digest: containerSHA(image.layer), Size: int64(len(image.layer))},
		},
	}
	index := newContainerArtifactIndex()
	config, layer := []byte("{}"), []byte("shared historical artifact payload")
	integrityBenchmarkBlob(b, root, config)
	integrityBenchmarkBlob(b, root, layer)
	for i := range artifacts {
		annotations := map[string]string{"description": fmt.Sprintf("Artifact %d: %s", i, strings.Repeat("x", 4<<10))}
		body, err := json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": mtOCIManifest, "artifactType": "application/example",
			"subject":     ociDescriptor{MediaType: mtDockerManifest, Digest: image.manifestDigest, Size: int64(len(image.manifest))},
			"config":      ociDescriptor{MediaType: "application/vnd.oci.empty.v1+json", Digest: containerSHA(config), Size: int64(len(config))},
			"layers":      []ociDescriptor{{MediaType: "application/example", Digest: containerSHA(layer), Size: int64(len(layer))}},
			"annotations": annotations,
		})
		if err != nil {
			b.Fatal(err)
		}
		integrityBenchmarkBlob(b, root, body)
		artifact := ContainerArtifact{
			Digest: containerSHA(body), MediaType: mtOCIManifest, ArtifactType: "application/example",
			Size: int64(len(body)), Subject: image.manifestDigest, Annotations: annotations,
			Blobs: []ContainerBlob{{Digest: containerSHA(config), Size: int64(len(config))}, {Digest: containerSHA(layer), Size: int64(len(layer))}},
		}
		index.Artifacts[artifact.Digest] = artifact
		img.Artifacts = append(img.Artifacts, artifact)
	}
	var size int64
	for i := range repositories {
		repo := ContainerRepo{Registry: "registry.test", Repository: fmt.Sprintf("history/repository-%03d", i), Images: []ContainerImage{img}}
		file := filepath.Join(root, filepath.FromSlash(containerIntegrityRepos), repo.Registry, repo.Repository, "_index.json")
		if err := writeJSONAtomic(file, containerRepoFile{ContainerRepo: repo, ArtifactIndex: index}, 0o644); err != nil {
			b.Fatal(err)
		}
		info, err := os.Stat(file)
		if err != nil {
			b.Fatal(err)
		}
		size += info.Size()
	}
	return root, size
}

func integrityBenchmarkBlob(b *testing.B, root string, body []byte) {
	b.Helper()
	file := filepath.Join(root, "cache", "download", filepath.FromSlash(containerBlobRel(containerSHA(body))))
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(file, body, 0o644); err != nil {
		b.Fatal(err)
	}
}
