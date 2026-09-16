package main

import "testing"

// A platform index may select an opaque artifact. The public tag still names
// the index, and signatures over that index must retain their original subject.
func TestContainerGenericArtifactPreservesPlatformIndex(t *testing.T) {
	f := newArtifactGraphRegistry()
	child := f.addArtifact(t, nil, []byte("opaque amd64 config"), []byte("amd64 artifact payload"))
	child.Platform = &ociPlatform{OS: "linux", Architecture: "amd64"}
	f.root = f.addManifest(t, map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIIndex,
		"manifests": []ociDescriptor{
			child,
			{
				MediaType: mtOCIManifest, Digest: containerSHA([]byte("unmirrored arm64 artifact")), Size: 123,
				Platform: &ociPlatform{OS: "linux", Architecture: "arm64"},
			},
		},
	}, nil)
	signature := f.addArtifact(t, &f.root, []byte("index signature config"), []byte("index signature payload"))
	hs, manifest, _ := collectAndImportArtifactGraph(t, f)
	image := manifest.Containers.Repos[0].Images[0]
	if image.Index == nil || image.Index.Digest != f.root.Digest {
		t.Fatalf("selected artifact lost upstream platform index: %+v", image)
	}
	assertArtifactGraphBody(t, hs, "manifests/1.0", f.manifests[f.root.Digest])
	assertArtifactGraphBody(t, hs, "manifests/"+f.root.Digest, f.manifests[f.root.Digest])
	assertArtifactGraphBody(t, hs, "manifests/"+child.Digest, f.manifests[child.Digest])
	assertArtifactGraphBody(t, hs, "manifests/"+signature.Digest, f.manifests[signature.Digest])
	assertArtifactGraphReferrers(t, hs, f.root, signature)
}
