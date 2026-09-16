package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type artifactGraphRegistry struct {
	root      ociDescriptor
	manifests map[string][]byte
	types     map[string]string
	blobs     map[string][]byte
	referrers map[string][]ociDescriptor
	aliases   map[string]bool
	mu        sync.Mutex
	requests  map[string]int
}

func newArtifactGraphRegistry() *artifactGraphRegistry {
	img := makeFakeImage("artifact-graph-image-layer")
	return &artifactGraphRegistry{
		root:      ociDescriptor{MediaType: mtDockerManifest, Digest: img.manifestDigest, Size: int64(len(img.manifest))},
		manifests: map[string][]byte{img.manifestDigest: img.manifest},
		types:     map[string]string{img.manifestDigest: mtDockerManifest},
		blobs:     map[string][]byte{containerSHA(img.config): img.config, containerSHA(img.layer): img.layer},
		referrers: map[string][]ociDescriptor{},
		aliases:   map[string]bool{"1.0": true},
		requests:  map[string]int{},
	}
}

func (f *artifactGraphRegistry) addManifest(t *testing.T, body map[string]any, subject *ociDescriptor) ociDescriptor {
	t.Helper()
	if subject != nil {
		body["subject"] = subject
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	desc := ociDescriptor{MediaType: body["mediaType"].(string), Digest: containerSHA(b), Size: int64(len(b))}
	if artifactType, ok := body["artifactType"].(string); ok {
		desc.ArtifactType = artifactType
	}
	f.manifests[desc.Digest] = b
	f.types[desc.Digest] = desc.MediaType
	if subject != nil {
		f.referrers[subject.Digest] = append(f.referrers[subject.Digest], desc)
	}
	return desc
}

func (f *artifactGraphRegistry) addArtifact(
	t *testing.T,
	subject *ociDescriptor,
	config, layer []byte,
) ociDescriptor {
	t.Helper()
	configDigest, layerDigest := containerSHA(config), containerSHA(layer)
	f.blobs[configDigest], f.blobs[layerDigest] = config, layer
	return f.addManifest(t, map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIManifest,
		"artifactType":  "application/vnd.example.graph-artifact.v1",
		"config": ociDescriptor{
			MediaType: "application/vnd.example.opaque-config.v1", Digest: configDigest, Size: int64(len(config)),
		},
		"layers": []ociDescriptor{{MediaType: "application/octet-stream", Digest: layerDigest, Size: int64(len(layer))}},
	}, subject)
}

func (f *artifactGraphRegistry) addIndex(t *testing.T, subject *ociDescriptor, children ...ociDescriptor) ociDescriptor {
	t.Helper()
	return f.addManifest(t, map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIIndex,
		"artifactType":  "application/vnd.example.graph-bundle.v1",
		"manifests":     children,
	}, subject)
}

func (f *artifactGraphRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resource := strings.TrimPrefix(r.URL.Path, "/v2/library/graph/")
	f.mu.Lock()
	f.requests[resource]++
	f.mu.Unlock()
	switch {
	case strings.HasPrefix(resource, "manifests/"):
		digest := strings.TrimPrefix(resource, "manifests/")
		if f.aliases[digest] {
			digest = f.root.Digest
		}
		body, ok := f.manifests[digest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", f.types[digest])
		_, _ = w.Write(body)
	case strings.HasPrefix(resource, "blobs/"):
		body, ok := f.blobs[strings.TrimPrefix(resource, "blobs/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	case strings.HasPrefix(resource, "referrers/"):
		descriptors := f.referrers[strings.TrimPrefix(resource, "referrers/")]
		if descriptors == nil {
			descriptors = []ociDescriptor{}
		}
		w.Header().Set("Content-Type", mtOCIIndex)
		_ = json.NewEncoder(w).Encode(ociReferrersIndex{SchemaVersion: 2, MediaType: mtOCIIndex, Manifests: descriptors})
	default:
		http.NotFound(w, r)
	}
}

func (f *artifactGraphRegistry) requestCount(resource string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[resource]
}

func collectAndImportArtifactGraph(t *testing.T, fixture *artifactGraphRegistry) (*HighServer, BundleManifest, []string) {
	t.Helper()
	upstream := httptest.NewServer(fixture)
	t.Cleanup(upstream.Close)
	ls, priv := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
	progress := []string{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = withProgress(ctx, func(line string) { progress = append(progress, line) })
	res, err := ls.CollectContainers(ctx, ContainerCollectRequest{Images: []string{"graph:1.0"}})
	if err != nil || res.ExportedModules != 1 {
		t.Fatalf("collect graph = %+v, %v; progress: %v", res, err, progress)
	}
	manifest := readBundleManifest(t, ls, res.BundleID)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	stageArtifactGraphBundle(t, hs, ls, res.BundleID)
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("import graph: %v", err)
	}
	return hs, manifest, progress
}

func stageArtifactGraphBundle(t *testing.T, hs *HighServer, ls *LowServer, bundleID string) {
	t.Helper()
	for _, suffix := range bundleSuffixes() {
		name := bundleID + suffix
		body, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), body)
	}
}

func artifactGraphRequest(hs *HighServer, resource string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	hs.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v2/docker.io/library/graph/"+resource, nil))
	return response
}

func assertArtifactGraphBody(t *testing.T, hs *HighServer, resource string, want []byte) {
	t.Helper()
	response := artifactGraphRequest(hs, resource)
	if response.Code != http.StatusOK || response.Body.String() != string(want) {
		t.Fatalf("GET %s = %d %q, want original bytes", resource, response.Code, response.Body.String())
	}
	if got := response.Header().Get("Docker-Content-Digest"); got != containerSHA(want) {
		t.Fatalf("GET %s digest = %q, want %q", resource, got, containerSHA(want))
	}
}

func assertArtifactGraphReferrers(t *testing.T, hs *HighServer, subject ociDescriptor, want ...ociDescriptor) {
	t.Helper()
	response := artifactGraphRequest(hs, "referrers/"+subject.Digest)
	if response.Code != http.StatusOK {
		t.Fatalf("referrers status = %d: %s", response.Code, response.Body.String())
	}
	var index ociReferrersIndex
	if err := json.Unmarshal(response.Body.Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	gotDigests, wantDigests := []string{}, []string{}
	for _, descriptor := range index.Manifests {
		gotDigests = append(gotDigests, descriptor.Digest)
	}
	for _, descriptor := range want {
		wantDigests = append(wantDigests, descriptor.Digest)
	}
	slices.Sort(gotDigests)
	slices.Sort(wantDigests)
	if !slices.Equal(gotDigests, wantDigests) {
		t.Fatalf("referrers(%s) = %v, want %v", subject.Digest, gotDigests, wantDigests)
	}
}

func TestContainerArtifactGraphIndexReferrer(t *testing.T) {
	f := newArtifactGraphRegistry()
	leaf := f.addArtifact(t, nil, []byte("opaque child config"), []byte("artifact payload"))
	inner := f.addIndex(t, nil, leaf)
	index := f.addIndex(t, &f.root, inner, leaf)
	signature := f.addArtifact(t, &leaf, []byte("signature config"), []byte("signature payload"))
	hs, _, _ := collectAndImportArtifactGraph(t, f)
	for _, descriptor := range []ociDescriptor{index, inner, leaf, signature} {
		assertArtifactGraphBody(t, hs, "manifests/"+descriptor.Digest, f.manifests[descriptor.Digest])
	}
	assertArtifactGraphBody(t, hs, "blobs/"+containerSHA([]byte("opaque child config")), []byte("opaque child config"))
	assertArtifactGraphReferrers(t, hs, f.root, index)
	assertArtifactGraphReferrers(t, hs, index)
	assertArtifactGraphReferrers(t, hs, leaf, signature)
	if got := f.requestCount("manifests/" + leaf.Digest); got != 1 {
		t.Fatalf("shared index child fetched %d times, want once", got)
	}
}

func TestContainerArtifactGraphNestedReferrers(t *testing.T) {
	f := newArtifactGraphRegistry()
	sbom := f.addArtifact(t, &f.root, []byte("sbom config"), []byte("sbom payload"))
	signature := f.addArtifact(t, &sbom, []byte("signature config"), []byte("signature payload"))
	hs, _, _ := collectAndImportArtifactGraph(t, f)
	assertArtifactGraphReferrers(t, hs, f.root, sbom)
	assertArtifactGraphReferrers(t, hs, sbom, signature)
	assertArtifactGraphBody(t, hs, "manifests/"+signature.Digest, f.manifests[signature.Digest])
}

func TestContainerArtifactGraphTopLevelOpaqueAndEmptyContent(t *testing.T) {
	for _, tc := range []struct {
		name                string
		config              []byte
		layer               []byte
		withoutArtifactType bool
	}{
		{name: "opaque config and empty layer", config: []byte{0, 0xff, 1, 0xfe}, layer: []byte{}},
		{name: "empty config and opaque layer", config: []byte{}, layer: []byte{0xff, 0, 0xfe}},
		{name: "config media type identifies artifact", config: []byte{0xff, 0}, layer: []byte{}, withoutArtifactType: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArtifactGraphRegistry()
			f.root = f.addArtifact(t, nil, tc.config, tc.layer)
			if tc.withoutArtifactType {
				var body map[string]any
				if err := json.Unmarshal(f.manifests[f.root.Digest], &body); err != nil {
					t.Fatal(err)
				}
				delete(body, "artifactType")
				f.root = f.addManifest(t, body, nil)
			}
			hs, manifest, _ := collectAndImportArtifactGraph(t, f)
			assertArtifactGraphBody(t, hs, "manifests/1.0", f.manifests[f.root.Digest])
			assertArtifactGraphBody(t, hs, "blobs/"+containerSHA(tc.config), tc.config)
			assertArtifactGraphBody(t, hs, "blobs/"+containerSHA(tc.layer), tc.layer)
			foundEmpty := false
			for _, file := range manifest.Files {
				if file.SHA256 == strings.TrimPrefix(containerSHA(nil), "sha256:") && file.Size == 0 {
					foundEmpty = true
				}
			}
			if !foundEmpty {
				t.Fatal("empty content missing from signed bundle metadata")
			}
		})
	}
}

func TestContainerArtifactGraphSubjectPreservesImagePlatformChecks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		manifest   string
		configType string
	}{
		{name: "OCI", manifest: mtOCIManifest, configType: "application/vnd.oci.image.config.v1+json"},
		{name: "Docker", manifest: mtDockerManifest, configType: "application/vnd.docker.container.image.v1+json"},
	} {
		for _, explicitType := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/explicitArtifactType=%t", tc.name, explicitType), func(t *testing.T) {
				f := newArtifactGraphRegistry()
				config, layer := []byte(`{"architecture":"arm64","os":"linux"}`), []byte("arm64 image layer")
				f.blobs[containerSHA(config)], f.blobs[containerSHA(layer)] = config, layer
				body := map[string]any{
					"schemaVersion": 2,
					"mediaType":     tc.manifest,
					"config": ociDescriptor{
						MediaType: tc.configType, Digest: containerSHA(config), Size: int64(len(config)),
					},
					"layers": []ociDescriptor{{Digest: containerSHA(layer), Size: int64(len(layer))}},
				}
				if explicitType {
					body["artifactType"] = "application/vnd.example.image-with-subject.v1"
				}
				f.root = f.addManifest(t, body, &f.root)
				upstream := httptest.NewServer(f)
				t.Cleanup(upstream.Close)
				ls, _ := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
				res, err := ls.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"graph:1.0"}})
				if err == nil || !strings.Contains(err.Error(), "linux/amd64") {
					t.Fatalf("native subject bypassed image platform check: result %+v, error %v", res, err)
				}
				if res.BundleID != "" {
					t.Fatalf("wrong-platform image exported as artifact: bundle %s", res.BundleID)
				}
			})
		}
	}
}

func TestContainerArtifactGraphDirectImageNativeSubject(t *testing.T) {
	f := newArtifactGraphRegistry()
	subject := f.root
	config, layer := []byte(`{"architecture":"amd64","os":"linux"}`), []byte("native subject image layer")
	f.blobs[containerSHA(config)], f.blobs[containerSHA(layer)] = config, layer
	f.root = f.addManifest(t, map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIManifest,
		"config": ociDescriptor{
			MediaType: "application/vnd.oci.image.config.v1+json", Digest: containerSHA(config), Size: int64(len(config)),
		},
		"layers": []ociDescriptor{{Digest: containerSHA(layer), Size: int64(len(layer))}},
	}, &subject)
	hs, _, _ := collectAndImportArtifactGraph(t, f)
	assertArtifactGraphBody(t, hs, "manifests/1.0", f.manifests[f.root.Digest])
	assertArtifactGraphBody(t, hs, "blobs/"+containerSHA(config), config)
	assertArtifactGraphReferrers(t, hs, subject, f.root)
}

func TestContainerArtifactGraphImportRequiresChildRecord(t *testing.T) {
	f := newArtifactGraphRegistry()
	child := f.addArtifact(t, nil, []byte("child config"), []byte("child layer"))
	index := f.addIndex(t, &f.root, child)
	upstream := httptest.NewServer(f)
	t.Cleanup(upstream.Close)
	ls, priv := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
	res, err := ls.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"graph:1.0"}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := readBundleManifest(t, ls, res.BundleID)
	artifacts := manifest.Containers.Repos[0].Images[0].Artifacts
	manifest.Containers.Repos[0].Images[0].Artifacts = slices.DeleteFunc(artifacts, func(artifact ContainerArtifact) bool {
		return artifact.Digest == child.Digest
	})
	body, err := marshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signManifestPH(priv, body)
	if err != nil {
		t.Fatal(err)
	}
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	stageArtifactGraphBundle(t, hs, ls, res.BundleID)
	writeFile(t, filepath.Join(hs.cfg.Landing, res.BundleID+".manifest.json"), body)
	writeFile(t, filepath.Join(hs.cfg.Landing, res.BundleID+".manifest.json.sig"),
		[]byte(manifestSignaturePHPrefix+base64.StdEncoding.EncodeToString(signature)+"\n"))
	if _, err := hs.ImportNext(); err == nil || !strings.Contains(err.Error(), "incomplete child") {
		t.Fatalf("import accepted an index without its child's artifact record: %v", err)
	}
	if response := artifactGraphRequest(hs, "manifests/"+index.Digest); response.Code != http.StatusNotFound {
		t.Fatalf("failed import published incomplete index: status %d", response.Code)
	}
}

func TestContainerArtifactGraphDryRunAndPriorDelta(t *testing.T) {
	f := newArtifactGraphRegistry()
	sharedConfig := []byte("shared opaque config")
	first := f.addArtifact(t, nil, sharedConfig, []byte("first layer"))
	second := f.addArtifact(t, nil, sharedConfig, []byte("second layer"))
	f.root = f.addIndex(t, nil, first, second)
	f.aliases["2.0"] = true
	upstream := httptest.NewServer(f)
	t.Cleanup(upstream.Close)
	ls, priv := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
	dry, err := ls.CollectContainers(withDryRunCollect(t.Context()), ContainerCollectRequest{Images: []string{"graph:1.0"}})
	if err != nil || !dry.DryRun || dry.BundleID != "" || dry.Estimate == nil || dry.Estimate.TotalFiles != 6 {
		t.Fatalf("graph dry run = %+v, %v", dry, err)
	}
	sharedPath := "blobs/" + containerSHA(sharedConfig)
	if got := f.requestCount(sharedPath); got != 0 {
		t.Fatalf("dry run fetched shared artifact config %d times", got)
	}
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	for _, tag := range []string{"1.0", "2.0"} {
		res, err := ls.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"graph:" + tag}})
		if err != nil || res.ExportedModules != 1 {
			t.Fatalf("collect graph tag %s = %+v, %v", tag, res, err)
		}
		if tag == "2.0" {
			for _, file := range readBundleManifest(t, ls, res.BundleID).Files {
				if !file.Prior {
					t.Errorf("metadata-only graph delta lost prior flag: %+v", file)
				}
			}
			if entries := listArchiveEntries(t, ls.cfg.ExportDir, res.BundleID); len(entries) != 0 {
				t.Errorf("metadata-only graph delta repeated payload files: %v", entries)
			}
		}
		stageArtifactGraphBundle(t, hs, ls, res.BundleID)
		if _, err := hs.ImportNext(); err != nil {
			t.Fatalf("import graph tag %s: %v", tag, err)
		}
	}
	if got := f.requestCount(sharedPath); got != 1 {
		t.Fatalf("shared config fetched %d times across dry run and two collects, want once", got)
	}
	assertArtifactGraphBody(t, hs, "manifests/2.0", f.manifests[f.root.Digest])
	assertArtifactGraphBody(t, hs, "manifests/"+first.Digest, f.manifests[first.Digest])
	assertArtifactGraphBody(t, hs, "blobs/"+containerSHA(sharedConfig), sharedConfig)
}

func TestContainerArtifactGraphMissingChildRejectsParent(t *testing.T) {
	f := newArtifactGraphRegistry()
	child := f.addArtifact(t, nil, []byte("complete config"), []byte("complete child payload"))
	missing := ociDescriptor{MediaType: mtOCIManifest, Digest: containerSHA([]byte("missing child")), Size: 13}
	index := f.addIndex(t, &f.root, child, missing)
	hs, _, progress := collectAndImportArtifactGraph(t, f)
	assertArtifactGraphReferrers(t, hs, f.root)
	for _, desc := range []ociDescriptor{index, child} {
		if response := artifactGraphRequest(hs, "manifests/"+desc.Digest); response.Code != http.StatusNotFound {
			t.Fatalf("incomplete graph published %s: status %d", desc.Digest, response.Code)
		}
	}
	if !strings.Contains(strings.Join(progress, "\n"), "⚠") {
		t.Fatalf("incomplete graph omitted without warning: %v", progress)
	}
}

func TestContainerArtifactGraphRequiredChildrenCap(t *testing.T) {
	f := newArtifactGraphRegistry()
	children := []ociDescriptor{}
	for i := 0; i < containerMaxImageArtifacts; i++ {
		children = append(children, f.addArtifact(t, nil, []byte("shared config"), []byte(fmt.Sprintf("child-%d", i))))
	}
	index := f.addIndex(t, &f.root, children...)
	hs, _, progress := collectAndImportArtifactGraph(t, f)
	assertArtifactGraphReferrers(t, hs, f.root)
	if response := artifactGraphRequest(hs, "manifests/"+index.Digest); response.Code != http.StatusNotFound {
		t.Fatalf("artifact graph exceeding the node cap was published: status %d", response.Code)
	}
	if !strings.Contains(strings.Join(progress, "\n"), "⚠") {
		t.Fatalf("capped graph omitted without warning: %v", progress)
	}
}

func TestContainerArtifactGraphNestedDiscoveryIsBounded(t *testing.T) {
	f := newArtifactGraphRegistry()
	subject := f.root
	chain := []ociDescriptor{}
	for i := 0; i < containerMaxImageArtifacts+5; i++ {
		subject = f.addArtifact(t, &subject, []byte("shared chain config"), []byte(fmt.Sprintf("chain-%d", i)))
		chain = append(chain, subject)
	}
	hs, manifest, progress := collectAndImportArtifactGraph(t, f)
	artifacts := manifest.Containers.Repos[0].Images[0].Artifacts
	if len(artifacts) == 0 || len(artifacts) > containerMaxImageArtifacts {
		t.Fatalf("bounded graph collected %d artifacts", len(artifacts))
	}
	assertArtifactGraphReferrers(t, hs, f.root, chain[0])
	if response := artifactGraphRequest(hs, "manifests/"+chain[len(chain)-1].Digest); response.Code != http.StatusNotFound {
		t.Fatalf("nested graph exceeded collection cap: status %d", response.Code)
	}
	if !strings.Contains(strings.Join(progress, "\n"), "⚠") {
		t.Fatalf("truncated graph omitted without warning: %v", progress)
	}
}

func TestContainerArtifactGraphRepeatedAndBackEdgeDescriptors(t *testing.T) {
	f := newArtifactGraphRegistry()
	attachment := f.addArtifact(t, &f.root, []byte("config"), []byte("attachment"))
	for range 10 {
		f.referrers[f.root.Digest] = append(f.referrers[f.root.Digest], attachment)
	}
	// A mutable discovery response can contain cycles even though immutable
	// manifest subjects cannot construct a content-addressed cycle.
	f.referrers[attachment.Digest] = []ociDescriptor{attachment, f.root}
	hs, _, _ := collectAndImportArtifactGraph(t, f)
	assertArtifactGraphReferrers(t, hs, f.root, attachment)
	assertArtifactGraphReferrers(t, hs, attachment)
	if got := f.requestCount("manifests/" + attachment.Digest); got != 1 {
		t.Fatalf("repeated/back-edge artifact fetched %d times, want once", got)
	}
	if got := f.requestCount("referrers/" + attachment.Digest); got != 1 {
		t.Fatalf("nested discovery queried %d times, want once", got)
	}
}
