package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func integrityFixture(t *testing.T) (*HighServer, fakeImage, fakeArtifact) {
	t.Helper()
	hs := newTestHighServer(t, nil)
	image := makeFakeImage("integrity-image")
	img := artifactStoreStageImage(t, hs, image, "latest")
	covR2WriteFile(t, hs.containerBlobPath(containerSHA(image.index)), image.index)
	img.Index = &ContainerIndex{Digest: containerSHA(image.index), MediaType: mtDockerList, Size: int64(len(image.index))}
	artifact := artifactStoreWithSubject(t,
		makeFakeArtifact("application/example", "integrity-payload", "application/example", map[string]string{"title": "original"}),
		ociDescriptor{Digest: image.manifestDigest, MediaType: mtDockerManifest, Size: int64(len(image.manifest))})
	img.Artifacts = []ContainerArtifact{artifactStoreStageArtifact(t, hs, artifact, image.manifestDigest, "attachment")}
	artifactStoreMerge(t, hs, img)
	return hs, image, artifact
}

func integrityReadIndex(t *testing.T, hs *HighServer) (containerRepoFile, []byte) {
	t.Helper()
	body, err := os.ReadFile(hs.containerRepoIndexPath(artifactStoreRepo))
	if err != nil {
		t.Fatal(err)
	}
	var stored containerRepoFile
	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatal(err)
	}
	return stored, body
}

func integrityWriteIndex(t *testing.T, hs *HighServer, stored containerRepoFile) {
	t.Helper()
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), stored, 0o644); err != nil {
		t.Fatal(err)
	}
}

func integrityCheck(t *testing.T, hs *HighServer, repair bool) containerIntegrityReport {
	t.Helper()
	report, err := checkContainerIntegrity(t.Context(), containerIntegrityOptions{Root: hs.cfg.Root, Repair: repair})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestContainerIntegrityReportOnly(t *testing.T) {
	hs, image, _ := integrityFixture(t)
	_, before := integrityReadIndex(t, hs)
	report := integrityCheck(t, hs, false)
	if !report.OK || report.BlobsChecked != 7 || len(report.Repositories) != 1 || report.Repaired != 0 {
		t.Fatalf("check = %+v", report)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(before, after) {
		t.Fatal("report-only check changed the repository index")
	}
	// This fixture's original index advertises an unmirrored arm64 sibling.
	// Only the selected image and collected attachment graph are required.
	if _, err := os.Stat(hs.containerBlobPath("sha256:" + strings.Repeat("0", 64))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unmirrored platform unexpectedly exists: %v (%s)", err, image.manifestDigest)
	}
}

func TestContainerIntegrityRejectsCorruptInputs(t *testing.T) {
	for _, mode := range []string{"missing blob", "corrupt blob", "wrong size", "unauthorized blob", "invalid digest", "missing tag map", "missing artifact map"} {
		t.Run(mode, func(t *testing.T) {
			hs, image, artifact := integrityFixture(t)
			stored, _ := integrityReadIndex(t, hs)
			switch mode {
			case "missing blob":
				if err := os.Remove(hs.containerBlobPath(containerSHA(artifact.layer))); err != nil {
					t.Fatal(err)
				}
			case "corrupt blob":
				writeFile(t, hs.containerBlobPath(containerSHA(image.layer)), []byte("corrupted"))
			case "wrong size":
				stored.Images[0].Blobs[0].Size++
			case "unauthorized blob":
				stored.Images[0].Artifacts[0].Blobs = stored.Images[0].Artifacts[0].Blobs[:1]
				record := stored.ArtifactIndex.Artifacts[artifact.digest]
				record.Blobs = record.Blobs[:1]
				stored.ArtifactIndex.Artifacts[artifact.digest] = record
			case "invalid digest":
				stored.Images[0].Digest = "../../outside"
			case "missing tag map":
				stored.ArtifactIndex.Tags = nil
			case "missing artifact map":
				stored.ArtifactIndex.Artifacts = nil
			}
			integrityWriteIndex(t, hs, stored)
			_, before := integrityReadIndex(t, hs)
			report := integrityCheck(t, hs, true)
			if report.OK || report.Repaired != 0 || len(report.Repositories[0].Issues) == 0 {
				t.Fatalf("corrupt input accepted: %+v", report)
			}
			_, after := integrityReadIndex(t, hs)
			if !bytes.Equal(before, after) {
				t.Fatal("failed repair changed the index")
			}
		})
	}
}

func TestContainerIntegrityRepairPreservesMetadata(t *testing.T) {
	hs, image, artifact := integrityFixture(t)
	stored, _ := integrityReadIndex(t, hs)
	record := stored.ArtifactIndex.Artifacts[artifact.digest]
	record.Subject = containerSHA([]byte("fabricated-subject"))
	record.ArtifactType = "application/wrong"
	record.Annotations = map[string]string{"title": "wrong"}
	stored.ArtifactIndex.Artifacts[artifact.digest] = record
	integrityWriteIndex(t, hs, stored)
	_, before := integrityReadIndex(t, hs)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(before, &fields); err != nil {
		t.Fatal(err)
	}
	fields["future_metadata"] = json.RawMessage(`{"enabled":true,"label":"keep"}`)
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), fields, 0o644); err != nil {
		t.Fatal(err)
	}
	if report := integrityCheck(t, hs, false); report.OK || report.Repositories[0].Issues[0].Code != "index_inconsistent" {
		t.Fatalf("metadata inconsistency was not reported: %+v", report)
	}
	if report := integrityCheck(t, hs, true); !report.OK || report.Repaired != 1 {
		t.Fatalf("repair failed: %+v", report)
	}
	after, body := integrityReadIndex(t, hs)
	repaired := after.ArtifactIndex.Artifacts[artifact.digest]
	if repaired.Subject != image.manifestDigest || repaired.ArtifactType != "application/example" || repaired.Annotations["title"] != "original" {
		t.Fatalf("repair did not derive native metadata: %+v", repaired)
	}
	var afterFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &afterFields); err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(afterFields["future_metadata"], &metadata); err != nil || metadata["label"] != "keep" {
		t.Fatalf("unknown repository metadata lost: %v, %v", metadata, err)
	}
	if !jsonEqual(fields["images"], afterFields["images"]) {
		t.Fatal("repair changed image metadata")
	}
	if report := integrityCheck(t, hs, false); !report.OK || report.Repaired != 0 {
		t.Fatalf("repaired index is not clean: %+v", report)
	}
	matches, err := filepath.Glob(hs.containerRepoIndexPath(artifactStoreRepo) + ".repair-*")
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary repair files remain: %v (%v)", matches, err)
	}
}

func jsonEqual(a, b []byte) bool {
	var first, second any
	if json.Unmarshal(a, &first) != nil || json.Unmarshal(b, &second) != nil {
		return false
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	return bytes.Equal(left, right)
}

func TestContainerIntegrityRepairPreservesHistoryAndMovedAlias(t *testing.T) {
	hs, image, old := integrityFixture(t)
	newArtifact := artifactStoreWithSubject(t,
		makeFakeArtifact("application/example", "new-payload", "application/example", nil),
		ociDescriptor{Digest: image.manifestDigest, MediaType: mtDockerManifest, Size: int64(len(image.manifest))})
	img := artifactStoreStageImage(t, hs, image, "latest")
	img.Artifacts = []ContainerArtifact{artifactStoreStageArtifact(t, hs, newArtifact, image.manifestDigest, "attachment")}
	artifactStoreMerge(t, hs, img)
	stored, _ := integrityReadIndex(t, hs)
	stored.Images[0].Artifacts = img.Artifacts // Old digest now exists only in the repository index.
	record := stored.ArtifactIndex.Artifacts[old.digest]
	record.Subject = ""
	stored.ArtifactIndex.Artifacts[old.digest] = record
	integrityWriteIndex(t, hs, stored)
	if report := integrityCheck(t, hs, true); !report.OK || report.Repaired != 1 {
		t.Fatalf("history repair: %+v", report)
	}
	repaired, _ := integrityReadIndex(t, hs)
	if len(repaired.ArtifactIndex.Artifacts) != 2 || repaired.ArtifactIndex.Tags["attachment"] != newArtifact.digest {
		t.Fatalf("repair lost history or moved alias backwards: %+v", repaired.ArtifactIndex)
	}
	artifactStoreAssertBody(t, hs, "manifests/attachment", newArtifact.manifest)
	artifactStoreAssertBody(t, hs, "manifests/"+old.digest, old.manifest)
}

func TestContainerIntegrityLegacyRepair(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		name := "unambiguous"
		if ambiguous {
			name = "ambiguous"
		}
		t.Run(name, func(t *testing.T) {
			hs, image, _ := integrityFixture(t)
			stored, _ := integrityReadIndex(t, hs)
			stored.ArtifactIndex = nil
			if ambiguous {
				other := makeFakeArtifact("application/example", "other", "application/example", nil)
				stored.Images[0].Artifacts = append(stored.Images[0].Artifacts,
					artifactStoreStageArtifact(t, hs, other, image.manifestDigest, "attachment"))
			}
			integrityWriteIndex(t, hs, stored)
			_, before := integrityReadIndex(t, hs)
			if report := integrityCheck(t, hs, false); report.OK || report.Repaired != 0 {
				t.Fatalf("legacy check: %+v", report)
			}
			_, after := integrityReadIndex(t, hs)
			if !bytes.Equal(before, after) {
				t.Fatal("report-only check migrated legacy index")
			}
			report := integrityCheck(t, hs, true)
			if report.OK == ambiguous || (report.Repaired == 1) == ambiguous {
				t.Fatalf("legacy repair ambiguity=%t: %+v", ambiguous, report)
			}
			if ambiguous {
				_, after = integrityReadIndex(t, hs)
				if !bytes.Equal(before, after) {
					t.Fatal("ambiguous legacy tags changed")
				}
			}
		})
	}
}

func TestContainerIntegrityRequiredArtifactChildren(t *testing.T) {
	hs, image, leaf := integrityFixture(t)
	stored, _ := integrityReadIndex(t, hs)
	indexBody, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIIndex, "artifactType": "application/graph",
		"manifests": []ociDescriptor{{Digest: leaf.digest, MediaType: mtOCIManifest, Size: int64(len(leaf.manifest))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := containerSHA(indexBody)
	covR2WriteFile(t, hs.containerBlobPath(digest), indexBody)
	graph := ContainerArtifact{
		Digest: digest, MediaType: mtOCIIndex, Size: int64(len(indexBody)), Subject: image.manifestDigest,
		Manifests: []ContainerIndex{{Digest: leaf.digest, MediaType: mtOCIManifest, Size: int64(len(leaf.manifest))}},
	}
	img := stored.Images[0]
	img.Artifacts = append(img.Artifacts, graph)
	artifactStoreMerge(t, hs, img)
	if report := integrityCheck(t, hs, false); !report.OK {
		t.Fatalf("complete graph failed: %+v", report)
	}
	stored, _ = integrityReadIndex(t, hs)
	delete(stored.ArtifactIndex.Artifacts, leaf.digest)
	delete(stored.ArtifactIndex.Tags, "attachment")
	stored.Images[0].Artifacts = []ContainerArtifact{graph}
	integrityWriteIndex(t, hs, stored)
	_, before := integrityReadIndex(t, hs)
	if report := integrityCheck(t, hs, true); report.OK || report.Repaired != 0 {
		t.Fatalf("missing child authorization accepted: %+v", report)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(before, after) {
		t.Fatal("repair invented repository membership from shared blobs")
	}
}

func TestContainerIntegrityPathsAndCLI(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{name: "help", args: []string{"--help"}, code: 0},
		{name: "required root", code: 2},
		{name: "unknown flag", args: []string{"--unknown"}, code: 2},
		{name: "unexpected operand", args: []string{"--root", root, "extra"}, code: 2},
		{name: "empty root", args: []string{"--root", root, "--json"}, code: 0},
		{name: "nonexistent root", args: []string{"--root", filepath.Join(root, "missing")}, code: 1},
		{name: "missing repository", args: []string{"--root", root, "--repository", artifactStoreRepo}, code: 1},
		{name: "traversal", args: []string{"--root", root, "--repository", "../outside"}, code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runContainersCheck(tc.args, &stdout, &stderr); code != tc.code {
				t.Fatalf("exit=%d, want %d; out=%q err=%q", code, tc.code, stdout.String(), stderr.String())
			}
			if tc.name == "empty root" {
				var report containerIntegrityReport
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || !report.OK || len(report.Repositories) != 0 {
					t.Fatalf("empty check = %s (%v)", stdout.String(), err)
				}
			}
			if tc.name == "help" && !strings.Contains(stderr.String(), "stop the high side") {
				t.Fatal("help omits offline requirement")
			}
		})
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("CLI unexpectedly created directories: %v (%v)", entries, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := checkContainerIntegrity(ctx, containerIntegrityOptions{Root: root}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}

func TestContainerIntegrityRejectsEscapingSymlink(t *testing.T) {
	hs, image, _ := integrityFixture(t)
	blob := hs.containerBlobPath(containerSHA(image.layer))
	outside := filepath.Join(t.TempDir(), "outside")
	writeFile(t, outside, image.layer)
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, blob); err != nil {
		t.Fatal(err)
	}
	_, before := integrityReadIndex(t, hs)
	if report := integrityCheck(t, hs, true); report.OK || report.Repaired != 0 {
		t.Fatalf("outside symlink accepted: %+v", report)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(before, after) {
		t.Fatal("symlink failure changed index")
	}
}

func TestContainerIntegrityValidatesAllRepositoriesBeforeRepair(t *testing.T) {
	hs, _, _ := integrityFixture(t)
	stored, _ := integrityReadIndex(t, hs)
	stored.ArtifactIndex = nil
	integrityWriteIndex(t, hs, stored)
	_, before := integrityReadIndex(t, hs)
	stored.Repository = "library/broken"
	stored.Images[0].Blobs[0].Size++
	brokenPath := hs.containerRepoIndexPath("docker.io/library/broken")
	if err := writeJSONAtomic(brokenPath, stored, 0o644); err != nil {
		t.Fatal(err)
	}
	report := integrityCheck(t, hs, true)
	if report.OK || report.Repaired != 0 || len(report.Repositories) != 2 {
		t.Fatalf("cross-repository preflight failed: %+v", report)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(before, after) {
		t.Fatal("repair modified the first index before checking the corrupt second repository")
	}
	// An explicit repository selection checks and repairs only that repository.
	report, err := checkContainerIntegrity(t.Context(), containerIntegrityOptions{
		Root: hs.cfg.Root, Repository: artifactStoreRepo, Repair: true,
	})
	if err != nil || !report.OK || report.Repaired != 1 || len(report.Repositories) != 1 {
		t.Fatalf("selected repository repair: %+v (%v)", report, err)
	}
}

func TestContainerIntegrityCLIReportsFailureAsJSON(t *testing.T) {
	hs, image, _ := integrityFixture(t)
	if err := os.Remove(hs.containerBlobPath(image.manifestDigest)); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runContainersCheck([]string{"--root", hs.cfg.Root, "--json", "--repair"}, &stdout, &stderr)
	var report containerIntegrityReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("JSON report: %q (%v); stderr=%q", stdout.String(), err, stderr.String())
	}
	if code != 1 || report.OK || report.Repaired != 0 || len(report.Repositories[0].Issues) == 0 {
		t.Fatalf("corrupt CLI result: exit=%d report=%+v", code, report)
	}
}

func TestContainerIntegrityRejectsExtraImageBlobAuthorizations(t *testing.T) {
	for _, kind := range []string{"manifest", "index"} {
		t.Run(kind, func(t *testing.T) {
			hs, _, leaf := integrityFixture(t)
			if kind == "index" {
				integrityUseArtifactIndexRoot(t, hs, leaf)
			}
			if report := integrityCheck(t, hs, false); !report.OK {
				t.Fatalf("fixture is not clean: %+v", report)
			}
			payload := []byte("shared content that this manifest never referenced")
			digest := containerSHA(payload)
			covR2WriteFile(t, hs.containerBlobPath(digest), payload)
			stored, _ := integrityReadIndex(t, hs)
			stored.Images[0].Blobs = append(stored.Images[0].Blobs, ContainerBlob{Digest: digest, Size: int64(len(payload))})
			integrityWriteIndex(t, hs, stored)
			_, before := integrityReadIndex(t, hs)
			for _, repair := range []bool{false, true} {
				report := integrityCheck(t, hs, repair)
				if report.OK || report.Repaired != 0 || containerIntegrityCanRepair(report.Repositories) {
					t.Fatalf("extra image authorization accepted (repair=%t): %+v", repair, report)
				}
			}
			_, after := integrityReadIndex(t, hs)
			if !bytes.Equal(before, after) {
				t.Fatal("repair rewrote primary image authorization metadata")
			}
		})
	}
}

func integrityUseArtifactIndexRoot(t *testing.T, hs *HighServer, leaf fakeArtifact) {
	t.Helper()
	stored, _ := integrityReadIndex(t, hs)
	body, err := json.Marshal(ociReferrersIndex{
		SchemaVersion: 2, MediaType: mtOCIIndex,
		Manifests: []ociDescriptor{{Digest: leaf.digest, MediaType: mtOCIManifest, Size: int64(len(leaf.manifest))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := containerSHA(body)
	covR2WriteFile(t, hs.containerBlobPath(digest), body)
	graph := ContainerArtifact{
		Digest: digest, MediaType: mtOCIIndex, Size: int64(len(body)),
		Manifests: []ContainerIndex{{Digest: leaf.digest, MediaType: mtOCIManifest, Size: int64(len(leaf.manifest))}},
	}
	artifactStoreMerge(t, hs, ContainerImage{
		Tag: "latest", Digest: digest, MediaType: mtOCIIndex, Size: int64(len(body)),
		Artifacts: append(stored.Images[0].Artifacts, graph),
	})
}

func TestContainerIntegrityRefusesUnknownIndexMetadata(t *testing.T) {
	hs, _, artifact := integrityFixture(t)
	_, before := integrityReadIndex(t, hs)
	var fields map[string]any
	if err := json.Unmarshal(before, &fields); err != nil {
		t.Fatal(err)
	}
	index := fields["artifact_index"].(map[string]any)
	record := index["artifacts"].(map[string]any)[artifact.digest].(map[string]any)
	record["future_metadata"] = map[string]any{"must_survive": true}
	record["subject"] = containerSHA([]byte("wrong subject"))
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), fields, 0o644); err != nil {
		t.Fatal(err)
	}
	_, before = integrityReadIndex(t, hs)
	if report := integrityCheck(t, hs, true); report.OK || report.Repaired != 0 {
		t.Fatalf("unsupported metadata was accepted for destructive reconstruction: %+v", report)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(before, after) {
		t.Fatal("repair dropped unknown artifact metadata")
	}
}

func TestContainerIntegrityLargeRepositoryIndex(t *testing.T) {
	hs, _, _ := integrityFixture(t)
	_, body := integrityReadIndex(t, hs)
	name := hs.containerRepoIndexPath(artifactStoreRepo)
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Valid JSON formatting takes this repository beyond the old diagnostic-
	// only 64 MiB cap without allocating a second huge metadata fixture under
	// -race. The benchmark separately exercises actual attachment history.
	padding := bytes.Repeat([]byte(" "), 64<<10)
	for range 1025 {
		if _, err := file.Write(padding); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := file.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(name)
	if err != nil || before.Size() <= 64<<20 {
		t.Fatalf("large fixture: %v (%v)", before, err)
	}
	if report := integrityCheck(t, hs, false); !report.OK || report.Repaired != 0 {
		t.Fatalf("valid large repository rejected: %+v", report)
	}
	after, err := os.Stat(name)
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("report-only scan changed the index: %v (%v)", after, err)
	}
}

func TestContainerIntegrityStreamingJSONValidation(t *testing.T) {
	for _, mode := range []string{"second value", "trailing garbage", "truncated object", "malformed unknown field", "unknown index field"} {
		t.Run(mode, func(t *testing.T) {
			hs, _, _ := integrityFixture(t)
			_, before := integrityReadIndex(t, hs)
			body := bytes.TrimSpace(before)
			switch mode {
			case "second value":
				body = append(body, []byte(` {"extra":true}`)...)
			case "trailing garbage":
				body = append(body, []byte(" nonsense")...)
			case "truncated object":
				body = body[:len(body)-1]
			case "malformed unknown field":
				body = append(body[:len(body)-1], []byte(`,"unknown":{"items":[1,]}}`)...)
			case "unknown index field":
				body = bytes.Replace(body, []byte(`"artifact_index": {`), []byte(`"artifact_index": {"unsupported":true,`), 1)
			}
			name := hs.containerRepoIndexPath(artifactStoreRepo)
			if err := os.WriteFile(name, body, 0o644); err != nil {
				t.Fatal(err)
			}
			if report := integrityCheck(t, hs, true); report.OK || report.Repaired != 0 {
				t.Fatalf("invalid repository JSON accepted: %+v", report)
			}
			after, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatalf("failed scan changed repository: %v", err)
			}
		})
	}
}

type integrityCancelReader struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (r integrityCancelReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.cancel()
	return n, err
}

func TestContainerIntegrityStreamingCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader := integrityCancelReader{reader: strings.NewReader(strings.Repeat(" ", 4096) + `{}`), cancel: cancel}
	decoder := json.NewDecoder(containerIntegrityReader{ctx: ctx, reader: reader})
	var stored containerRepoFile
	_, err := decodeContainerIntegrityRepository(decoder, &stored, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("streaming read ignored cancellation: %v", err)
	}
}

func TestContainerIntegrityRepairDetectsChangedSource(t *testing.T) {
	hs, _, _ := integrityFixture(t)
	stored, _ := integrityReadIndex(t, hs)
	stored.ArtifactIndex = nil
	integrityWriteIndex(t, hs, stored)
	root, err := os.OpenRoot(hs.cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	checker := containerIntegrityChecker{root: root, verified: make(map[string]containerIntegrityBlob)}
	result, plan := checker.checkRepository(t.Context(), artifactStoreRepo, false)
	if len(result.Issues) != 1 || !containerIntegrityCanRepair([]containerIntegrityRepository{result}) {
		t.Fatalf("invalid repair fixture: %+v", result)
	}
	_, original := integrityReadIndex(t, hs)
	changed := bytes.Clone(original)
	changed = append(changed, '\n') // Even a formatting-only edit invalidates the snapshot.
	if err := os.WriteFile(hs.containerRepoIndexPath(artifactStoreRepo), changed, 0o644); err != nil {
		t.Fatal(err)
	}
	report := containerIntegrityReport{Repositories: []containerIntegrityRepository{result}}
	err = checker.applyRepairs(t.Context(), []containerIntegrityRepair{plan}, &report)
	if err == nil || !strings.Contains(err.Error(), "repository changed") || report.Repaired != 0 {
		t.Fatalf("changed source was not rejected: report=%+v err=%v", report, err)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(changed, after) {
		t.Fatal("repair overwrote the intervening source change")
	}
}

func TestContainerIntegrityRejectsDuplicateMembershipKeys(t *testing.T) {
	for _, mode := range []string{"repository identity", "repository artifact index", "artifact map", "artifact digest", "artifact alias"} {
		t.Run(mode, func(t *testing.T) {
			hs, _, artifact := integrityFixture(t)
			stored, before := integrityReadIndex(t, hs)
			body := bytes.TrimSpace(before)
			switch mode {
			case "repository identity":
				body = append(body[:len(body)-1], []byte(`,"registry":"docker.io"}`)...)
			case "repository artifact index":
				body = append(body[:len(body)-1], []byte(`,"artifact_index":null}`)...)
			case "artifact map":
				body = bytes.Replace(body, []byte(`"artifact_index": {`), []byte(`"artifact_index": {"artifacts":{},`), 1)
			case "artifact digest":
				record, err := json.Marshal(stored.ArtifactIndex.Artifacts[artifact.digest])
				if err != nil {
					t.Fatal(err)
				}
				prefix := []byte(`"artifacts": {`)
				duplicate := append([]byte(`"artifacts": {"`+artifact.digest+`":`), record...)
				duplicate = append(duplicate, ',')
				body = bytes.Replace(body, prefix, duplicate, 1)
			case "artifact alias":
				body = bytes.Replace(body, []byte(`"tags": {`), []byte(`"tags": {"attachment":"`+artifact.digest+`",`), 1)
			}
			if !json.Valid(body) {
				t.Fatal("duplicate-key fixture must otherwise be valid JSON")
			}
			name := hs.containerRepoIndexPath(artifactStoreRepo)
			if err := os.WriteFile(name, body, 0o644); err != nil {
				t.Fatal(err)
			}
			if report := integrityCheck(t, hs, true); report.OK || report.Repaired != 0 || containerIntegrityCanRepair(report.Repositories) {
				t.Fatalf("ambiguous membership accepted: %+v", report)
			}
			after, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatalf("repair rewrote ambiguous source metadata: %v", err)
			}
		})
	}
}

func TestContainerIntegrityRepairRechecksManifestBytes(t *testing.T) {
	hs, _, artifact := integrityFixture(t)
	stored, _ := integrityReadIndex(t, hs)
	stored.ArtifactIndex = nil
	integrityWriteIndex(t, hs, stored)
	root, err := os.OpenRoot(hs.cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	checker := containerIntegrityChecker{root: root, verified: make(map[string]containerIntegrityBlob)}
	result, plan := checker.checkRepository(t.Context(), artifactStoreRepo, false)
	if len(result.Issues) != 1 || !containerIntegrityCanRepair([]containerIntegrityRepository{result}) {
		t.Fatalf("invalid repair fixture: %+v", result)
	}
	_, before := integrityReadIndex(t, hs)
	// The file keeps its old size and still parses, but no longer hashes to
	// the recorded digest. An earlier cached hash must not authorize new bytes.
	changed := bytes.Replace(artifact.manifest, []byte("original"), []byte("modified"), 1)
	if err := os.WriteFile(hs.containerBlobPath(artifact.digest), changed, 0o644); err != nil {
		t.Fatal(err)
	}
	report := containerIntegrityReport{Repositories: []containerIntegrityRepository{result}}
	err = checker.applyRepairs(t.Context(), []containerIntegrityRepair{plan}, &report)
	if err == nil || report.Repaired != 0 {
		t.Fatalf("changed manifest bytes accepted for repair: report=%+v err=%v", report, err)
	}
	_, after := integrityReadIndex(t, hs)
	if !bytes.Equal(before, after) {
		t.Fatal("repair published metadata from a modified manifest")
	}
}

func TestContainerIntegrityPreservesUnknownLargeNumbers(t *testing.T) {
	hs, _, _ := integrityFixture(t)
	stored, _ := integrityReadIndex(t, hs)
	stored.ArtifactIndex = nil
	integrityWriteIndex(t, hs, stored)
	_, before := integrityReadIndex(t, hs)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(before, &fields); err != nil {
		t.Fatal(err)
	}
	fields["future_metadata"] = json.RawMessage(`{"large":1e1000,"nested":[-1e1000,true,null,{"other":1e999}]}`)
	if err := writeJSONAtomic(hs.containerRepoIndexPath(artifactStoreRepo), fields, 0o644); err != nil {
		t.Fatal(err)
	}
	if report := integrityCheck(t, hs, false); report.OK || !containerIntegrityCanRepair(report.Repositories) {
		t.Fatalf("unknown numbers were constrained during report-only scan: %+v", report)
	}
	if report := integrityCheck(t, hs, true); !report.OK || report.Repaired != 1 {
		t.Fatalf("unknown numbers were constrained during repair: %+v", report)
	}
	_, after := integrityReadIndex(t, hs)
	var afterFields map[string]json.RawMessage
	if err := json.Unmarshal(after, &afterFields); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, afterFields["future_metadata"]); err != nil || compact.String() != string(fields["future_metadata"]) {
		t.Fatalf("unknown numeric metadata changed: %s (%v)", compact.String(), err)
	}
}
