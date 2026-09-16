package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func discoveryResultStatus(t *testing.T, result ExportResult) ContainerDiscoveryStatus {
	t.Helper()
	if len(result.ContainerDiscovery) != 1 || result.ContainerDiscovery[0].Discovery == nil {
		t.Fatalf("collect omitted structured discovery: %+v", result)
	}
	return *result.ContainerDiscovery[0].Discovery
}

func TestContainerDiscoveryStatusTransitions(t *testing.T) {
	f := newArtifactGraphRegistry()
	attachment := f.addArtifact(t, &f.root, []byte("status config"), []byte("status payload"))
	var unavailable atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() && strings.Contains(r.URL.Path, "/referrers/") {
			http.Error(w, "https://user:secret@example.invalid/private?token=secret", http.StatusUnauthorized)
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	ls, priv := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	collect := func() ExportResult {
		t.Helper()
		result, err := ls.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"graph:1.0"}})
		if err != nil {
			t.Fatal(err)
		}
		if !result.Skipped {
			stageArtifactGraphBundle(t, hs, ls, result.BundleID)
			if _, err := hs.ImportNext(); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	first := collect()
	complete := discoveryResultStatus(t, first)
	if complete.State != containerDiscoveryComplete || complete.Artifacts != 1 || complete.Subjects != 2 || complete.LastSuccessAt != complete.CheckedAt {
		t.Fatalf("initial coverage: %+v", complete)
	}
	repeated := collect()
	if !repeated.Skipped {
		t.Fatal("timestamp-only refresh defeated export dedup")
	}
	lastSuccess := discoveryResultStatus(t, repeated).LastSuccessAt
	unavailable.Store(true)
	partial := collect()
	status := discoveryResultStatus(t, partial)
	if partial.Skipped || status.State != containerDiscoveryIncomplete || status.LastSuccessAt != lastSuccess || status.Artifacts != 0 {
		t.Fatalf("failed discovery must export a partial observation retaining last success: %+v", partial)
	}
	assertArtifactGraphReferrers(t, hs, f.root, attachment)
	repo, err := hs.loadContainerRepoIndex("docker.io/library/graph")
	if err != nil || len(repo.Images) != 1 || containerImageDiscovery(repo.Images[0]).State != containerDiscoveryIncomplete {
		t.Fatalf("signed high-side status = %+v, %v", repo, err)
	}
	if err := ls.Close(); err != nil {
		t.Fatal(err)
	}
	ls, err = NewLowServer(ls.cfg, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })
	ls.containerRegistryBases = map[string]string{"docker.io": upstream.URL}
	records, err := ls.containerDiscoveryRecords()
	if err != nil || len(records) != 1 || records[0].Discovery.State != containerDiscoveryIncomplete || records[0].Discovery.LastSuccessAt != lastSuccess {
		t.Fatalf("discovery did not survive restart: %+v, %v", records, err)
	}
	response := httptest.NewRecorder()
	ls.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/containers/discovery", nil))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "https:") {
		t.Fatalf("unsafe or unavailable durable status API: %d %s", response.Code, response.Body.String())
	}
	unavailable.Store(false)
	recovered := discoveryResultStatus(t, collect())
	if recovered.State != containerDiscoveryComplete || recovered.LastSuccessAt != recovered.CheckedAt || len(recovered.Issues) != 0 {
		t.Fatalf("recovery failed to clear partial status: %+v", recovered)
	}
	oldDigest := f.root.Digest
	f.root = f.addArtifact(t, nil, []byte("new tag config"), []byte("new tag payload"))
	unavailable.Store(true)
	moved := discoveryResultStatus(t, collect())
	if moved.State != containerDiscoveryIncomplete || moved.LastSuccessAt != "" {
		t.Fatalf("new digest inherited another digest's success: %+v", moved)
	}
	records, err = ls.containerDiscoveryRecords()
	if err != nil || len(records) != 2 {
		t.Fatalf("moved tag records: %+v, %v", records, err)
	}
	for _, record := range records {
		if (record.Digest == oldDigest && len(record.Tags) != 0) || (record.Digest == f.root.Digest && !slices.Equal(record.Tags, []string{"1.0"})) {
			t.Fatalf("stale tag association: %+v", record)
		}
	}
}

func TestContainerDiscoveryMixedPinnedAndMovedTag(t *testing.T) {
	for _, pinnedFirst := range []bool{true, false} {
		name := "moved tag first"
		if pinnedFirst {
			name = "digest pin first"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newArtifactGraphRegistry()
			oldDigest := fixture.root.Digest
			upstream := httptest.NewServer(fixture)
			t.Cleanup(upstream.Close)
			low, _ := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
			if _, err := low.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"graph:1.0"}}); err != nil {
				t.Fatal(err)
			}
			fixture.root = fixture.addArtifact(t, nil, []byte("moved config"), []byte("moved payload"))
			refs := []string{"graph:1.0", "graph@" + oldDigest}
			if pinnedFirst {
				slices.Reverse(refs)
			}
			result, err := low.CollectContainers(t.Context(), ContainerCollectRequest{Images: refs})
			if err != nil {
				t.Fatal(err)
			}
			durable, err := low.containerDiscoveryRecords()
			if err != nil {
				t.Fatal(err)
			}
			for _, records := range [][]ContainerDiscoveryRecord{result.ContainerDiscovery, durable} {
				if len(records) != 2 {
					t.Fatalf("mixed batch discovery records = %+v", records)
				}
				for _, record := range records {
					want := []string{}
					if record.Digest == fixture.root.Digest {
						want = []string{"1.0"}
					}
					if !slices.Equal(record.Tags, want) {
						t.Fatalf("mixed batch digest %s tags = %q, want %q", record.Digest, record.Tags, want)
					}
				}
			}
		})
	}
}

func TestContainerDiscoveryFailureCodes(t *testing.T) {
	for _, code := range []string{"referrers_api", "referrers_fallback", "legacy_fetch", "artifact_fetch", "artifact_invalid", "graph_fetch", "blob_fetch", "graph_limit"} {
		t.Run(code, func(t *testing.T) {
			f := newArtifactGraphRegistry()
			attachment := f.addArtifact(t, &f.root, []byte("issue config"), []byte("issue content"))
			if code == "artifact_fetch" {
				delete(f.manifests, attachment.Digest)
			}
			if code == "artifact_invalid" {
				invalid := f.addArtifact(t, nil, []byte("invalid config"), []byte("no subject"))
				f.referrers[f.root.Digest] = []ociDescriptor{invalid}
			}
			wantCode := code
			if code == "graph_fetch" {
				child := f.addArtifact(t, nil, []byte("missing child config"), []byte("missing child payload"))
				f.addIndex(t, &f.root, child)
				delete(f.manifests, child.Digest)
				wantCode = "artifact_fetch"
			}
			if code == "blob_fetch" {
				delete(f.blobs, containerSHA([]byte("issue content")))
				wantCode = "artifact_fetch"
			}
			if code == "graph_limit" {
				child := f.addArtifact(t, nil, []byte("deep config"), []byte("deep payload"))
				for range containerMaxArtifactDepth + 1 {
					child = f.addIndex(t, nil, child)
				}
				f.addIndex(t, &f.root, child)
				wantCode = "discovery_limit"
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if discoveryFailureResponse(w, r, code) {
					return
				}
				f.ServeHTTP(w, r)
			}))
			t.Cleanup(upstream.Close)
			ls, _ := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
			result, err := ls.CollectContainers(t.Context(), ContainerCollectRequest{Images: []string{"graph:1.0"}})
			if err != nil {
				t.Fatal(err)
			}
			status := discoveryResultStatus(t, result)
			if status.State != containerDiscoveryIncomplete || !slices.ContainsFunc(status.Issues, func(issue ContainerDiscoveryIssue) bool { return issue.Code == wantCode }) {
				t.Fatalf("missing %s issue: %+v", wantCode, status)
			}
		})
	}
}

func discoveryFailureResponse(w http.ResponseWriter, r *http.Request, code string) bool {
	switch {
	case code == "referrers_api" && strings.Contains(r.URL.Path, "/referrers/"):
		http.Error(w, "denied", http.StatusUnauthorized)
	case code == "referrers_fallback" && strings.Contains(r.URL.Path, "/referrers/"):
		http.NotFound(w, r)
	case code == "referrers_fallback" && strings.Contains(r.URL.Path, "/manifests/sha256-") && !strings.Contains(r.URL.Path, "."):
		http.Error(w, "denied", http.StatusUnauthorized)
	case code == "legacy_fetch" && strings.HasSuffix(r.URL.Path, ".sig"):
		http.Error(w, "denied", http.StatusUnauthorized)
	default:
		return false
	}
	return true
}

func TestContainerDiscoveryDryRunAndPersistenceFailure(t *testing.T) {
	f := newArtifactGraphRegistry()
	upstream := httptest.NewServer(f)
	t.Cleanup(upstream.Close)
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": upstream.URL})
	request := ContainerCollectRequest{Images: []string{"graph:1.0"}}
	dry, err := ls.CollectContainers(withDryRunCollect(t.Context()), request)
	if err != nil {
		t.Fatal(err)
	}
	status := discoveryResultStatus(t, dry)
	if status.State != containerDiscoveryUnknown || status.LastSuccessAt != "" {
		t.Fatalf("dry run claimed verified discovery: %+v", status)
	}
	if _, err := os.Stat(ls.containerDiscoveryPath()); !os.IsNotExist(err) {
		t.Fatalf("dry run persisted discovery: %v", err)
	}
	if _, err := ls.CollectContainers(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ls.containerDiscoveryPath())
	if err != nil {
		t.Fatal(err)
	}
	existingDry, err := ls.CollectContainers(withDryRunCollect(t.Context()), request)
	if err != nil {
		t.Fatal(err)
	}
	if existingDry.Estimate == nil || existingDry.Estimate.Bundles != 0 {
		t.Fatalf("dry run discovery status defeated dedup estimate: %+v", existingDry)
	}
	after, _ := os.ReadFile(ls.containerDiscoveryPath())
	if string(before) != string(after) {
		t.Fatal("dry run overwrote existing durable discovery")
	}
	if err := os.WriteFile(ls.containerDiscoveryPath(), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ls.CollectContainers(t.Context(), request); err == nil || !strings.Contains(err.Error(), "discovery status") {
		t.Fatalf("corrupt snapshot was silently overwritten: %v", err)
	}
	response := httptest.NewRecorder()
	ls.handleContainerDiscovery(response, httptest.NewRequest(http.MethodGet, "/admin/containers/discovery", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt snapshot API status = %d", response.Code)
	}
}

func TestContainerDiscoveryBoundsAndValidation(t *testing.T) {
	ctx, tracker := withContainerDiscovery(t.Context())
	for i := range 24 {
		noteContainerDiscoveryIssue(ctx, "artifact_fetch", containerSHA([]byte{byte(i)}))
	}
	noteContainerDiscoveryIssue(ctx, "legacy_fetch", "https://user:secret@example.invalid/?token=secret")
	status := tracker.finish(ctx, ContainerImage{})
	if len(status.Issues) != containerDiscoveryMaxIssues || status.IssuesDropped != 9 {
		t.Fatalf("issues unbounded: %+v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil || strings.Contains(string(encoded), "secret") {
		t.Fatalf("unsafe encoded status: %s, %v", encoded, err)
	}
	if err := validateContainerDiscovery(status); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ContainerDiscoveryStatus)
	}{
		{name: "unknown state", mutate: func(s *ContainerDiscoveryStatus) { s.State = "trusted" }},
		{name: "URL issue", mutate: func(s *ContainerDiscoveryStatus) { s.Issues[0].Subject = "https://secret.invalid/" }},
		{name: "arbitrary code", mutate: func(s *ContainerDiscoveryStatus) { s.Issues[0].Code = "https://secret.invalid/" }},
		{name: "excess issues", mutate: func(s *ContainerDiscoveryStatus) { s.Issues = append(s.Issues, s.Issues[0]) }},
		{name: "negative count", mutate: func(s *ContainerDiscoveryStatus) { s.Artifacts = -1 }},
		{name: "excess subjects", mutate: func(s *ContainerDiscoveryStatus) { s.Subjects = 1000000 }},
		{name: "bad timestamp", mutate: func(s *ContainerDiscoveryStatus) { s.CheckedAt = "https://secret.invalid/" }},
		{name: "inconsistent complete", mutate: func(s *ContainerDiscoveryStatus) { s.State = containerDiscoveryComplete }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := *status
			invalid.Issues = slices.Clone(status.Issues)
			tc.mutate(&invalid)
			if err := validateContainerImage(ContainerImage{Discovery: &invalid}, nil, nil); err == nil || !strings.Contains(err.Error(), "discovery") {
				t.Fatalf("bundle accepted unsafe discovery metadata: %v", err)
			}
		})
	}
	if got := containerImageDiscovery(ContainerImage{}); got.State != containerDiscoveryUnknown {
		t.Fatalf("legacy metadata claimed discovery: %+v", got)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got := tracker.finish(canceled, ContainerImage{}); got.State != containerDiscoveryIncomplete {
		t.Fatalf("canceled discovery claimed complete: %+v", got)
	}
	limitContext, limitTracker := withContainerDiscovery(t.Context())
	collector := &artifactCollector{attempts: containerMaxArtifactFetches}
	if !collector.capReached(limitContext) || limitTracker.finish(limitContext, ContainerImage{}).Issues[0].Code != "discovery_limit" {
		t.Fatal("artifact traversal cap was not reported")
	}
}
