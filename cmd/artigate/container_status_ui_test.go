package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestContainerDiscoveryDetailLegacyAndIncomplete(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	img := artifactStoreStageImage(t, hs, makeFakeImage("discovery-detail"), "latest")
	artifactStoreMerge(t, hs, img)
	detail, err := hs.containerDetail(artifactStoreRepo + "@latest")
	if err != nil {
		t.Fatal(err)
	}
	if detail.ContainerDiscovery == nil || detail.ContainerDiscovery.State != "unknown" {
		t.Fatalf("legacy image implies successful discovery: %+v", detail.ContainerDiscovery)
	}
	img.Discovery = &ContainerDiscoveryStatus{
		State: "incomplete", CheckedAt: "2026-09-16T20:00:00Z", LastSuccessAt: "2026-09-15T20:00:00Z", Artifacts: 2, Subjects: 3,
		Issues: []ContainerDiscoveryIssue{{Code: "artifact_fetch", Subject: img.Digest}}, IssuesDropped: 1,
	}
	artifactStoreMerge(t, hs, img)
	detail, err = hs.containerDetail(artifactStoreRepo + "@latest")
	if err != nil {
		t.Fatal(err)
	}
	if detail.ContainerDiscovery.State != "incomplete" || detail.ContainerDiscovery.LastSuccessAt != img.Discovery.LastSuccessAt {
		t.Fatalf("detail lost structured discovery: %+v", detail.ContainerDiscovery)
	}
	fields := make(map[string]string)
	for _, field := range detail.Fields {
		fields[field.Label] = field.Value
	}
	if !strings.Contains(fields["Attachment discovery"], "Incomplete") || fields["Artifacts collected in this observation"] != "2" ||
		!strings.Contains(fields["Discovery issue"], "could not be downloaded") || fields["Additional discovery issues"] != "1" {
		t.Fatalf("discovery detail missing actionable fields: %v", fields)
	}
}

func TestContainerDiscoveryMetricsAndAPIUseDurableStatus(t *testing.T) {
	ls, _ := newContainerLowServer(t, nil)
	status := &ContainerDiscoveryStatus{
		State: "incomplete", CheckedAt: "2026-09-16T20:00:00Z", LastSuccessAt: "2026-09-15T20:00:00Z", Artifacts: 2, Subjects: 1,
		Issues: []ContainerDiscoveryIssue{{Code: "legacy_fetch"}},
	}
	repos := []ContainerRepo{{Registry: "docker.io", Repository: "library/example", Images: []ContainerImage{{Tag: "latest", Digest: containerSHA([]byte("metrics")), Discovery: status}}}}
	if _, err := ls.updateContainerDiscovery(t.Context(), repos); err != nil {
		t.Fatal(err)
	}
	api := doLowReq(t, ls, http.MethodGet, "/admin/containers/discovery", "")
	var reply struct {
		Records []ContainerDiscoveryRecord `json:"records"`
	}
	if err := json.Unmarshal(api.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if api.Code != http.StatusOK || len(reply.Records) != 1 || reply.Records[0].Discovery.State != "incomplete" {
		t.Fatalf("discovery API: %d %s", api.Code, api.Body.String())
	}
	metrics := doLowReq(t, ls, http.MethodGet, "/metrics", "")
	for _, want := range []string{
		`artigate_low_container_discovery_status_read_error 0`,
		`artigate_low_container_discovery_records{state="incomplete"} 1`,
		`artigate_low_container_discovery_records{state="complete"} 0`,
		`artigate_low_container_discovery_artifacts{state="incomplete"} 2`,
		`artigate_low_container_discovery_issues{code="legacy_fetch"} 1`,
	} {
		if !strings.Contains(metrics.Body.String(), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	if strings.Contains(metrics.Body.String(), "library/example") || strings.Contains(metrics.Body.String(), repos[0].Images[0].Digest) {
		t.Fatal("unbounded repository/digest labels in discovery metrics")
	}
	if err := os.WriteFile(ls.containerDiscoveryPath(), []byte(`{"invalid"`), 0o600); err != nil {
		t.Fatal(err)
	}
	api = doLowReq(t, ls, http.MethodGet, "/admin/containers/discovery", "")
	metrics = doLowReq(t, ls, http.MethodGet, "/metrics", "")
	if api.Code != http.StatusInternalServerError || !strings.Contains(metrics.Body.String(), "artigate_low_container_discovery_status_read_error 1") {
		t.Fatal("unreadable discovery status was presented as healthy")
	}
}
