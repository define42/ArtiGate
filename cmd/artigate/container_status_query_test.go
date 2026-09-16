package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func discoveryQueryFixture(t *testing.T) (*LowServer, containerDiscoverySnapshot) {
	t.Helper()
	low := &LowServer{cfg: LowConfig{Root: t.TempDir()}}
	snapshot := containerDiscoverySnapshot{Version: 1, Records: make(map[string]ContainerDiscoveryRecord)}
	now := time.Now().UTC()
	for i := range 200 {
		record := ContainerDiscoveryRecord{
			Registry: "registry.example", Repository: "team/repo", Digest: fmt.Sprintf("sha256:%064x", i), Tags: []string{},
		}
		switch {
		case i < 120:
			checked := now.Add(-time.Hour).Format(time.RFC3339Nano)
			record.Tags = []string{fmt.Sprintf("release-%03d", i)}
			record.ReferenceTracking = true
			record.Discovery = &ContainerDiscoveryStatus{State: "complete", CheckedAt: checked, LastSuccessAt: checked}
		case i < 155:
			record.Pinned, record.ReferenceTracking = true, true
			record.Discovery = &ContainerDiscoveryStatus{State: "incomplete", CheckedAt: now.Add(-25 * time.Hour).Format(time.RFC3339Nano)}
		case i < 175:
			record.Repository, record.ReferenceTracking = "other/repo", true
		}
		key := record.Registry + "/" + record.Repository + "@" + record.Digest
		snapshot.Records[key] = record
	}
	writeDiscoveryQueryFixture(t, low, snapshot)
	return low, snapshot
}

func writeDiscoveryQueryFixture(t *testing.T, low *LowServer, snapshot containerDiscoverySnapshot) {
	t.Helper()
	if err := writeJSONAtomic(low.containerDiscoveryPath(), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
}

func discoveryQueryResponse(low *LowServer, query string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	low.handleContainerDiscovery(response, httptest.NewRequest(http.MethodGet, "/admin/containers/discovery?"+query, nil))
	return response
}

func readDiscoveryQueryPage(t *testing.T, low *LowServer, query string) containerDiscoveryPage {
	t.Helper()
	response := discoveryQueryResponse(low, query)
	if response.Code != http.StatusOK {
		t.Fatalf("discovery query %q: %d %s", query, response.Code, response.Body.String())
	}
	if response.Body.Len() > containerDiscoveryMaxResponseBytes {
		t.Fatalf("discovery page exceeds response limit: %d", response.Body.Len())
	}
	var page containerDiscoveryPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestContainerDiscoveryQueryPaginationAndFilters(t *testing.T) {
	low, _ := discoveryQueryFixture(t)
	first := readDiscoveryQueryPage(t, low, "")
	if len(first.Records) != 100 || first.Total != 200 || first.NextCursor == "" || first.StaleAfterSeconds != 86400 {
		t.Fatalf("default first page: %+v", first)
	}
	second := readDiscoveryQueryPage(t, low, url.Values{"cursor": {first.NextCursor}}.Encode())
	if len(second.Records) != 100 || second.Total != 200 || second.NextCursor != "" || second.AsOf != first.AsOf {
		t.Fatalf("second page metadata: %+v", second)
	}
	var identities []string
	for _, record := range append(first.Records, second.Records...) {
		identities = append(identities, record.Registry+"/"+record.Repository+"@"+record.Digest)
	}
	if !slices.IsSorted(identities) || len(slices.Compact(identities)) != 200 {
		t.Fatal("pagination duplicated, omitted, or reordered records")
	}
	for _, test := range []struct {
		query string
		want  int
	}{
		{"repository=registry.example/team/repo", 180},
		{"state=incomplete", 35},
		{"lifecycle=active", 155},
		{"lifecycle=historical", 20},
		{"lifecycle=unknown", 25},
		{"freshness=fresh", 120},
		{"freshness=stale", 35},
		{"freshness=unknown", 45},
		{"state=unknown", 45},
		{"repository=registry.example/team/repo&lifecycle=active&freshness=fresh&state=complete", 120},
		{"freshness=fresh&stale_after=168h", 155},
		{"repository=registry.example/missing&lifecycle=all", 0},
	} {
		t.Run(test.query, func(t *testing.T) {
			page := readDiscoveryQueryPage(t, low, test.query+"&limit=250")
			if page.Total != test.want || len(page.Records) != test.want || page.NextCursor != "" {
				t.Fatalf("filtered page: total=%d records=%d next=%q", page.Total, len(page.Records), page.NextCursor)
			}
		})
	}
}

func TestContainerDiscoveryQueryValidation(t *testing.T) {
	low, _ := discoveryQueryFixture(t)
	for _, query := range []string{
		"limit=0", "limit=251", "limit=-1", "limit=1.5", "limit=", "limit=1&limit=1",
		"state=all&state=complete", "lifecycle=active&lifecycle=active", "freshness=stale&freshness=stale",
		"repository=a/b&repository=a/b", "cursor=a&cursor=b", "stale_after=1h&stale_after=1h",
		"repository=repo", "repository=registry.example/../bad", "repository=https://registry.example/repo",
		"state=verified", "lifecycle=current", "freshness=future", "unexpected=value",
		"stale_after=0s", "stale_after=1.5s", "stale_after=8761h", "stale_after=-1h", "stale_after=nope",
		"cursor=not+base64", "cursor=" + strings.Repeat("a", containerDiscoveryMaxCursorBytes+1),
		"state=complete;limit=10", "state=%zz", "repository=" + strings.Repeat("a", 8193),
	} {
		t.Run(query[:min(len(query), 80)], func(t *testing.T) {
			if response := discoveryQueryResponse(low, query); response.Code != http.StatusBadRequest {
				t.Fatalf("invalid query returned %d: %s", response.Code, response.Body.String())
			}
		})
	}
	response := httptest.NewRecorder()
	low.handleContainerDiscovery(response, httptest.NewRequest(http.MethodPost, "/admin/containers/discovery", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", response.Code)
	}
}

func TestContainerDiscoveryCursorBindsQueryAndSnapshot(t *testing.T) {
	low, snapshot := discoveryQueryFixture(t)
	first := readDiscoveryQueryPage(t, low, "limit=10&lifecycle=active")
	for _, changed := range []string{"limit=11&lifecycle=active", "limit=10&lifecycle=historical", "limit=10&lifecycle=active&stale_after=1h"} {
		query := changed + "&cursor=" + url.QueryEscape(first.NextCursor)
		if response := discoveryQueryResponse(low, query); response.Code != http.StatusBadRequest {
			t.Fatalf("changed query accepted cursor: %d %s", response.Code, response.Body.String())
		}
	}
	query := "limit=10&lifecycle=active&cursor=" + url.QueryEscape(first.NextCursor)
	_ = readDiscoveryQueryPage(t, low, query)
	for key, record := range snapshot.Records {
		record.Tags = append(record.Tags, "new-observation")
		snapshot.Records[key] = record
		break
	}
	writeDiscoveryQueryFixture(t, low, snapshot)
	if response := discoveryQueryResponse(low, query); response.Code != http.StatusConflict {
		t.Fatalf("changed snapshot accepted cursor: %d %s", response.Code, response.Body.String())
	}
}

func TestContainerDiscoveryCursorKeepsFreshnessTime(t *testing.T) {
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	snapshot := containerDiscoverySnapshot{Version: 1, Records: make(map[string]ContainerDiscoveryRecord)}
	for i := range 2 {
		snapshot.Records[fmt.Sprint(i)] = ContainerDiscoveryRecord{Discovery: &ContainerDiscoveryStatus{
			State: "incomplete", CheckedAt: now.Add(-24*time.Hour + time.Second).Format(time.RFC3339Nano),
		}}
	}
	query, err := parseContainerDiscoveryQuery("limit=1&freshness=fresh")
	if err != nil {
		t.Fatal(err)
	}
	var first, second containerDiscoveryPage
	body, err := queryContainerDiscovery(snapshot, query, now)
	if err != nil || json.Unmarshal(body, &first) != nil {
		t.Fatalf("first page: %s, %v", body, err)
	}
	query.Cursor = first.NextCursor
	body, err = queryContainerDiscovery(snapshot, query, now.Add(48*time.Hour))
	if err != nil || json.Unmarshal(body, &second) != nil {
		t.Fatalf("second page: %s, %v", body, err)
	}
	if first.NextCursor == "" || first.AsOf != second.AsOf || len(second.Records) != 1 || second.Total != 2 || second.Records[0].Freshness != "fresh" {
		t.Fatalf("freshness changed between pages: first=%+v second=%+v", first, second)
	}
	if *first.Records[0].AgeSeconds != *second.Records[0].AgeSeconds {
		t.Fatal("age changed between pages")
	}
	for _, bad := range []string{"{}", `{"v":1} {}`, `{"unexpected":1}`, `{"offset":-1}`} {
		query.Cursor = base64.RawURLEncoding.EncodeToString([]byte(bad))
		if _, err := queryContainerDiscovery(snapshot, query, now); err == nil {
			t.Fatalf("accepted invalid cursor %s", bad)
		}
	}
}

func TestContainerDiscoveryFreshness(t *testing.T) {
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, checked, want string
		age                 int64
	}{
		{"missing", "", "unknown", -1},
		{"invalid", "yesterday", "unknown", -1},
		{"future", now.Add(time.Second).Format(time.RFC3339Nano), "unknown", -1},
		{"now", now.Format(time.RFC3339Nano), "fresh", 0},
		{"recent", now.Add(-time.Hour).Format(time.RFC3339Nano), "fresh", 3600},
		{"threshold", now.Add(-24 * time.Hour).Format(time.RFC3339Nano), "stale", 86400},
		{"ancient", "0001-01-01T00:00:00Z", "stale", now.Unix() - time.Time{}.Unix()},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := enrichContainerDiscoveryRecord(ContainerDiscoveryRecord{Discovery: &ContainerDiscoveryStatus{CheckedAt: test.checked}}, now, containerDiscoveryDefaultStaleAfter)
			if record.Freshness != test.want {
				t.Fatalf("freshness = %s, want %s", record.Freshness, test.want)
			}
			if test.age < 0 {
				if record.AgeSeconds != nil {
					t.Fatalf("unknown age = %d", *record.AgeSeconds)
				}
			} else if record.AgeSeconds == nil || *record.AgeSeconds != test.age {
				t.Fatalf("age = %v, want %d", record.AgeSeconds, test.age)
			}
		})
	}
}

func TestContainerDiscoveryQueryResponseByteLimit(t *testing.T) {
	low := &LowServer{cfg: LowConfig{Root: t.TempDir()}}
	snapshot := containerDiscoverySnapshot{Version: 1, Records: make(map[string]ContainerDiscoveryRecord)}
	for i := range 2 {
		record := ContainerDiscoveryRecord{Registry: "registry.example", Repository: "repo", Digest: fmt.Sprintf("sha256:%064x", i)}
		for j := range 6000 {
			record.Tags = append(record.Tags, fmt.Sprintf("%0120d%08d", i, j))
		}
		snapshot.Records[fmt.Sprint(i)] = record
	}
	writeDiscoveryQueryFixture(t, low, snapshot)
	first := readDiscoveryQueryPage(t, low, "limit=250")
	second := readDiscoveryQueryPage(t, low, "limit=250&cursor="+url.QueryEscape(first.NextCursor))
	if first.Total != 2 || len(first.Records) != 1 || first.NextCursor == "" || len(second.Records) != 1 || second.NextCursor != "" {
		t.Fatal("byte bound did not paginate large records")
	}
	record := snapshot.Records["0"]
	record.Tags = append(record.Tags, record.Tags...)
	snapshot.Records["0"] = record
	writeDiscoveryQueryFixture(t, low, snapshot)
	response := discoveryQueryResponse(low, "")
	if response.Code != http.StatusInternalServerError || response.Body.Len() > containerDiscoveryMaxResponseBytes {
		t.Fatalf("oversized individual record returned %d, %d bytes", response.Code, response.Body.Len())
	}
}

func TestContainerDiscoveryReferenceProvenance(t *testing.T) {
	low := &LowServer{cfg: LowConfig{Root: t.TempDir()}}
	legacy := ContainerDiscoveryRecord{Registry: "registry.example", Repository: "repo", Digest: fmt.Sprintf("sha256:%064x", 1), Tags: []string{}}
	tagged := legacy
	tagged.Digest, tagged.Tags = fmt.Sprintf("sha256:%064x", 2), []string{"latest"}
	key := func(record ContainerDiscoveryRecord) string {
		return record.Registry + "/" + record.Repository + "@" + record.Digest
	}
	snapshot := containerDiscoverySnapshot{Version: 1, Records: map[string]ContainerDiscoveryRecord{key(legacy): legacy, key(tagged): tagged}}
	writeDiscoveryQueryFixture(t, low, snapshot)
	newDigest := fmt.Sprintf("sha256:%064x", 3)
	if _, err := low.updateContainerDiscovery(t.Context(), []ContainerRepo{{Registry: legacy.Registry, Repository: legacy.Repository, Images: []ContainerImage{{Digest: newDigest, Tag: "latest"}}}}); err != nil {
		t.Fatal(err)
	}
	records, err := low.containerDiscoveryRecords()
	if err != nil || len(records) != 3 {
		t.Fatalf("reference records = %+v, %v", records, err)
	}
	if records[0].Lifecycle != "unknown" || records[1].Lifecycle != "historical" || records[2].Lifecycle != "active" {
		t.Fatalf("legacy and moved reference classification: %+v", records)
	}
	if _, err := low.updateContainerDiscovery(t.Context(), []ContainerRepo{{Registry: legacy.Registry, Repository: legacy.Repository, Images: []ContainerImage{{Digest: legacy.Digest}}}}); err != nil {
		t.Fatal(err)
	}
	records, err = low.containerDiscoveryRecords()
	if err != nil || !records[0].Pinned || !records[0].ReferenceTracking || records[0].Lifecycle != "active" {
		t.Fatalf("explicit digest pin did not survive reload: %+v, %v", records, err)
	}
	body, err := os.ReadFile(low.containerDiscoveryPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, derived := range []string{`"lifecycle"`, `"freshness"`, `"age_seconds"`} {
		if strings.Contains(string(body), derived) {
			t.Fatalf("persisted derived field %s", derived)
		}
	}
}
