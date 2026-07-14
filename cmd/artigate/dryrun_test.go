package main

// Dry-run collects (?dry_run=1): the estimate must mirror what a real collect
// would export — same dedup marking, same split plan — while writing nothing,
// consuming no sequence number, and recording nothing as forwarded. The
// metadata-driven collectors (apt, containers, ...) must additionally skip the
// artifact downloads themselves.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// dryExport drives exportIfNew under a dry-run context with a writer that must
// never run.
func dryExport(t *testing.T, ls *LowServer, stage string, files []ManifestFile, force bool) (ExportResult, error) {
	t.Helper()
	ctx := withDryRunCollect(context.Background())
	return ls.exportIfNew(ctx, streamNpm, stage, files, force, func(seq int64) (ExportResult, error) {
		t.Errorf("a dry run must never write a bundle (sequence %d allocated)", seq)
		return ExportResult{}, nil
	})
}

// assertNothingExported checks a dry run's core promise on a stream: no bundle
// artifacts on disk and no sequence number consumed.
func assertNothingExported(t *testing.T, ls *LowServer, stream string) {
	t.Helper()
	entries, err := os.ReadDir(ls.cfg.ExportDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("export dir not empty after dry run: %v", names)
	}
	if seq := ls.peekSequence(stream); seq != 1 {
		t.Errorf("next sequence = %d, want 1 (a dry run must not burn a number)", seq)
	}
}

// TestDryRunExportIfNew covers the choke point every ecosystem shares: the
// estimate's totals and new/prior split, that nothing is written, committed,
// or recorded, that force counts everything as new, that an all-prior dry run
// reports a would-skip, and that a real collect afterwards behaves exactly as
// if the dry runs never happened.
func TestDryRunExportIfNew(t *testing.T) {
	ls := newBareLowServer(t)
	stage := t.TempDir()
	a := stageTestFile(t, stage, "data/a.bin", "content-a")
	b := stageTestFile(t, stage, "data/b.bin", "content-b")
	c := stageTestFile(t, stage, "data/c.bin", "content-cc")
	ls.recordForwarded(streamNpm, []ManifestFile{a})

	res, err := dryExport(t, ls, stage, []ManifestFile{a, b, c}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Skipped || res.BundleID != "" || res.PriorFiles != 1 {
		t.Fatalf("dry run result = %+v, want DryRun with PriorFiles 1 and no bundle", res)
	}
	est := res.Estimate
	if est == nil {
		t.Fatal("dry run result carries no estimate")
	}
	if est.TotalFiles != 3 || est.TotalBytes != 28 || est.NewFiles != 2 || est.NewBytes != 19 || est.Bundles != 1 {
		t.Errorf("estimate = %+v, want 3 files/28 B total, 2 files/19 B new, 1 bundle", est)
	}
	wantArchive := int64(bundlePackBaseOverheadBytes) + estimatedPackedBytes(b.Size) + estimatedPackedBytes(c.Size)
	if est.EstimatedArchiveBytes != wantArchive {
		t.Errorf("estimated archive bytes = %d, want %d", est.EstimatedArchiveBytes, wantArchive)
	}
	if !strings.Contains(res.Message, "dry run") {
		t.Errorf("message %q should say it was a dry run", res.Message)
	}
	assertNothingExported(t, ls, streamNpm)
	if ok, err := ls.exported.IsForwarded(streamNpm, b.Path, b.SHA256); err != nil || ok {
		t.Errorf("dry run recorded %s as forwarded (ok=%v, err=%v)", b.Path, ok, err)
	}

	// force: dedup bypassed, everything counts as new.
	resF, err := dryExport(t, ls, stage, []ManifestFile{a, b, c}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !resF.DryRun || resF.Skipped || resF.PriorFiles != 0 || resF.Estimate.NewFiles != 3 || resF.Estimate.NewBytes != 28 {
		t.Fatalf("forced dry run = %+v (estimate %+v), want all 3 files new", resF, resF.Estimate)
	}
	assertNothingExported(t, ls, streamNpm)

	// The real collect right after is untouched by the dry runs: a is still the
	// only prior file and the bundle carries b and c.
	toExport := []ManifestFile{a, b, c}
	resR, err := ls.exportIfNew(context.Background(), streamNpm, stage, toExport, false, func(seq int64) (ExportResult, error) {
		id := bundleIDFor(streamNpm, seq)
		if err := ls.writeBundleArtifacts(context.Background(), id, stage, []byte("{}"), toExport); err != nil {
			return ExportResult{}, err
		}
		return ExportResult{Stream: streamNpm, Sequence: seq, BundleID: id}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if resR.DryRun || resR.Skipped || resR.Sequence != 1 || resR.PriorFiles != 1 {
		t.Fatalf("real export after dry runs = %+v, want sequence 1 with PriorFiles 1", resR)
	}
	if got := listArchiveEntries(t, ls.cfg.ExportDir, resR.BundleID); len(got) != 2 {
		t.Errorf("real archive = %v, want b and c", got)
	}

	// Everything forwarded now: the dry run reports a would-skip.
	resS, err := dryExport(t, ls, stage, []ManifestFile{a, b, c}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !resS.DryRun || !resS.Skipped || resS.PriorFiles != 3 || resS.Estimate.NewFiles != 0 || resS.Estimate.TotalFiles != 3 {
		t.Fatalf("all-prior dry run = %+v (estimate %+v), want a would-skip", resS, resS.Estimate)
	}
	if seq := ls.peekSequence(streamNpm); seq != 2 {
		t.Errorf("next sequence = %d, want 2 (only the real export may advance it)", seq)
	}
}

// TestDryRunSplitEstimate proves the estimate plans bundles with the real
// splitter: an oversized collect reports the part count and the summed
// archive bound, and a file no bundle can carry fails the dry run with the
// same error the real collect would hit.
func TestDryRunSplitEstimate(t *testing.T) {
	ls := newBareLowServer(t)
	ls.splitBudget = splitTestBudget
	stage := t.TempDir()
	files := stageSplitFiles(t, stage)

	res, err := dryExport(t, ls, stage, files, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Estimate.Bundles != 3 {
		t.Errorf("estimate bundles = %d, want 3 (five files, two per bundle)", res.Estimate.Bundles)
	}
	wantArchive := 3*int64(bundlePackBaseOverheadBytes) + 5*estimatedPackedBytes(100)
	if res.Estimate.EstimatedArchiveBytes != wantArchive {
		t.Errorf("estimated archive bytes = %d, want %d", res.Estimate.EstimatedArchiveBytes, wantArchive)
	}
	assertNothingExported(t, ls, streamNpm)

	big := stageTestFile(t, stage, "data/big.bin", strings.Repeat("x", int(splitTestBudget)))
	if _, err := dryExport(t, ls, stage, []ManifestFile{big}, false); err == nil || !strings.Contains(err.Error(), "does not fit a bundle") {
		t.Errorf("oversized dry run error = %v, want the transport-limit refusal", err)
	}
}

// TestUploadsDryRunHTTP drives ?dry_run=1 end to end through the HTTP surface
// and the job queue on the uploads stream (the one collector with no external
// tools): the buffered JSON answer carries the estimate, the job is labeled as
// a dry run and reports the estimate as its message, nothing is exported — and
// the same upload without the flag then exports for real.
func TestUploadsDryRunHTTP(t *testing.T) {
	ls, _ := newAptLowServer(t)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	upload := func(url string) ExportResult {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if err := mw.WriteField("folder", "tools"); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{"hello.txt": "hello world", "data.bin": "BYTES-1"} {
			fw, err := mw.CreateFormFile("file", name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(fw, content); err != nil {
				t.Fatal(err)
			}
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(url, mw.FormDataContentType(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("upload status = %d: %s", resp.StatusCode, body)
		}
		var res ExportResult
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("parse result: %v: %s", err, body)
		}
		return res
	}

	res := upload(srv.URL + "/admin/uploads/collect?dry_run=1")
	if !res.DryRun || res.Skipped || res.BundleID != "" || res.Estimate == nil {
		t.Fatalf("dry-run upload result = %+v, want a dry-run estimate and no bundle", res)
	}
	if est := res.Estimate; est.NewFiles != 2 || est.NewBytes != int64(len("hello world")+len("BYTES-1")) || est.Bundles != 1 {
		t.Errorf("estimate = %+v, want 2 new files with both files' bytes", est)
	}
	assertNothingExported(t, ls, streamUploads)

	// The job queue shows the run for what it was: labeled a dry run, its
	// message the estimate.
	jobsResp, err := http.Get(srv.URL + "/admin/jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer jobsResp.Body.Close()
	var jobs JobListResponse
	if err := json.NewDecoder(jobsResp.Body).Decode(&jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Jobs) != 1 {
		t.Fatalf("jobs = %+v, want exactly the dry-run job", jobs.Jobs)
	}
	job := jobs.Jobs[0]
	if job.Label != "uploads: file upload (dry run)" || job.State != string(jobOK) || job.Message != res.Message {
		t.Errorf("job = %+v, want the (dry run) label and the estimate message", job)
	}

	// The same upload without the flag exports for real.
	resReal := upload(srv.URL + "/admin/uploads/collect")
	if resReal.DryRun || resReal.BundleID != "uploads-bundle-000001" {
		t.Fatalf("real upload after dry run = %+v, want bundle 000001", resReal)
	}
}

// TestAptDryRunSkipsDebDownloads proves the metadata-only estimate on the apt
// stream: a dry-run mirror fetches indexes but not one .deb, reports exactly
// what the following real collect then exports, and leaves no trace.
func TestAptDryRunSkipsDebDownloads(t *testing.T) {
	alpha := aptTestPkg{name: "alpha", version: "1.0", deb: []byte("DEB-ALPHA-1.0")}
	mux := http.NewServeMux()
	serveAptPkgs(t, mux, "/repo", "stable", []aptTestPkg{alpha})
	counting := newCountingHandler(mux)
	up := httptest.NewServer(counting)
	t.Cleanup(up.Close)

	ls, _ := newAptLowServer(t)
	req := AptCollectRequest{
		Name: "m", URI: up.URL + "/repo",
		Suites: []string{"stable"}, Components: []string{"main"}, Architectures: []string{"amd64"},
	}
	res, err := ls.CollectApt(withDryRunCollect(context.Background()), req)
	if err != nil {
		t.Fatalf("dry-run CollectApt: %v", err)
	}
	if !res.DryRun || res.Skipped || res.Estimate == nil {
		t.Fatalf("dry-run collect = %+v, want an estimate", res)
	}
	if n := counting.count("/repo/" + alpha.rel()); n != 0 {
		t.Errorf("alpha.deb was downloaded %d time(s) during the dry run, want 0", n)
	}
	assertNothingExported(t, ls, streamApt)

	// The real mirror downloads the .deb once and exports exactly what the
	// estimate promised.
	resReal, err := ls.CollectApt(context.Background(), req)
	if err != nil {
		t.Fatalf("real CollectApt: %v", err)
	}
	if n := counting.count("/repo/" + alpha.rel()); n != 1 {
		t.Errorf("alpha.deb downloaded %d time(s) by the real collect, want 1", n)
	}
	m := readBundleManifest(t, ls, resReal.BundleID)
	var totalBytes int64
	for _, f := range m.Files {
		totalBytes += f.Size
	}
	if est := res.Estimate; est.NewFiles != len(m.Files) || est.NewBytes != totalBytes {
		t.Errorf("estimate %+v disagrees with the real bundle (%d files, %d bytes)", est, len(m.Files), totalBytes)
	}
}

// TestContainerDryRunFetchesOnlyConfig pins the one blob a container dry run
// must still download: the config, which the platform check reads back from
// staging. Layers are only counted, and the estimate matches the real bundle.
func TestContainerDryRunFetchesOnlyConfig(t *testing.T) {
	img := makeFakeImage("layer-bytes-dryrun")
	const token = "fake-pull-token"
	mux := http.NewServeMux()
	requireToken := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+token }
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"token": token})
	})
	registerFakeImage(mux, "library/app", "v1", img, requireToken)
	counting := newCountingHandler(mux)
	var srv *httptest.Server
	srv = httptest.NewServer(rewriteChallengeRealm(counting, func() string { return srv.URL }))
	t.Cleanup(srv.Close)

	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": srv.URL})
	res, err := ls.CollectContainers(withDryRunCollect(context.Background()), ContainerCollectRequest{Images: []string{"app:v1"}})
	if err != nil {
		t.Fatalf("dry-run CollectContainers: %v", err)
	}
	if !res.DryRun || res.Skipped || res.Estimate == nil {
		t.Fatalf("dry-run collect = %+v, want an estimate", res)
	}
	if n := counting.count("/v2/library/app/blobs/" + containerSHA(img.layer)); n != 0 {
		t.Errorf("layer blob downloaded %d time(s) during the dry run, want 0", n)
	}
	if n := counting.count("/v2/library/app/blobs/" + containerSHA(img.config)); n != 1 {
		t.Errorf("config blob downloaded %d time(s) during the dry run, want 1 (the platform check reads it)", n)
	}
	assertNothingExported(t, ls, streamContainers)

	resReal, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"app:v1"}})
	if err != nil {
		t.Fatalf("real CollectContainers: %v", err)
	}
	m := readBundleManifest(t, ls, resReal.BundleID)
	var totalBytes int64
	for _, f := range m.Files {
		totalBytes += f.Size
	}
	if est := res.Estimate; est.NewFiles != len(m.Files) || est.NewBytes != totalBytes {
		t.Errorf("estimate %+v disagrees with the real bundle (%d files, %d bytes)", est, len(m.Files), totalBytes)
	}
}

func TestWantsDryRunCollect(t *testing.T) {
	for url, want := range map[string]bool{
		"/admin/go/collect":                      false,
		"/admin/go/collect?dry_run=1":            true,
		"/admin/go/collect?dry_run=0":            false,
		"/admin/go/collect?stream=1&dry_run=1":   true,
		"/admin/uploads/collect?dry_run=1&x=emp": true,
	} {
		r := httptest.NewRequest(http.MethodPost, url, nil)
		if got := wantsDryRunCollect(r); got != want {
			t.Errorf("wantsDryRunCollect(%s) = %v, want %v", url, got, want)
		}
	}
}

func TestSkipDownloadForDryRun(t *testing.T) {
	sha := strings.Repeat("a", 64)
	dry := withDryRunCollect(context.Background())
	for name, tc := range map[string]struct {
		ctx  context.Context
		sha  string
		size int64
		want bool
	}{
		"plain collect":  {context.Background(), sha, 10, false},
		"no sha":         {dry, "", 10, false},
		"no size":        {dry, sha, 0, false},
		"metadata known": {dry, sha, 10, true},
	} {
		if got := skipDownloadForDryRun(tc.ctx, tc.sha, tc.size); got != tc.want {
			t.Errorf("%s: skipDownloadForDryRun = %v, want %v", name, got, tc.want)
		}
	}
}

// TestWatchRunMessageDryRun keeps the job list's success summary honest for
// dry runs: the estimate line is the message.
func TestWatchRunMessageDryRun(t *testing.T) {
	res := ExportResult{DryRun: true, Skipped: true, Message: "dry run: all 3 file(s) (28 B) already forwarded; a collect would skip"}
	if got := watchRunMessage(res); got != res.Message {
		t.Errorf("watchRunMessage(dry run) = %q, want the estimate message", got)
	}
}
