package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cov3CSkipIfRoot skips a filesystem-fault-injection test when running as root,
// where permission bits are ignored.
func cov3CSkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("fault injection needs an unprivileged euid")
	}
}

// cov3CChmod chmods dir and restores it to 0o755 during cleanup.
func cov3CChmod(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// -----------------------------------------------------------------------------
// container.go: writeVerifiedBlob / stageContainerManifestBlob direct edges
// -----------------------------------------------------------------------------

func TestCov3C_WriteVerifiedBlob(t *testing.T) {
	sha := hexSHA([]byte("abc"))

	// Happy path first so the later error branches are the only difference.
	if err := writeVerifiedBlob(filepath.Join(t.TempDir(), "ok"), strings.NewReader("abc"), 3, sha); err != nil {
		t.Fatalf("valid blob rejected: %v", err)
	}

	// Size mismatch: reader shorter than declared.
	if err := writeVerifiedBlob(filepath.Join(t.TempDir(), "short"), strings.NewReader("ab"), 3, sha); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("short reader err = %v, want size mismatch", err)
	}
	// Size mismatch: reader longer than declared (LimitReader admits one extra byte).
	if err := writeVerifiedBlob(filepath.Join(t.TempDir(), "long"), strings.NewReader("abcd"), 3, sha); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("long reader err = %v, want size mismatch", err)
	}
	// SHA mismatch: right size, wrong content.
	if err := writeVerifiedBlob(filepath.Join(t.TempDir(), "wrong"), strings.NewReader("xyz"), 3, sha); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("wrong content err = %v, want sha256 mismatch", err)
	}
	// MkdirAll error: a parent path component is a regular file.
	file := filepath.Join(t.TempDir(), "afile")
	writeFile(t, file, []byte("x"))
	if err := writeVerifiedBlob(filepath.Join(file, "sub", "blob"), strings.NewReader("abc"), 3, sha); err == nil {
		t.Error("blob under a file parent should fail MkdirAll")
	}
}

func TestCov3C_StageContainerManifestBlob(t *testing.T) {
	digest := containerSHA([]byte("manifest"))
	seen := map[string]bool{}

	mf, err := stageContainerManifestBlob(t.TempDir(), digest, []byte("manifest"), seen)
	if err != nil || mf.SHA256 != strings.TrimPrefix(digest, "sha256:") {
		t.Fatalf("stage = %+v, %v", mf, err)
	}
	// Second call with the path already seen returns the record without writing.
	if _, err := stageContainerManifestBlob(t.TempDir(), digest, []byte("manifest"), seen); err != nil {
		t.Fatalf("already-seen stage: %v", err)
	}
	// MkdirAll error: stageRoot is actually a file.
	file := filepath.Join(t.TempDir(), "notadir")
	writeFile(t, file, []byte("x"))
	if _, err := stageContainerManifestBlob(file, digest, []byte("manifest"), map[string]bool{}); err == nil {
		t.Error("stage under a file stageRoot should fail")
	}
}

// -----------------------------------------------------------------------------
// container.go: validation / parsing edges
// -----------------------------------------------------------------------------

func TestCov3C_ValidateImageRefEdges(t *testing.T) {
	if err := validateImageRef("x", imageRef{Registry: "bad_host!", Repository: "ok"}); err == nil {
		t.Error("invalid registry host should be rejected")
	}
	if err := validateImageRef("x", imageRef{Registry: "docker.io", Repository: "library/ok", Tag: "bad tag"}); err == nil {
		t.Error("invalid tag should be rejected")
	}
}

func TestCov3C_ValidateContainerImageBadTag(t *testing.T) {
	digest := containerSHA([]byte("m"))
	seen := map[string]bool{containerBlobRel(digest): true}
	shaByPath := map[string]string{containerBlobRel(digest): strings.TrimPrefix(digest, "sha256:")}
	if err := validateContainerImage(ContainerImage{Tag: "bad tag", Digest: digest}, seen, shaByPath); err == nil {
		t.Error("invalid container tag should be rejected")
	}
}

func TestCov3C_ParseBearerChallengeEdges(t *testing.T) {
	// A part without '=' is skipped; an ftp realm is rejected as invalid.
	if _, _, err := parseBearerChallenge(`Bearer realm="ftp://x/token",lonelyparam`); err == nil {
		t.Error("ftp realm should be rejected")
	}
}

func TestCov3C_NextTagPageEdges(t *testing.T) {
	cases := []string{
		"",                             // empty
		`</v2/x>; rel="prev"`,          // not next
		`no-brackets; rel="next"`,      // no '<'
		`></v2/x>; rel="next"`,         // end <= start
		`<https://x/path>; rel="next"`, // no query
	}
	for _, link := range cases {
		if got := nextTagPage(link); got != "" {
			t.Errorf("nextTagPage(%q) = %q, want empty", link, got)
		}
	}
}

func TestCov3C_ResolveConstraintTagBadConstraint(t *testing.T) {
	ls, _ := newContainerLowServer(t, nil)
	client := ls.newContainerClient()
	_, err := client.resolveConstraintTag(context.Background(),
		imageRef{Registry: "docker.io", Repository: "library/x", Constraint: "<notaversion"})
	if err == nil {
		t.Error("garbage constraint should fail before any network call")
	}
}

func TestCov3C_CollectContainersBadRef(t *testing.T) {
	ls, _ := newContainerLowServer(t, nil)
	if _, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"Bad Ref!!"}}); err == nil {
		t.Error("an unparseable image ref should fail the collect")
	}
}

// -----------------------------------------------------------------------------
// container.go: upstream registry failure branches (token / manifest / blob)
// -----------------------------------------------------------------------------

// cov3CAlways401 serves a Bearer challenge pointing at a configurable /token
// handler and 401s every /v2 request, so the token dance in get()/fetchToken is
// exercised end to end.
func cov3CAlways401(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCov3C_ContainerTokenFailures(t *testing.T) {
	cases := []struct {
		name  string
		token http.HandlerFunc
	}{
		{"token endpoint 500", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}},
		{"token endpoint bad json", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "not json")
		}},
		{"token endpoint no token", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]string{})
		}},
		{"still unauthorized after token", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]string{"token": "good"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := cov3CAlways401(t, tc.token)
			ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
			_, err := ls.CollectContainers(context.Background(),
				ContainerCollectRequest{Images: []string{"example.com/org/app:1.0"}})
			if err == nil {
				t.Fatal("collect should fail when the token dance cannot succeed")
			}
		})
	}
}

// cov3CManifestBody is a Docker manifest referencing the given config and
// layer descriptors.
func cov3CManifest(config []byte, layers []map[string]any) []byte {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerManifest,
		"config":        map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": containerSHA(config), "size": len(config)},
		"layers":        layers,
	}
	b, _ := json.Marshal(m)
	return b
}

func TestCov3C_ContainerManifestErrors(t *testing.T) {
	t.Run("manifest HTTP 500", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/manifests/latest", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		if err := cov3CCollectOne(t, mux, "example.com/org/app"); err == nil {
			t.Fatal("500 manifest should fail")
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		wrong := "sha256:" + strings.Repeat("00", 32)
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/manifests/"+wrong, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", mtDockerManifest)
			_, _ = w.Write([]byte("some-other-bytes"))
		})
		if err := cov3CCollectOne(t, mux, "example.com/org/app@"+wrong); err == nil {
			t.Fatal("digest mismatch should fail")
		}
	})

	t.Run("unsupported media type", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/manifests/latest", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello not a manifest"))
		})
		if err := cov3CCollectOne(t, mux, "example.com/org/app"); err == nil {
			t.Fatal("unsupported media type should fail")
		}
	})

	t.Run("no config or layers", func(t *testing.T) {
		manifest := []byte(`{"schemaVersion":2,"mediaType":"` + mtDockerManifest + `","config":{},"layers":[]}`)
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/manifests/latest", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", mtDockerManifest)
			_, _ = w.Write(manifest)
		})
		if err := cov3CCollectOne(t, mux, "example.com/org/app"); err == nil {
			t.Fatal("manifest with no config/layers should fail")
		}
	})

	t.Run("foreign layer", func(t *testing.T) {
		config := []byte(`{"architecture":"amd64","os":"linux"}`)
		layer := []byte("layer-bytes")
		manifest := cov3CManifest(config, []map[string]any{
			{"mediaType": "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip", "digest": containerSHA(layer), "size": len(layer)},
		})
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/manifests/latest", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", mtDockerManifest)
			_, _ = w.Write(manifest)
		})
		mux.HandleFunc("/v2/org/app/blobs/"+containerSHA(config), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(config)
		})
		if err := cov3CCollectOne(t, mux, "example.com/org/app"); err == nil {
			t.Fatal("foreign layer should fail")
		}
	})

	t.Run("blob HTTP 404", func(t *testing.T) {
		config := []byte(`{"architecture":"amd64","os":"linux"}`)
		layer := []byte("layer-bytes")
		manifest := cov3CManifest(config, []map[string]any{
			{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": containerSHA(layer), "size": len(layer)},
		})
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/manifests/latest", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", mtDockerManifest)
			_, _ = w.Write(manifest)
		})
		mux.HandleFunc("/v2/org/app/blobs/"+containerSHA(config), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(config)
		})
		// The layer blob is never registered, so the mux 404s it.
		if err := cov3CCollectOne(t, mux, "example.com/org/app"); err == nil {
			t.Fatal("missing layer blob should fail")
		}
	})

	t.Run("tags/list HTTP 500 for a constraint", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/org/app/tags/list", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		if err := cov3CCollectOne(t, mux, "example.com/org/app:1.x"); err == nil {
			t.Fatal("tags/list 500 should fail the constraint resolve")
		}
	})
}

// cov3CCollectOne runs a single-image collect against a no-auth registry served
// by mux and returns the collect error (nil on success).
func cov3CCollectOne(t *testing.T, mux *http.ServeMux, image string) error {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	_, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{image}})
	return err
}

// -----------------------------------------------------------------------------
// container.go: high-side listing/serving error branches (fault injection)
// -----------------------------------------------------------------------------

func TestCov3C_ContainerHighSideErrors(t *testing.T) {
	cov3CSkipIfRoot(t)
	hs, _, _ := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Break the repos tree so every walk of it errors.
	cov3CChmod(t, filepath.Join(hs.containersDir(), "repos"), 0)

	if code, _ := httpGet(t, srv.URL+"/v2/_catalog"); code != http.StatusInternalServerError {
		t.Errorf("_catalog with broken repos dir = %d, want 500", code)
	}
	if code, _ := httpGet(t, srv.URL+"/ui/api/tree?eco=containers"); code != http.StatusInternalServerError {
		t.Errorf("containers tree with broken repos dir = %d, want 500", code)
	}
	if code, _ := httpGet(t, srv.URL+"/ui/api/repos?eco=containers"); code != http.StatusInternalServerError {
		t.Errorf("containers repos with broken repos dir = %d, want 500", code)
	}

	// Direct list calls surface the walk error too.
	if _, err := hs.listContainerRepoNames(); err == nil {
		t.Error("listContainerRepoNames should error on an unreadable repos dir")
	}
}

func TestCov3C_ContainerServeNotFound(t *testing.T) {
	hs, _, _ := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// tags/list for an unknown repository -> 404.
	if code, _ := httpGet(t, srv.URL+"/v2/docker.io/library/nope/tags/list"); code != http.StatusNotFound {
		t.Errorf("unknown tags/list = %d, want 404", code)
	}
	// A blob request with an invalid digest -> 404 DIGEST_INVALID.
	if code, _ := httpGet(t, srv.URL+"/v2/docker.io/library/alpine/blobs/notadigest"); code != http.StatusNotFound {
		t.Errorf("bad blob digest = %d, want 404", code)
	}
	// A blob whose digest is well-formed but not referenced by the repo -> 404.
	unref := "sha256:" + strings.Repeat("11", 32)
	if code, _ := httpGet(t, srv.URL+"/v2/docker.io/library/alpine/blobs/"+unref); code != http.StatusNotFound {
		t.Errorf("unreferenced blob = %d, want 404", code)
	}
}

// -----------------------------------------------------------------------------
// hf.go: collect parse error + repo plain-file download branches
// -----------------------------------------------------------------------------

func TestCov3C_CollectHFBadRef(t *testing.T) {
	ls, _ := newHFLowServer(t, "http://127.0.0.1:0")
	if _, err := ls.CollectHF(context.Background(), HFCollectRequest{Models: []string{"bad ref!!"}}); err == nil {
		t.Error("an unparseable model ref should fail the collect")
	}
}

// TestCov3C_HFRepoPlainFileDedup drives a repo snapshot with two non-LFS files
// carrying identical content: the second hashes to an already-staged blob, so
// downloadHFRepoPlainFile takes its early "already staged" return.
func TestCov3C_HFRepoPlainFileDedup(t *testing.T) {
	up := fakeHFRepoUpstream{
		sha: strings.Repeat("cd", 20),
		files: map[string][]byte{
			"config.json":            []byte("same-bytes"),
			"generation_config.json": []byte("same-bytes"),
		},
		lfs: map[string]bool{},
	}
	hub := fakeHFHub(t, nil, map[string]fakeHFRepoUpstream{"openai/dup": up}, "")
	ls, _ := newHFLowServer(t, hub.URL)

	res, err := ls.CollectHF(context.Background(), HFCollectRequest{Repos: []string{"openai/dup"}})
	if err != nil {
		t.Fatalf("CollectHF: %v", err)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	// Two repo files, but only one content-addressed blob (shared content).
	if len(m.HuggingFace.Repos[0].Files) != 2 {
		t.Fatalf("repo files = %+v, want 2", m.HuggingFace.Repos[0].Files)
	}
	if len(m.Files) != 1 {
		t.Fatalf("bundle blobs = %+v, want 1 (shared content staged once)", m.Files)
	}
}

// TestCov3C_HFRepoPlainFile404 makes a non-LFS file's resolve return 404, so
// downloadHFToTemp hits its non-200 branch and the repo collect fails.
func TestCov3C_HFRepoPlainFile404(t *testing.T) {
	up := fakeGptOssRepo()
	mux := http.NewServeMux()
	info := fakeHFRepoInfoJSON(up)
	mux.HandleFunc("/api/models/openai/gpt-oss-20b/revision/main", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(info)
	})
	mux.HandleFunc("/api/models/openai/gpt-oss-20b/revision/"+up.sha, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(info)
	})
	// config.json (non-LFS) resolves to 404; the LFS weights are served fine but
	// the plain-file failure aborts the snapshot.
	mux.HandleFunc("/openai/gpt-oss-20b/resolve/"+up.sha+"/config.json", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	for p, content := range up.files {
		if p == "config.json" {
			continue
		}
		body := content
		mux.HandleFunc("/openai/gpt-oss-20b/resolve/"+up.sha+"/"+p, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ls, _ := newHFLowServer(t, srv.URL)

	if _, err := ls.CollectHF(context.Background(), HFCollectRequest{
		Repos:       []string{"openai/gpt-oss-20b"},
		RepoExclude: []string{"original"},
	}); err == nil {
		t.Fatal("a 404 on a plain repo file should fail the collect")
	}
}

// -----------------------------------------------------------------------------
// hf.go: high-side listing errors + hfConfigFields edges
// -----------------------------------------------------------------------------

func TestCov3C_HFHighSideListErrors(t *testing.T) {
	cov3CSkipIfRoot(t)
	hs, _, _ := collectAndImportHF(t)
	cov3CChmod(t, filepath.Join(hs.hfDir(), "models"), 0)

	if _, err := hs.listHFModels(); err == nil {
		t.Error("listHFModels should error on an unreadable models dir")
	}
	if _, err := hs.hfRepoList(); err == nil {
		t.Error("hfRepoList should error on an unreadable models dir")
	}
}

func TestCov3C_HFConfigFieldsEdges(t *testing.T) {
	hs, _, _ := collectAndImportHF(t)

	// No blobs -> no fields.
	if fields := hs.hfConfigFields(HFVariant{}); fields != nil {
		t.Errorf("hfConfigFields(no blobs) = %+v, want nil", fields)
	}
	// A config blob that is not on disk -> ReadFile fails -> no fields.
	missing := HFVariant{Blobs: []HFBlob{{Digest: "sha256:" + strings.Repeat("00", 32)}}}
	if fields := hs.hfConfigFields(missing); fields != nil {
		t.Errorf("hfConfigFields(missing blob) = %+v, want nil", fields)
	}
}

// -----------------------------------------------------------------------------
// python.go: scan/hash/collect error branches
// -----------------------------------------------------------------------------

func TestCov3C_CollectPythonDistReadDirError(t *testing.T) {
	if _, _, _, err := collectPythonDist(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("collectPythonDist on a missing directory should error")
	}
}

func TestCov3C_PythonScanErrors(t *testing.T) {
	cov3CSkipIfRoot(t)
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 1, 0, map[string]string{
		"requests-2.32.4-py3-none-any.whl": "wheel-requests",
	})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Unreadable package dir -> scanPyFiles ReadDir error -> 500 on both pages.
	cov3CChmod(t, hs.pythonDir(), 0)
	if code, _ := httpGet(t, srv.URL+"/simple/"); code != http.StatusInternalServerError {
		t.Errorf("simple root with unreadable dir = %d, want 500", code)
	}
	if code, _ := httpGet(t, srv.URL+"/simple/requests/"); code != http.StatusInternalServerError {
		t.Errorf("simple project with unreadable dir = %d, want 500", code)
	}
}

func TestCov3C_PythonSimpleProjectHashError(t *testing.T) {
	cov3CSkipIfRoot(t)
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 1, 0, map[string]string{
		"requests-2.32.4-py3-none-any.whl": "wheel-requests",
	})
	if _, err := hs.ImportNext(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// The dir is readable (scan succeeds) but the wheel file cannot be hashed.
	wheel := filepath.Join(hs.pythonDir(), "requests-2.32.4-py3-none-any.whl")
	cov3CChmod(t, wheel, 0)
	if code, _ := httpGet(t, srv.URL+"/simple/requests/"); code != http.StatusInternalServerError {
		t.Errorf("project page with unhashable wheel = %d, want 500", code)
	}
}

func TestCov3C_CollectPythonPipFails(t *testing.T) {
	const failingPip = `#!/usr/bin/env bash
echo "pip is broken" >&2
exit 1
`
	ls, _ := newPyLowServerWithPip(t, failingPip)
	if _, err := ls.CollectPython(context.Background(), PythonCollectRequest{Requirements: []string{"requests"}}); err == nil {
		t.Error("a failing pip should fail CollectPython")
	}
}

// -----------------------------------------------------------------------------
// uploads.go: collect + delete + listing error branches
// -----------------------------------------------------------------------------

func TestCov3C_UploadsCollectNonMultipart(t *testing.T) {
	ls, _ := newAptLowServer(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/uploads/collect", strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	if _, err := ls.HandleUploadsCollect(context.Background(), req); err == nil {
		t.Error("a non-multipart upload should fail")
	}
}

func TestCov3C_UploadsCollectExtraFieldAndCancel(t *testing.T) {
	ls, _ := newAptLowServer(t)

	// A multipart body with an unknown non-file field exercises the "drain and
	// ignore" branch of consumeUploadPart.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("folder", "tools"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("junk", "ignored"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("file", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/uploads/collect", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if _, err := ls.HandleUploadsCollect(context.Background(), req); err != nil {
		t.Fatalf("upload with an extra field failed: %v", err)
	}

	// A cancelled context makes the export gate refuse before packing, so
	// collectUploads returns that error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ls.HandleUploadsCollect(ctx, newUploadRequest(t, "tools", []uploadPair{{"b.txt", "x"}})); err == nil {
		t.Error("a cancelled upload collect should fail")
	}
}

// cov3CUploadsHighServer imports one upload into a fresh high server and returns
// it alongside a running test server.
func cov3CUploadsHighServer(t *testing.T) (*HighServer, *httptest.Server) {
	t.Helper()
	ls, priv := newAptLowServer(t)
	hs := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	res := collectUpload(t, ls, "tools", []uploadPair{{"a.txt", "content-a"}})
	importNextUploads(t, ls, hs, res.BundleID)
	srv := httptest.NewServer(hs)
	t.Cleanup(srv.Close)
	return hs, srv
}

func TestCov3C_DeleteUploadValidationErrors(t *testing.T) {
	_, srv := cov3CUploadsHighServer(t)

	// Malformed JSON body -> 400.
	resp, err := http.Post(srv.URL+"/admin/uploads/delete", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed delete body = %d, want 400", resp.StatusCode)
	}

	// Empty folder and invalid file names -> 400.
	if r := deleteUpload(t, srv, "", "a.txt"); r.StatusCode != http.StatusBadRequest {
		t.Errorf("empty folder delete = %d, want 400", r.StatusCode)
	}
	if r := deleteUpload(t, srv, "tools", "bad name/"); r.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid file delete = %d, want 400", r.StatusCode)
	}
}

func TestCov3C_DeleteUploadRemoveError(t *testing.T) {
	cov3CSkipIfRoot(t)
	hs, srv := cov3CUploadsHighServer(t)

	// Make the folder directory read-only so os.Remove of the file fails with a
	// permission error rather than not-found -> 500.
	cov3CChmod(t, filepath.Join(hs.uploadsDir(), "tools"), 0o500)
	if r := deleteUpload(t, srv, "tools", "a.txt"); r.StatusCode != http.StatusInternalServerError {
		t.Errorf("delete with unwritable folder = %d, want 500", r.StatusCode)
	}
}

func TestCov3C_UploadsListErrors(t *testing.T) {
	cov3CSkipIfRoot(t)
	hs, _ := cov3CUploadsHighServer(t)

	// An unreadable folder makes listUploadedFiles error, which propagates.
	cov3CChmod(t, filepath.Join(hs.uploadsDir(), "tools"), 0)
	if _, err := hs.listUploadedFolders(); err == nil {
		t.Error("listUploadedFolders should error on an unreadable folder")
	}

	if _, err := listUploadedFiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("listUploadedFiles on a missing dir should error")
	}
}

func TestCov3C_UploadsDetailErrors(t *testing.T) {
	hs, _ := cov3CUploadsHighServer(t)

	// No slash separating folder/name.
	if _, err := hs.uploadsDetail("noslash"); err == nil {
		t.Error("uploadsDetail without a slash should fail")
	}
	// Well-formed but the file does not exist.
	if _, err := hs.uploadsDetail("tools/missing.txt"); err == nil {
		t.Error("uploadsDetail for a missing file should fail")
	}
}

// -----------------------------------------------------------------------------
// ui.go: cachedTrees / listGoModules / goDetail error branches
// -----------------------------------------------------------------------------

func TestCov3C_ListGoModulesNoDir(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// No Go modules mirrored yet: listGoModules returns nil, nil.
	mods, err := hs.listGoModules()
	if err != nil || mods != nil {
		t.Fatalf("listGoModules(empty) = %+v, %v, want nil, nil", mods, err)
	}
}

func TestCov3C_CachedListsAndTreeError(t *testing.T) {
	cov3CSkipIfRoot(t)
	srv := mixedHighServer(t) // imports Go modules under go/
	// Break the Go module tree so listGoModules (the first cachedTrees step)
	// errors, surfacing as a 500 from handleUITree and a direct cachedTrees error.
	hs := srv.Config.Handler.(*HighServer)
	cov3CChmod(t, hs.goModuleDir(), 0)

	if code, _ := httpGet(t, srv.URL+"/ui/api/tree?eco=go"); code != http.StatusInternalServerError {
		t.Errorf("tree with broken go dir = %d, want 500", code)
	}
	if _, err := hs.cachedTrees(); err == nil {
		t.Error("cachedTrees should error on an unreadable go module dir")
	}
	if _, err := hs.listGoModules(); err == nil {
		t.Error("listGoModules should error on an unreadable go module dir")
	}
}

func TestCov3C_GoDetailInvalidVersion(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	// A version containing a slash is rejected before any filesystem access.
	if _, err := hs.goDetail("github.com/foo/bar@v1/2"); err == nil {
		t.Error("goDetail with a slash in the version should fail")
	}
}

func TestCov3C_GoInfoTimeEdges(t *testing.T) {
	// Missing file -> empty.
	if got := goInfoTime(filepath.Join(t.TempDir(), "nope.info")); got != "" {
		t.Errorf("goInfoTime(missing) = %q, want empty", got)
	}
	// Present but with a zero/absent time -> empty.
	info := filepath.Join(t.TempDir(), "v1.info")
	writeFile(t, info, []byte(`{"Version":"v1.0.0"}`))
	if got := goInfoTime(info); got != "" {
		t.Errorf("goInfoTime(no time) = %q, want empty", got)
	}
}

func TestCov3C_PythonDetailErrors(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	for _, spec := range []string{"", "a/b", "nope.whl"} {
		if _, err := hs.pythonDetail(spec); err == nil {
			t.Errorf("pythonDetail(%q) should fail", spec)
		}
	}
}

func TestCov3C_HandlePyPackageSlash(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	// A filename containing a slash is a 404 (not a directory walk).
	if code, _ := httpGet(t, srv.URL+"/packages/foo/bar.whl"); code != http.StatusNotFound {
		t.Errorf("nested /packages path = %d, want 404", code)
	}
}

// -----------------------------------------------------------------------------
// container.go: validContainerName + manifest-blob-missing branches
// -----------------------------------------------------------------------------

func TestCov3C_ValidContainerName(t *testing.T) {
	bad := []string{
		"onlyone",           // fewer than two segments
		"../etc/passwd",     // fails validateRelPath
		"docker.io/BadCaps", // component fails the lowercase regex
	}
	for _, name := range bad {
		if validContainerName(name) {
			t.Errorf("validContainerName(%q) = true, want false", name)
		}
	}
	if !validContainerName("docker.io/library/alpine") {
		t.Error("a normal registry/repo name should be valid")
	}
}

func TestCov3C_ContainerManifestBlobMissing(t *testing.T) {
	hs, alpine, _ := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	// The repo index still references the documents, but their blob files are
	// gone: the amd64 manifest (fetched by digest) and the preserved
	// multi-platform index (served for the tag).
	if err := os.Remove(hs.containerBlobPath(alpine.manifestDigest)); err != nil {
		t.Fatal(err)
	}
	if code, _ := httpGet(t, srv.URL+"/v2/docker.io/library/alpine/manifests/"+alpine.manifestDigest); code != http.StatusNotFound {
		t.Errorf("manifest with a missing blob = %d, want 404", code)
	}
	if err := os.Remove(hs.containerBlobPath(containerSHA(alpine.index))); err != nil {
		t.Fatal(err)
	}
	if code, _ := httpGet(t, srv.URL+"/v2/docker.io/library/alpine/manifests/3.20"); code != http.StatusNotFound {
		t.Errorf("tag with a missing index blob = %d, want 404", code)
	}
}

// -----------------------------------------------------------------------------
// hf.go: hfModelBlob + manifest-blob-missing + LFS download failure
// -----------------------------------------------------------------------------

func TestCov3C_HFModelBlobNoMatch(t *testing.T) {
	if _, ok := hfModelBlob(HFVariant{Blobs: []HFBlob{{MediaType: "application/other"}}}); ok {
		t.Error("a variant without an Ollama model layer should report no model blob")
	}
}

func TestCov3C_HFManifestBlobMissing(t *testing.T) {
	hs, gpt, _ := collectAndImportHF(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()
	if err := os.Remove(hs.hfBlobPath(gpt.digest)); err != nil {
		t.Fatal(err)
	}
	if code, _ := httpGet(t, srv.URL+"/v2/unsloth/gpt-oss-20b-GGUF/manifests/Q4_0"); code != http.StatusNotFound {
		t.Errorf("hf manifest with a missing blob = %d, want 404", code)
	}
}

func TestCov3C_HFRepoLFSFile404(t *testing.T) {
	weights := []byte("lfs-weights")
	up := fakeHFRepoUpstream{
		sha:   strings.Repeat("ef", 20),
		files: map[string][]byte{"model.safetensors": weights},
		lfs:   map[string]bool{"model.safetensors": true},
	}
	info := fakeHFRepoInfoJSON(up)
	mux := http.NewServeMux()
	for _, rev := range []string{"main", up.sha} {
		mux.HandleFunc("/api/models/org/lfsrepo/revision/"+rev, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(info)
		})
	}
	// The LFS file resolves to a 404, so downloadHFRepoLFSFile hits its non-200 branch.
	mux.HandleFunc("/org/lfsrepo/resolve/"+up.sha+"/model.safetensors", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ls, _ := newHFLowServer(t, srv.URL)

	if _, err := ls.CollectHF(context.Background(), HFCollectRequest{Repos: []string{"org/lfsrepo"}}); err == nil {
		t.Fatal("a 404 on an LFS repo file should fail the collect")
	}
}

// -----------------------------------------------------------------------------
// uploads.go: pure tree helper edge
// -----------------------------------------------------------------------------

func TestCov3C_UploadsTreeChildrenUnknownFolder(t *testing.T) {
	folders := []UploadedFolder{{Folder: "tools", Files: []UploadedFile{{Name: "a.txt"}}}}
	if nodes := uploadsTreeChildren(folders, "nonexistent"); len(nodes) != 0 {
		t.Errorf("uploadsTreeChildren(unknown) = %+v, want empty", nodes)
	}
}
