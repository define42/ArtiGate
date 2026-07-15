package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		spec string
		want imageRef
	}{
		{"alpine", imageRef{Registry: "docker.io", Repository: "library/alpine", Tag: "latest"}},
		{"alpine:3.20", imageRef{Registry: "docker.io", Repository: "library/alpine", Tag: "3.20"}},
		{"grafana/grafana:10.4.0", imageRef{Registry: "docker.io", Repository: "grafana/grafana", Tag: "10.4.0"}},
		{"ghcr.io/org/app:v1", imageRef{Registry: "ghcr.io", Repository: "org/app", Tag: "v1"}},
		{"registry.access.redhat.com/ubi9/ubi:latest", imageRef{Registry: "registry.access.redhat.com", Repository: "ubi9/ubi", Tag: "latest"}},
		{"index.docker.io/library/alpine:3.20", imageRef{Registry: "docker.io", Repository: "library/alpine", Tag: "3.20"}},
		{
			"ghcr.io/org/app@sha256:" + strings.Repeat("ab", 32),
			imageRef{Registry: "ghcr.io", Repository: "org/app", Digest: "sha256:" + strings.Repeat("ab", 32)},
		},
	}
	for _, tt := range tests {
		got, err := parseImageRef(tt.spec)
		if err != nil {
			t.Errorf("parseImageRef(%q): %v", tt.spec, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseImageRef(%q) = %+v, want %+v", tt.spec, got, tt.want)
		}
	}

	bad := []string{
		"",
		"Alpine:3.20",                 // uppercase repository
		"alpine:bad tag",              // invalid tag
		"alpine@sha256:short",         // invalid digest
		"myreg.local:5000/foo:latest", // registry port cannot be mirrored
		"registry.example.com/",       // empty repository
	}
	for _, spec := range bad {
		if _, err := parseImageRef(spec); err == nil {
			t.Errorf("parseImageRef(%q) should fail", spec)
		}
	}
}

func TestPickAmd64Manifest(t *testing.T) {
	entries := []ociDescriptor{
		{Digest: "sha256:arm", Platform: &ociPlatform{OS: "linux", Architecture: "arm64"}},
		{Digest: "sha256:att", Platform: &ociPlatform{OS: "unknown", Architecture: "unknown"}},
		{Digest: "sha256:amd", Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
	}
	got, err := pickAmd64Manifest(entries)
	if err != nil || got.Digest != "sha256:amd" {
		t.Fatalf("pickAmd64Manifest = %+v, %v", got, err)
	}
	if _, err := pickAmd64Manifest(entries[:2]); err == nil {
		t.Error("index without linux/amd64 should be rejected")
	}
}

func TestParseBearerChallenge(t *testing.T) {
	realm, params, err := parseBearerChallenge(
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`)
	if err != nil {
		t.Fatal(err)
	}
	if realm != "https://auth.docker.io/token" || params["service"] != "registry.docker.io" {
		t.Fatalf("parsed realm=%q params=%v", realm, params)
	}
	if _, _, err := parseBearerChallenge(`Basic realm="registry"`); err == nil {
		t.Error("Basic challenge should be rejected")
	}
	if _, _, err := parseBearerChallenge(`Bearer service="x"`); err == nil {
		t.Error("challenge without realm should be rejected")
	}
}

func TestParseContainerRegistryOverrides(t *testing.T) {
	m, err := parseContainerRegistryOverrides("docker.io=https://mirror.example.com/, ghcr.io=http://proxy.local")
	if err != nil {
		t.Fatal(err)
	}
	if m["docker.io"] != "https://mirror.example.com" || m["ghcr.io"] != "http://proxy.local" {
		t.Fatalf("overrides = %v", m)
	}
	for _, bad := range []string{"docker.io", "docker.io=ftp://x"} {
		if _, err := parseContainerRegistryOverrides(bad); err == nil {
			t.Errorf("override %q should be rejected", bad)
		}
	}
}

func TestParseContainerAuthEnv(t *testing.T) {
	m, err := parseContainerAuthEnv("ghcr.io=alice:s3cr3t, index.docker.io=bob:tok:en= ,")
	if err != nil {
		t.Fatal(err)
	}
	if m["ghcr.io"] != (registryCredential{Username: "alice", Password: "s3cr3t"}) {
		t.Fatalf("ghcr.io login = %+v", m["ghcr.io"])
	}
	// Docker Hub aliases fold to docker.io; a password may contain ':' and '='.
	if m["docker.io"] != (registryCredential{Username: "bob", Password: "tok:en="}) {
		t.Fatalf("docker.io login = %+v", m["docker.io"])
	}
	if len(m) != 2 {
		t.Fatalf("logins = %v", m)
	}
	if m, err := parseContainerAuthEnv(""); err != nil || len(m) != 0 {
		t.Fatalf("empty value = %v, %v", m, err)
	}
	for _, tt := range []struct{ entry, secret string }{
		{"ghcr.io", ""},
		{"ghcr.io=aliceonly", "aliceonly"},
		{"ghcr.io=:hunter2", "hunter2"},
		{"ghcr.io=alice:", "alice"},
	} {
		_, err := parseContainerAuthEnv(tt.entry)
		if err == nil {
			t.Errorf("entry %q should be rejected", tt.entry)
			continue
		}
		if !strings.Contains(err.Error(), containerAuthEnv) {
			t.Errorf("error should name the env var: %v", err)
		}
		if tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
			t.Errorf("error must not echo the login: %v", err)
		}
	}
}

func TestContainerCollectCredentials(t *testing.T) {
	refs := func(specs ...string) []imageRef {
		t.Helper()
		parsed, err := parseContainerCollectRefs(specs)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	t.Setenv(containerAuthEnv, "ghcr.io=envuser:envpass")

	// Without request auth the standing env credentials apply (the path
	// scheduled watches take).
	creds, err := containerCollectCredentials(refs("ghcr.io/org/app:v1"), nil)
	if err != nil || creds["ghcr.io"].Username != "envuser" {
		t.Fatalf("env creds = %v, %v", creds, err)
	}

	// A request login wins over the env entry; an unnamed registry resolves to
	// the pull's single registry.
	creds, err = containerCollectCredentials(refs("ghcr.io/org/app:v1"), &ContainerCollectAuth{Username: "u", Password: "p"})
	if err != nil || creds["ghcr.io"] != (registryCredential{Username: "u", Password: "p"}) {
		t.Fatalf("request creds = %v, %v", creds, err)
	}

	// Naming the registry scopes the login inside a multi-registry pull, and
	// Docker Hub aliases fold.
	creds, err = containerCollectCredentials(refs("alpine:3.20", "quay.io/org/app:v1"),
		&ContainerCollectAuth{Registry: "index.docker.io", Username: "u", Password: "p"})
	if err != nil || creds["docker.io"].Username != "u" {
		t.Fatalf("scoped creds = %v, %v", creds, err)
	}

	if _, err := containerCollectCredentials(refs("alpine:3.20", "quay.io/org/app:v1"),
		&ContainerCollectAuth{Username: "u", Password: "p"}); err == nil {
		t.Error("multi-registry pull with an unscoped login should fail")
	}
	if _, err := containerCollectCredentials(refs("alpine:3.20"),
		&ContainerCollectAuth{Registry: "ghcr.io", Username: "u", Password: "p"}); err == nil {
		t.Error("a login for a registry outside the pull should fail")
	}
	if _, err := containerCollectCredentials(refs("alpine:3.20"),
		&ContainerCollectAuth{Username: "u"}); err == nil {
		t.Error("a login without a password should fail")
	}

	// A malformed env value fails the collect, naming the variable.
	t.Setenv(containerAuthEnv, "garbage")
	if _, err := containerCollectCredentials(refs("alpine:3.20"), nil); err == nil || !strings.Contains(err.Error(), containerAuthEnv) {
		t.Errorf("malformed env value should fail naming %s, got %v", containerAuthEnv, err)
	}
}

// -----------------------------------------------------------------------------
// Fake upstream registry
// -----------------------------------------------------------------------------

func containerSHA(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// fakeImage is one linux/amd64 image (config + one layer + manifest + a
// multi-platform index pointing at it) served by the fake registry.
type fakeImage struct {
	layer          []byte
	config         []byte
	manifest       []byte
	manifestDigest string
	index          []byte
}

func makeFakeImage(layerContent string) fakeImage {
	// The config carries a build history: one filesystem layer (the ADD, which
	// matches the single manifest layer) plus a metadata-only CMD step.
	img := fakeImage{
		layer: []byte(layerContent),
		config: []byte(`{"architecture":"amd64","os":"linux","history":[` +
			`{"created_by":"/bin/sh -c #(nop) ADD file:abc123 in / "},` +
			`{"created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}` +
			`]}`),
	}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerManifest,
		"config": map[string]any{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"digest":    containerSHA(img.config),
			"size":      len(img.config),
		},
		"layers": []map[string]any{{
			"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
			"digest":    containerSHA(img.layer),
			"size":      len(img.layer),
		}},
	}
	img.manifest, _ = json.Marshal(manifest)
	img.manifestDigest = containerSHA(img.manifest)
	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerList,
		"manifests": []map[string]any{
			{
				"mediaType": mtDockerManifest,
				"digest":    "sha256:" + strings.Repeat("00", 32),
				"size":      1,
				"platform":  map[string]string{"architecture": "arm64", "os": "linux"},
			},
			{
				"mediaType": mtDockerManifest,
				"digest":    img.manifestDigest,
				"size":      len(img.manifest),
				"platform":  map[string]string{"architecture": "amd64", "os": "linux"},
			},
		},
	}
	img.index, _ = json.Marshal(index)
	return img
}

// registerFakeImage serves one image's index (by tag), manifest (by digest),
// and blobs for a repository on mux, behind an anonymous Bearer token flow.
func registerFakeImage(mux *http.ServeMux, repo, tag string, img fakeImage, requireToken func(*http.Request) bool) {
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !requireToken(r) {
				w.Header().Set("Www-Authenticate", `Bearer realm="/token-not-set",service="test"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	serve := func(body []byte, contentType string) http.HandlerFunc {
		return authed(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(body)
		})
	}
	mux.HandleFunc("/v2/"+repo+"/manifests/"+tag, serve(img.index, mtDockerList))
	mux.HandleFunc("/v2/"+repo+"/manifests/"+img.manifestDigest, serve(img.manifest, mtDockerManifest))
	mux.HandleFunc("/v2/"+repo+"/blobs/"+containerSHA(img.config), serve(img.config, "application/octet-stream"))
	mux.HandleFunc("/v2/"+repo+"/blobs/"+containerSHA(img.layer), serve(img.layer, "application/octet-stream"))
}

// fakeContainerRegistry serves the given repo:tag images behind a token flow
// and returns the server. Requests without the fake token get a 401 pointing
// at the server's own /token endpoint. extraTags optionally overrides a
// repository's tags/list response (for constraint-resolution tests); by
// default each repository lists the tags of its registered images.
func fakeContainerRegistry(t *testing.T, images map[string]fakeImage, extraTags ...map[string][]string) *httptest.Server {
	t.Helper()
	return fakeContainerRegistryGated(t, nil, images, extraTags...)
}

// fakeContainerRegistryGated is fakeContainerRegistry with an optional gate on
// the token endpoint: when tokenGate is non-nil, /token demands it (e.g. HTTP
// Basic credentials — the docker login flow of a private registry).
func fakeContainerRegistryGated(t *testing.T, tokenGate func(*http.Request) bool, images map[string]fakeImage, extraTags ...map[string][]string) *httptest.Server {
	t.Helper()
	const token = "fake-pull-token"
	mux := http.NewServeMux()
	var srv *httptest.Server
	requireToken := func(r *http.Request) bool {
		return r.Header.Get("Authorization") == "Bearer "+token
	}
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if tokenGate != nil && !tokenGate(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]string{"token": token})
	})
	tagsByRepo := map[string][]string{}
	for key, img := range images {
		repo, tag, ok := strings.Cut(key, ":")
		if !ok {
			t.Fatalf("bad fake image key %q", key)
		}
		registerFakeImage(mux, repo, tag, img, requireToken)
		tagsByRepo[repo] = append(tagsByRepo[repo], tag)
	}
	for _, override := range extraTags {
		for repo, tags := range override {
			tagsByRepo[repo] = tags
		}
	}
	registerFakeTagLists(mux, tagsByRepo, requireToken)
	srv = httptest.NewServer(rewriteChallengeRealm(mux, func() string { return srv.URL }))
	t.Cleanup(srv.Close)
	return srv
}

// registerFakeTagLists serves each repository's tags/list behind the token check.
func registerFakeTagLists(mux *http.ServeMux, tagsByRepo map[string][]string, requireToken func(*http.Request) bool) {
	for repo, tags := range tagsByRepo {
		mux.HandleFunc("/v2/"+repo+"/tags/list", func(w http.ResponseWriter, r *http.Request) {
			if !requireToken(r) {
				w.Header().Set("Www-Authenticate", `Bearer realm="/token-not-set",service="test"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			writeJSON(w, map[string]any{"name": repo, "tags": tags})
		})
	}
}

// rewriteChallengeRealm patches the Bearer challenge's placeholder realm with
// the server's absolute /token URL, which is known only once it is running.
func rewriteChallengeRealm(next http.Handler, baseURL func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, vs := range rec.Header() {
			for _, v := range vs {
				if k == "Www-Authenticate" {
					v = strings.Replace(v, "/token-not-set", baseURL()+"/token", 1)
				}
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func newContainerLowServer(t *testing.T, registryBases map[string]string) (*LowServer, ed25519.PrivateKey) {
	t.Helper()
	ls, priv := newAptLowServer(t)
	ls.containerRegistryBases = registryBases
	return ls, priv
}

// -----------------------------------------------------------------------------
// Low side: collect
// -----------------------------------------------------------------------------

func TestCollectContainers(t *testing.T) {
	img := makeFakeImage("layer-bytes-alpine")
	up := fakeContainerRegistry(t, map[string]fakeImage{"library/alpine:3.20": img})
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": up.URL})

	res, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"alpine:3.20"}})
	if err != nil {
		t.Fatalf("CollectContainers: %v", err)
	}
	if res.BundleID != "containers-bundle-000001" || res.ExportedModules != 1 || len(res.SkippedModules) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}

	m := readBundleManifest(t, ls, res.BundleID)
	if m.Containers == nil || len(m.Containers.Repos) != 1 {
		t.Fatalf("manifest has no container repos: %+v", m.Containers)
	}
	repo := m.Containers.Repos[0]
	if repo.Registry != "docker.io" || repo.Repository != "library/alpine" {
		t.Fatalf("repo identity = %+v", repo)
	}
	if len(repo.Images) != 1 || repo.Images[0].Tag != "3.20" || repo.Images[0].Digest != img.manifestDigest {
		t.Fatalf("image record = %+v", repo.Images)
	}
	assertContentAddressedFiles(t, m.Files, 3) // manifest + config + layer
}

func readBundleManifest(t *testing.T, ls *LowServer, bundleID string) BundleManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, bundleID+".manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m BundleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// assertContentAddressedFiles checks every bundle file lives in the blob store
// under its own sha256.
func assertContentAddressedFiles(t *testing.T, files []ManifestFile, want int) {
	t.Helper()
	if len(files) != want {
		t.Fatalf("bundle files = %+v, want %d", files, want)
	}
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "containers/blobs/sha256/") || !strings.HasSuffix(f.Path, f.SHA256) {
			t.Errorf("file %s is not content-addressed by its sha256", f.Path)
		}
	}
}

func TestCollectContainersSkipsUnfetchable(t *testing.T) {
	img := makeFakeImage("layer-bytes")
	up := fakeContainerRegistry(t, map[string]fakeImage{"library/alpine:3.20": img})
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": up.URL})

	res, err := ls.CollectContainers(context.Background(),
		ContainerCollectRequest{Images: []string{"alpine:3.20", "alpine:no-such-tag"}})
	if err != nil {
		t.Fatalf("CollectContainers: %v", err)
	}
	if res.ExportedModules != 1 || len(res.SkippedModules) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.SkippedModules[0].Module != "docker.io/library/alpine" || res.SkippedModules[0].Version != "no-such-tag" {
		t.Fatalf("skipped = %+v", res.SkippedModules)
	}

	// All images failing must not burn a sequence number.
	if _, err := ls.CollectContainers(context.Background(),
		ContainerCollectRequest{Images: []string{"alpine:also-missing"}}); err == nil {
		t.Fatal("collect of only unfetchable images should fail")
	}
	if seq := ls.peekSequence(streamContainers); seq != 2 {
		t.Fatalf("next sequence = %d, want 2", seq)
	}
}

// TestCollectContainersPrivateRegistry exercises the docker login flow: the
// registry's token endpoint demands HTTP Basic credentials before it issues a
// pull token.
func TestCollectContainersPrivateRegistry(t *testing.T) {
	img := makeFakeImage("private-layer")
	gate := func(r *http.Request) bool {
		user, pass, ok := r.BasicAuth()
		return ok && user == "robot" && pass == "s3cr3t"
	}
	up := fakeContainerRegistryGated(t, gate, map[string]fakeImage{"org/app:v1": img})
	ls, _ := newContainerLowServer(t, map[string]string{"registry.example.com": up.URL})
	ctx := context.Background()
	image := "registry.example.com/org/app:v1"

	// Anonymous pulls are rejected at the token endpoint.
	if _, err := ls.CollectContainers(ctx, ContainerCollectRequest{Images: []string{image}}); err == nil {
		t.Fatal("anonymous pull from a private registry should fail")
	}

	// A wrong login is reported as rejected — and the error never echoes it.
	_, err := ls.CollectContainers(ctx, ContainerCollectRequest{
		Images: []string{image},
		Auth:   &ContainerCollectAuth{Username: "robot", Password: "wrongpass"},
	})
	if err == nil || !strings.Contains(err.Error(), "credentials were not accepted") {
		t.Fatalf("wrong-login error = %v", err)
	}
	if strings.Contains(err.Error(), "wrongpass") {
		t.Fatalf("error must not echo the password: %v", err)
	}

	// The per-pull login authenticates the token fetch.
	res, err := ls.CollectContainers(ctx, ContainerCollectRequest{
		Images: []string{image},
		Auth:   &ContainerCollectAuth{Username: "robot", Password: "s3cr3t"},
	})
	if err != nil || res.ExportedModules != 1 {
		t.Fatalf("authenticated collect = %+v, %v", res, err)
	}

	// Standing ARTIGATE_CONTAINER_AUTH credentials work without request auth —
	// the only credential source scheduled watches have.
	t.Setenv(containerAuthEnv, "registry.example.com=robot:s3cr3t")
	res, err = ls.CollectContainers(ctx, ContainerCollectRequest{Images: []string{image}, Force: true})
	if err != nil || res.ExportedModules != 1 {
		t.Fatalf("env-authenticated collect = %+v, %v", res, err)
	}
}

// TestContainerBasicChallenge covers registries that skip the token dance and
// demand HTTP Basic directly on the registry API.
func TestContainerBasicChallenge(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:hunter2"))
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/app/manifests/x", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("{}"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ls, _ := newContainerLowServer(t, map[string]string{"example.com": srv.URL})
	ref := imageRef{Registry: "example.com", Repository: "org/app"}

	c := ls.newContainerClient()
	c.creds = map[string]registryCredential{"example.com": {Username: "bob", Password: "hunter2"}}
	resp, err := c.get(context.Background(), ref, "manifests/x", "")
	if err != nil {
		t.Fatalf("Basic-authenticated get: %v", err)
	}
	_ = resp.Body.Close()

	// A rejected login is reported without echoing the password.
	c = ls.newContainerClient()
	c.creds = map[string]registryCredential{"example.com": {Username: "bob", Password: "nope"}}
	_, err = c.get(context.Background(), ref, "manifests/x", "")
	if err == nil || !strings.Contains(err.Error(), "were not accepted") || strings.Contains(err.Error(), "nope") {
		t.Fatalf("wrong Basic login error = %v", err)
	}

	// Without a login the challenge is answered with guidance instead.
	c = ls.newContainerClient()
	_, err = c.get(context.Background(), ref, "manifests/x", "")
	if err == nil || !strings.Contains(err.Error(), containerAuthEnv) {
		t.Fatalf("anonymous Basic-challenge error should name %s, got %v", containerAuthEnv, err)
	}
}

func TestCollectContainersRejectsWrongPlatform(t *testing.T) {
	img := makeFakeImage("layer-bytes")
	img.config = []byte(`{"architecture":"arm64","os":"linux"}`)
	// Rebuild the manifest chain around the modified config.
	rebuilt := fakeImage{layer: img.layer, config: img.config}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtDockerManifest,
		"config":        map[string]any{"digest": containerSHA(rebuilt.config), "size": len(rebuilt.config)},
		"layers":        []map[string]any{{"digest": containerSHA(rebuilt.layer), "size": len(rebuilt.layer)}},
	}
	rebuilt.manifest, _ = json.Marshal(manifest)
	rebuilt.manifestDigest = containerSHA(rebuilt.manifest)
	rebuilt.index = rebuilt.manifest // serve the image manifest directly under the tag

	up := fakeContainerRegistry(t, map[string]fakeImage{"library/armthing:1.0": rebuilt})
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": up.URL})

	res, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"armthing:1.0"}})
	if err == nil {
		t.Fatalf("collect of a non-amd64 image should fail, got %+v", res)
	}
	if !strings.Contains(err.Error(), "linux/amd64") {
		t.Fatalf("error should mention the platform restriction: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Full pipeline: low collect -> bundle transfer -> high import -> /v2 serving
// -----------------------------------------------------------------------------

// collectAndImportContainers mirrors two repositories on different fake
// upstream registries into one bundle and imports it on a fresh high server.
func collectAndImportContainers(t *testing.T) (*HighServer, fakeImage, fakeImage) {
	t.Helper()
	alpine := makeFakeImage("layer-alpine")
	app := makeFakeImage("layer-ghcr-app")
	hub := fakeContainerRegistry(t, map[string]fakeImage{"library/alpine:3.20": alpine})
	ghcr := fakeContainerRegistry(t, map[string]fakeImage{"org/app:v1": app})
	ls, priv := newContainerLowServer(t, map[string]string{"docker.io": hub.URL, "ghcr.io": ghcr.URL})

	res, err := ls.CollectContainers(context.Background(),
		ContainerCollectRequest{Images: []string{"alpine:3.20", "ghcr.io/org/app:v1"}})
	if err != nil {
		t.Fatalf("CollectContainers: %v", err)
	}
	if res.ExportedModules != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}

	pub := priv.Public().(ed25519.PublicKey)
	hs := newTestHighServer(t, pub)
	for _, suffix := range bundleSuffixes() {
		name := res.BundleID + suffix
		b, err := os.ReadFile(filepath.Join(ls.cfg.ExportDir, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(hs.cfg.Landing, name), b)
	}
	if _, err := hs.ImportNext(); err != nil {
		t.Fatalf("high import of container bundle failed: %v", err)
	}
	return hs, alpine, app
}

func TestLowToHighContainerPipeline(t *testing.T) {
	hs, alpine, app := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// API version ping.
	if code, _ := httpGet(t, srv.URL+"/v2/"); code != http.StatusOK {
		t.Fatalf("GET /v2/ = %d", code)
	}
	assertManifestByTag(t, srv.URL, alpine)

	// Manifest by digest, blob by digest.
	assertHTTPBody(t, srv.URL+"/v2/docker.io/library/alpine/manifests/"+alpine.manifestDigest, string(alpine.manifest))
	assertHTTPBody(t, srv.URL+"/v2/docker.io/library/alpine/blobs/"+containerSHA(alpine.layer), string(alpine.layer))

	// The second upstream lives in its own namespace.
	assertHTTPBody(t, srv.URL+"/v2/ghcr.io/org/app/manifests/v1", string(app.manifest))

	// Namespaces do not mix: alpine is not visible under ghcr.io, and one
	// repo cannot read another's blobs even though the store is shared.
	assertHTTPStatus(t, srv.URL+"/v2/ghcr.io/library/alpine/manifests/3.20", http.StatusNotFound)
	assertHTTPStatus(t, srv.URL+"/v2/ghcr.io/org/app/blobs/"+containerSHA(alpine.layer), http.StatusNotFound)

	// tags/list and _catalog.
	code, got := httpGet(t, srv.URL+"/v2/docker.io/library/alpine/tags/list")
	if code != http.StatusOK || !strings.Contains(got, `"3.20"`) {
		t.Fatalf("tags/list: %d %q", code, got)
	}
	code, got = httpGet(t, srv.URL+"/v2/_catalog")
	if code != http.StatusOK || !strings.Contains(got, "docker.io/library/alpine") || !strings.Contains(got, "ghcr.io/org/app") {
		t.Fatalf("_catalog: %d %q", code, got)
	}
	assertContainerRegistryReadOnly(t, srv.URL)
}

// assertManifestByTag pulls a manifest by tag and checks the body and the
// Docker-Content-Digest / Content-Type headers docker relies on.
func assertManifestByTag(t *testing.T, base string, img fakeImage) {
	t.Helper()
	resp, err := http.Get(base + "/v2/docker.io/library/alpine/manifests/3.20") //nolint:noctx // test request
	if err != nil {
		t.Fatal(err)
	}
	body := readAllString(t, resp)
	if resp.StatusCode != http.StatusOK || body != string(img.manifest) {
		t.Fatalf("manifest by tag: %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != img.manifestDigest {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, img.manifestDigest)
	}
	if got := resp.Header.Get("Content-Type"); got != mtDockerManifest {
		t.Errorf("Content-Type = %q", got)
	}
}

func assertHTTPBody(t *testing.T, url, want string) {
	t.Helper()
	code, got := httpGet(t, url)
	if code != http.StatusOK || got != want {
		t.Fatalf("GET %s: %d (body match: %v)", url, code, got == want)
	}
}

func assertHTTPStatus(t *testing.T, url string, want int) {
	t.Helper()
	if code, _ := httpGet(t, url); code != want {
		t.Errorf("GET %s = %d, want %d", url, code, want)
	}
}

func assertContainerRegistryReadOnly(t *testing.T, base string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, base+"/v2/docker.io/library/alpine/manifests/3.20", strings.NewReader("{}")) //nolint:noctx // test request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT manifest = %d, want 405", resp.StatusCode)
	}
}

func readAllString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertContainerLayers checks the layers box built from the fake image's
// config history: the ADD step is a filesystem layer carrying the stored
// layer's size and digest; the CMD step is metadata-only with no layer.
func assertContainerLayers(t *testing.T, layers []UIImageLayer, wantLayerDigest string) {
	t.Helper()
	if len(layers) != 2 {
		t.Fatalf("detail layers = %d, want 2: %+v", len(layers), layers)
	}
	fsLayer := layers[0]
	if fsLayer.Command != "ADD file:abc123 in /" || fsLayer.Empty || fsLayer.Size == "" || fsLayer.Digest != wantLayerDigest {
		t.Errorf("filesystem layer = %+v", fsLayer)
	}
	metaLayer := layers[1]
	if metaLayer.Command != `CMD ["/bin/sh"]` || !metaLayer.Empty || metaLayer.Size != "" {
		t.Errorf("metadata layer = %+v", metaLayer)
	}
}

func TestCleanDockerfileCommand(t *testing.T) {
	tests := []struct{ in, want string }{
		{`/bin/sh -c #(nop)  CMD ["/bin/sh"]`, `CMD ["/bin/sh"]`},
		{"/bin/sh -c #(nop) ADD file:abc in / ", "ADD file:abc in /"},
		{"/bin/sh -c apk add --no-cache curl", "RUN apk add --no-cache curl"},
		{"RUN go build ./... # buildkit", "RUN go build ./... # buildkit"},
		{"", "(metadata)"},
	}
	for _, tt := range tests {
		if got := cleanDockerfileCommand(tt.in); got != tt.want {
			t.Errorf("cleanDockerfileCommand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestContainerDashboardAndDetail(t *testing.T) {
	hs, alpine, _ := collectAndImportContainers(t)
	srv := httptest.NewServer(hs)
	defer srv.Close()

	// Tree: registries are separate top-level branches.
	code, got := httpGet(t, srv.URL+"/ui/api/tree?eco=containers&path=")
	if code != http.StatusOK || !strings.Contains(got, `"docker.io"`) || !strings.Contains(got, `"ghcr.io"`) {
		t.Fatalf("containers tree root: %d %q", code, got)
	}
	// Detail for a tag leaf, including the host-relative pull reference the
	// dashboard turns into a prominent click-to-copy button (the full
	// <host>/<registry>/<repo>:<tag> a client pulls; the host is prepended
	// client-side, so the value here is host-relative).
	code, got = httpGet(t, srv.URL+"/ui/api/detail?eco=containers&path="+
		"docker.io%2Flibrary%2Falpine%403.20")
	if code != http.StatusOK || !strings.Contains(got, "linux/amd64") {
		t.Fatalf("container detail: %d %q", code, got)
	}
	var detail UIDetail
	if err := json.Unmarshal([]byte(got), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.CopyRef != "docker.io/library/alpine:3.20" {
		t.Fatalf("detail copy_ref = %q, want docker.io/library/alpine:3.20", detail.CopyRef)
	}
	assertContainerLayers(t, detail.Layers, containerSHA(alpine.layer))
	// Repos for the "Set me up" guide.
	code, got = httpGet(t, srv.URL+"/ui/api/repos?eco=containers")
	if code != http.StatusOK || !strings.Contains(got, "docker.io/library/alpine") {
		t.Fatalf("container repos: %d %q", code, got)
	}
}

func TestLooksLikeVersionConstraint(t *testing.T) {
	constraints := []string{"1.26.x", "1.x", "2.x.x", "1.26.*", "x", "*", "<2.0.0", ">= 1.24, < 2.0", "~> 1.26", "!= 1.0.0"}
	for _, s := range constraints {
		if !looksLikeVersionConstraint(s) {
			t.Errorf("%q should be a constraint", s)
		}
	}
	exactTags := []string{"", "latest", "3.20", "1.26.3", "v1.26.3", "1.26.3-alpine", "bookworm", "xenial"}
	for _, s := range exactTags {
		if looksLikeVersionConstraint(s) {
			t.Errorf("%q should be an exact tag", s)
		}
	}
}

func TestNormalizeVersionConstraint(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.26.x", ">= 1.26.0, < 1.27.0"},
		{"1.26.*", ">= 1.26.0, < 1.27.0"},
		{"1.x", ">= 1.0.0, < 2.0.0"},
		{"2.x.x", ">= 2.0.0, < 3.0.0"},
		{"v1.26.x", ">= 1.26.0, < 1.27.0"},
		{"x", ">= 0"},
		{"*", ">= 0"},
		{"< 2.x.x", "< 2.0.0"},
		{"<2.0.0", "<2.0.0"},
		{">= 1.24, < 2.0", ">= 1.24, < 2.0"},
	}
	for _, tt := range tests {
		if got := normalizeVersionConstraint(tt.in); got != tt.want {
			t.Errorf("normalizeVersionConstraint(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if _, err := parseVersionConstraint(tt.in); err != nil {
			t.Errorf("parseVersionConstraint(%q): %v", tt.in, err)
		}
	}
	if _, err := parseVersionConstraint("<notaversion"); err == nil {
		t.Error("garbage constraint should be rejected")
	}
}

func TestParseImageRefConstraints(t *testing.T) {
	ref, err := parseImageRef("golang:1.26.x")
	if err != nil {
		t.Fatal(err)
	}
	want := imageRef{Registry: "docker.io", Repository: "library/golang", Constraint: "1.26.x"}
	if ref != want {
		t.Fatalf("parseImageRef(golang:1.26.x) = %+v, want %+v", ref, want)
	}
	ref, err = parseImageRef("ghcr.io/org/app:>= 1.24, < 2.0")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Constraint != ">= 1.24, < 2.0" || ref.Tag != "" {
		t.Fatalf("operator constraint parse = %+v", ref)
	}
	// A digest cannot be combined with a constraint, and garbage operators fail.
	if _, err := parseImageRef("golang:1.26.x@sha256:" + strings.Repeat("ab", 32)); err == nil {
		t.Error("digest + constraint should be rejected")
	}
	if _, err := parseImageRef("golang:<notaversion"); err == nil {
		t.Error("invalid constraint should be rejected")
	}
}

// TestResolveConstraintTag exercises resolution against a fake registry's tag
// list: wildcard match, upper-bound match, variant-tag exclusion, and the
// no-match error.
func TestResolveConstraintTag(t *testing.T) {
	img := makeFakeImage("layer-golang")
	tags := map[string][]string{"library/golang": {
		"latest", "bookworm", "1", "1.25", "1.26", "1.26.2", "1.26.3", "1.26.4-alpine", "2.0.1", "2.1.0-rc1",
	}}
	up := fakeContainerRegistry(t, map[string]fakeImage{"library/golang:1.26.3": img}, tags)
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": up.URL})
	client := ls.newContainerClient()

	tests := []struct{ constraint, want string }{
		{"1.26.x", "1.26.3"}, // 1.26.4-alpine is a variant and must not win
		{"<2.0.0", "1.26.3"},
		{"1.x", "1.26.3"},
		{"*", "2.0.1"},
		{">= 2.0", "2.0.1"},
	}
	for _, tt := range tests {
		ref, err := parseImageRef("golang:" + tt.constraint)
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.resolveConstraintTag(context.Background(), ref)
		if err != nil {
			t.Errorf("resolve %q: %v", tt.constraint, err)
			continue
		}
		if got != tt.want {
			t.Errorf("resolve %q = %q, want %q", tt.constraint, got, tt.want)
		}
	}

	ref, _ := parseImageRef("golang:3.x")
	if _, err := client.resolveConstraintTag(context.Background(), ref); err == nil {
		t.Error("constraint with no matching tag should fail")
	}
}

// TestListUpstreamTagsPagination follows a Link-header paginated tags/list.
func TestListUpstreamTagsPagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/org/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</v2/org/app/tags/list?last=1.1.0&n=1000>; rel="next"`)
			writeJSON(w, map[string]any{"name": "org/app", "tags": []string{"1.0.0", "1.1.0"}})
			return
		}
		writeJSON(w, map[string]any{"name": "org/app", "tags": []string{"1.2.0"}})
	})
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	ls, _ := newContainerLowServer(t, map[string]string{"example.com": up.URL})
	client := ls.newContainerClient()

	ref, err := parseImageRef("example.com/org/app:1.x")
	if err != nil {
		t.Fatal(err)
	}
	tags, err := client.listUpstreamTags(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 3 || tags[2] != "1.2.0" {
		t.Fatalf("paginated tags = %v", tags)
	}
	if got, err := client.resolveConstraintTag(context.Background(), ref); err != nil || got != "1.2.0" {
		t.Fatalf("resolve across pages = %q, %v", got, err)
	}
}

// TestCollectContainersWithConstraint runs a whole collect from a constraint
// spec and checks the bundle records the resolved concrete tag.
func TestCollectContainersWithConstraint(t *testing.T) {
	img := makeFakeImage("layer-golang")
	tags := map[string][]string{"library/golang": {"latest", "1.25", "1.26.3", "1.26.4-alpine", "2.0.1"}}
	up := fakeContainerRegistry(t, map[string]fakeImage{"library/golang:1.26.3": img}, tags)
	ls, _ := newContainerLowServer(t, map[string]string{"docker.io": up.URL})

	res, err := ls.CollectContainers(context.Background(), ContainerCollectRequest{Images: []string{"golang:1.26.x"}})
	if err != nil {
		t.Fatalf("CollectContainers: %v", err)
	}
	m := readBundleManifest(t, ls, res.BundleID)
	if len(m.Containers.Repos) != 1 || len(m.Containers.Repos[0].Images) != 1 {
		t.Fatalf("manifest repos = %+v", m.Containers)
	}
	got := m.Containers.Repos[0].Images[0]
	if got.Tag != "1.26.3" || got.Digest != img.manifestDigest {
		t.Fatalf("resolved image = %+v, want tag 1.26.3", got)
	}
}

func TestValidateContainerRepos(t *testing.T) {
	digest := containerSHA([]byte("m"))
	blob := containerSHA([]byte("b"))
	repos := []ContainerRepo{{
		Registry:   "docker.io",
		Repository: "library/alpine",
		Images: []ContainerImage{{
			Tag: "3.20", Digest: digest, MediaType: mtDockerManifest,
			Blobs: []ContainerBlob{{Digest: blob, Size: 1}},
		}},
	}}
	files := []ManifestFile{
		{Path: containerBlobRel(digest), SHA256: strings.TrimPrefix(digest, "sha256:"), Size: 1},
		{Path: containerBlobRel(blob), SHA256: strings.TrimPrefix(blob, "sha256:"), Size: 1},
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.Path] = true
	}
	if err := validateContainerRepos(repos, seen, files); err != nil {
		t.Fatalf("valid repos rejected: %v", err)
	}

	// A blob missing from the file set is rejected.
	if err := validateContainerRepos(repos, map[string]bool{files[0].Path: true}, files[:1]); err == nil {
		t.Error("missing blob file should be rejected")
	}
	// A file whose sha256 does not match its content-addressed path is rejected.
	tampered := []ManifestFile{files[0], {Path: files[1].Path, SHA256: strings.Repeat("00", 32), Size: 1}}
	if err := validateContainerRepos(repos, seen, tampered); err == nil {
		t.Error("mismatched blob sha256 should be rejected")
	}
}
