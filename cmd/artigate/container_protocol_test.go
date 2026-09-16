package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestContainerTokenRealmQuery(t *testing.T) {
	for _, tc := range []struct {
		name       string
		realmQuery string
		challenge  string
		wantQuery  url.Values
	}{
		{
			name: "existing tenant and default scope", realmQuery: "tenant=example&audience=one&audience=two", challenge: `,service="registry.test"`,
			wantQuery: url.Values{"tenant": {"example"}, "audience": {"one", "two"}, "service": {"registry.test"}, "scope": {"repository:org/app:pull"}},
		},
		{
			name: "challenge overrides scope and service", realmQuery: "tenant=example&scope=old&service=old", challenge: `,service="registry.test",scope="repository:org/other:pull"`,
			wantQuery: url.Values{"tenant": {"example"}, "service": {"registry.test"}, "scope": {"repository:org/other:pull"}},
		},
		{
			name: "realm without query", challenge: `,service="registry.test"`,
			wantQuery: url.Values{"service": {"registry.test"}, "scope": {"repository:org/app:pull"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !reflect.DeepEqual(r.URL.Query(), tc.wantQuery) {
					t.Errorf("token query = %v, want %v", r.URL.Query(), tc.wantQuery)
					http.Error(w, "unexpected query", http.StatusBadRequest)
					return
				}
				user, password, ok := r.BasicAuth()
				if !ok || user != "test-user" || password != "test-password" {
					t.Errorf("missing expected token endpoint credentials")
				}
				_, _ = w.Write([]byte(`{"token":"test-token"}`))
			}))
			t.Cleanup(up.Close)
			realm := up.URL + "/token"
			if tc.realmQuery != "" {
				realm += "?" + tc.realmQuery
			}
			client := &containerClient{}
			token, err := client.fetchToken(t.Context(), `Bearer realm="`+realm+`"`+tc.challenge, "org/app", &registryCredential{Username: "test-user", Password: "test-password"})
			if err != nil || token != "test-token" {
				t.Fatalf("fetchToken = %q, %v", token, err)
			}
		})
	}
}

func TestContainerManifestSizeLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withIndex  bool
		largeChild bool
		size       int
	}{
		{name: "manifest at limit", size: maxServedManifestBytes},
		{name: "manifest over limit", size: maxServedManifestBytes + 1},
		{name: "index at limit", withIndex: true, size: maxServedManifestBytes},
		{name: "index over limit", withIndex: true, size: maxServedManifestBytes + 1},
		{name: "index child at limit", withIndex: true, largeChild: true, size: maxServedManifestBytes},
		{name: "index child over limit", withIndex: true, largeChild: true, size: maxServedManifestBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fix := makeFakeImage("manifest-size-test")
			pad := func(body []byte) []byte {
				return append(body, bytes.Repeat([]byte(" "), tc.size-len(body))...)
			}
			body, mediaType := pad(fix.manifest), mtDockerManifest
			if tc.withIndex {
				mediaType = mtDockerList
				if tc.largeChild {
					fix.manifest = body
					fix.manifestDigest = containerSHA(body)
					index := map[string]any{
						"schemaVersion": 2,
						"mediaType":     mtDockerList,
						"manifests": []ociDescriptor{{
							MediaType: mtDockerManifest, Digest: fix.manifestDigest, Size: int64(len(body)),
							Platform: &ociPlatform{OS: "linux", Architecture: "amd64"},
						}},
					}
					body, _ = json.Marshal(index)
				} else {
					body = pad(fix.index)
				}
			}
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/org/app/manifests/latest":
					w.Header().Set("Content-Type", mediaType)
					_, _ = w.Write(body)
				case "/v2/org/app/manifests/" + fix.manifestDigest:
					w.Header().Set("Content-Type", mtDockerManifest)
					_, _ = w.Write(fix.manifest)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(up.Close)
			ls := &LowServer{containerRegistryBases: map[string]string{"registry.test": up.URL}}
			ref := imageRef{Registry: "registry.test", Repository: "org/app", Tag: "latest"}
			resolved, err := ls.newContainerClient().fetchContainerManifest(t.Context(), ref)
			if tc.size > maxServedManifestBytes {
				if err == nil || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("oversized manifest must be rejected explicitly, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.withIndex {
				if !bytes.Equal(resolved.Index, body) || resolved.IndexDigest != containerSHA(body) {
					t.Fatal("index bytes or digest changed")
				}
				if !bytes.Equal(resolved.Manifest, fix.manifest) || resolved.Digest != fix.manifestDigest {
					t.Fatal("child manifest bytes or digest changed")
				}
			} else if !bytes.Equal(resolved.Manifest, body) || resolved.Digest != containerSHA(body) {
				t.Fatal("manifest bytes or digest changed")
			}
		})
	}
}

func TestHFManifestCollectionSizeLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{name: "at limit", size: maxServedManifestBytes},
		{name: "over limit", size: maxServedManifestBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fix := makeFakeHFModel("q4", "manifest-size-test")
			body := append(bytes.Clone(fix.manifest), bytes.Repeat([]byte(" "), tc.size-len(fix.manifest))...)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", mtDockerManifest)
				_, _ = w.Write(body)
			}))
			t.Cleanup(up.Close)
			client := &hfClient{base: up.URL}
			got, _, _, digest, err := client.fetchHFManifest(t.Context(), hfRef{Org: "org", Name: "model", Tag: "q4"})
			if tc.size > maxServedManifestBytes {
				if err == nil || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("oversized manifest must be rejected explicitly, got %v", err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, body) || digest != containerSHA(body) {
				t.Fatalf("boundary manifest bytes/digest not preserved: %v", err)
			}
		})
	}
}

func TestContainerRegistryRouteWords(t *testing.T) {
	for _, repository := range []string{"library/audit", "library/manifests/audit", "library/blobs/audit", "library/referrers/audit", "library/tags/list"} {
		t.Run(repository, func(t *testing.T) {
			pub, _ := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			fix := makeFakeImage("route-name-audit")
			for _, body := range [][]byte{fix.manifest, fix.config, fix.layer} {
				covR2WriteFile(t, hs.containerBlobPath(containerSHA(body)), body)
			}
			img := ContainerImage{Tag: "latest", Digest: fix.manifestDigest, MediaType: mtDockerManifest, Size: int64(len(fix.manifest)), Blobs: []ContainerBlob{{Digest: containerSHA(fix.config), Size: int64(len(fix.config))}, {Digest: containerSHA(fix.layer), Size: int64(len(fix.layer))}}}
			if err := hs.mergeContainerRepo(ContainerRepo{Registry: "docker.io", Repository: repository, Images: []ContainerImage{img}}); err != nil {
				t.Fatal(err)
			}
			request := func(method, resource, byteRange string) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(method, "/v2/docker.io/"+repository+"/"+resource, nil)
				if byteRange != "" {
					req.Header.Set("Range", byteRange)
				}
				rec := httptest.NewRecorder()
				hs.ServeHTTP(rec, req)
				return rec
			}
			for _, tc := range []struct {
				resource string
				body     []byte
				digest   string
			}{
				{resource: "manifests/latest", body: fix.manifest, digest: fix.manifestDigest},
				{resource: "manifests/" + fix.manifestDigest, body: fix.manifest, digest: fix.manifestDigest},
				{resource: "blobs/" + containerSHA(fix.layer), body: fix.layer, digest: containerSHA(fix.layer)},
			} {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					rec := request(method, tc.resource, "")
					if rec.Code != http.StatusOK || rec.Header().Get("Docker-Content-Digest") != tc.digest || rec.Header().Get("Content-Length") != fmt.Sprint(len(tc.body)) {
						t.Errorf("%s %s = %d %v", method, tc.resource, rec.Code, rec.Header())
					}
					if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), tc.body) || method == http.MethodHead && rec.Body.Len() != 0 {
						t.Errorf("%s %s returned unexpected body", method, tc.resource)
					}
				}
			}
			rangeResponse := request(http.MethodGet, "blobs/"+containerSHA(fix.layer), "bytes=2-5")
			if rangeResponse.Code != http.StatusPartialContent || !bytes.Equal(rangeResponse.Body.Bytes(), fix.layer[2:6]) || rangeResponse.Header().Get("Content-Range") != fmt.Sprintf("bytes 2-5/%d", len(fix.layer)) {
				t.Errorf("blob range request = %d %v %q", rangeResponse.Code, rangeResponse.Header(), rangeResponse.Body.String())
			}
			refs := request(http.MethodGet, "referrers/"+fix.manifestDigest, "")
			var index ociReferrersIndex
			if err := json.Unmarshal(refs.Body.Bytes(), &index); err != nil || refs.Code != http.StatusOK || len(index.Manifests) != 0 {
				t.Errorf("referrers response = %d %s, %v", refs.Code, refs.Body.String(), err)
			}
			tags := request(http.MethodGet, "tags/list", "")
			var listing struct {
				Tags []string `json:"tags"`
			}
			if err := json.Unmarshal(tags.Body.Bytes(), &listing); err != nil || tags.Code != http.StatusOK || !reflect.DeepEqual(listing.Tags, []string{"latest"}) {
				t.Errorf("tags response = %d %s, %v", tags.Code, tags.Body.String(), err)
			}
		})
	}
}
