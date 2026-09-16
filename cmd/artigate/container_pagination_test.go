package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func paginationTestRepo(t *testing.T, annotationBytes int) (*HighServer, string, []string) {
	t.Helper()
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	fix := makeFakeImage("pagination")
	img := artifactStoreStageImage(t, hs, fix, "a")
	var digests []string
	for i := range 3 {
		artifactType := "application/test+json"
		if annotationBytes == 0 && i == 2 {
			artifactType = "application/other"
		}
		art := artifactStoreWithSubject(t,
			makeFakeArtifact(artifactType, fmt.Sprintf("pagination-%d", i), artifactType, map[string]string{"large": strings.Repeat("x", annotationBytes)}),
			ociDescriptor{MediaType: img.MediaType, Digest: img.Digest, Size: img.Size})
		img.Artifacts = append(img.Artifacts, artifactStoreStageArtifact(t, hs, art, img.Digest, ""))
		if artifactType == "application/test+json" {
			digests = append(digests, art.digest)
		}
	}
	legacy := makeFakeArtifact("application/legacy", "legacy-tag", "application/legacy", nil)
	img.Artifacts = append(img.Artifacts, artifactStoreStageArtifact(t, hs, legacy, img.Digest, "legacy"))
	images := []ContainerImage{img}
	for _, tag := range []string{"A", "b", "Z"} {
		other := img
		other.Tag = tag
		other.Artifacts = nil
		images = append(images, other)
	}
	artifactStoreMerge(t, hs, images...)
	slices.Sort(digests)
	return hs, img.Digest, digests
}

func paginationGet(t *testing.T, hs *HighServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	hs.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("incorrect Content-Length: %v", rec.Header())
	}
	return rec
}

func paginationNext(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	link := rec.Header().Get("Link")
	if link == "" {
		return ""
	}
	if !strings.HasPrefix(link, "</v2/") || !strings.HasSuffix(link, `>; rel="next"`) {
		t.Fatalf("unsafe or malformed continuation: %s", link)
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "<"), `>; rel="next"`)
}

func TestContainerTagPagination(t *testing.T) {
	hs, _, _ := paginationTestRepo(t, 0)
	const base = "/v2/" + artifactStoreRepo + "/tags/list"
	want := []string{"A", "a", "b", "legacy", "Z"}
	var got []string
	for next, pages := base+"?n=2", 0; next != ""; pages++ {
		if pages > len(want) {
			t.Fatal("pagination loop")
		}
		rec := paginationGet(t, hs, next)
		var listing struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
			t.Fatal(err)
		}
		if listing.Name != artifactStoreRepo || len(listing.Tags) > 2 {
			t.Fatalf("unexpected tag page: %+v", listing)
		}
		got = append(got, listing.Tags...)
		next = paginationNext(t, rec)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tags lost, duplicated or reordered: %v, want %v", got, want)
	}
	for _, tc := range []struct{ name, query, want string }{
		{"zero", "?n=0", `"tags":[]`},
		{"absent cursor", "?n=2&last=bb", `"tags":["legacy","Z"]`},
		{"past end", "?last=zz", `"tags":[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := paginationGet(t, hs, base+tc.query)
			if !strings.Contains(rec.Body.String(), tc.want) || paginationNext(t, rec) != "" {
				t.Fatalf("unexpected last page: %s %v", rec.Body.String(), rec.Header())
			}
		})
	}
}

func TestContainerTagPaginationDefaultLimitAndDuplicates(t *testing.T) {
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	img := artifactStoreStageImage(t, hs, makeFakeImage("many-tags"), "")
	images := make([]ContainerImage, containerRegistryPageSize+1)
	for i := range images {
		images[i] = img
		images[i].Tag = fmt.Sprintf("tag-%04d", i)
	}
	artifactStoreMerge(t, hs, images...)
	const base = "/v2/" + artifactStoreRepo + "/tags/list"
	for _, query := range []string{"", "?n=18446744073709551615"} {
		rec := paginationGet(t, hs, base+query)
		var listing struct{ Tags []string }
		if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
			t.Fatal(err)
		}
		if len(listing.Tags) != containerRegistryPageSize || paginationNext(t, rec) == "" {
			t.Fatalf("tag page not bounded: count=%d headers=%v", len(listing.Tags), rec.Header())
		}
	}
	// An image and artifact may both record a mutable tag; serving resolves
	// one current reference, and enumeration must return that tag only once.
	art := makeFakeArtifact("application/test", "same-tag", "application/test", nil)
	images[0].Artifacts = []ContainerArtifact{artifactStoreStageArtifact(t, hs, art, img.Digest, images[0].Tag)}
	artifactStoreMerge(t, hs, images[0])
	rec := paginationGet(t, hs, base+"?n=2")
	if strings.Count(rec.Body.String(), images[0].Tag) != 1 {
		t.Fatalf("duplicate current tag: %s", rec.Body.String())
	}
}

func TestContainerReferrerServingPagination(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(fmt.Sprintf("large=%t", large), func(t *testing.T) {
			annotationBytes := 0
			if large {
				annotationBytes = maxServedManifestBytes / 2
			}
			hs, subject, want := paginationTestRepo(t, annotationBytes)
			path := "/v2/" + artifactStoreRepo + "/referrers/" + subject
			query := url.Values{"artifactType": {"application/test+json"}}
			if !large {
				query.Set("n", "1")
			}
			var got []string
			pages := 0
			for next := path + "?" + query.Encode(); next != ""; pages++ {
				if pages > len(want) {
					t.Fatal("referrer pagination loop")
				}
				rec := paginationGet(t, hs, next)
				if rec.Body.Len() > maxServedManifestBytes || rec.Header().Get("OCI-Filters-Applied") != "artifactType" {
					t.Fatalf("unbounded or unfiltered page: bytes=%d headers=%v", rec.Body.Len(), rec.Header())
				}
				var index ociReferrersIndex
				if err := json.Unmarshal(rec.Body.Bytes(), &index); err != nil {
					t.Fatal(err)
				}
				for _, desc := range index.Manifests {
					if desc.ArtifactType != "application/test+json" || len(desc.Annotations["large"]) != annotationBytes {
						t.Fatal("filter or annotation lost on paginated descriptor")
					}
					got = append(got, desc.Digest)
				}
				next = paginationNext(t, rec)
			}
			if pages < 2 || !slices.Equal(got, want) {
				t.Fatalf("referrer pages=%d digests=%v, want %v", pages, got, want)
			}
			// Exercise the actual low-side page follower against high-side links.
			up := httptest.NewServer(hs)
			t.Cleanup(up.Close)
			client := (&LowServer{containerRegistryBases: map[string]string{"mirror.test": up.URL}}).newContainerClient()
			refs := client.fetchReferrers(t.Context(), imageRef{Registry: "mirror.test", Repository: artifactStoreRepo}, subject)
			if len(refs) != 3 {
				t.Fatalf("low-side discovery lost referrers: got %d, want 3", len(refs))
			}
		})
	}
}

func TestContainerPaginationInvalidParametersAndHead(t *testing.T) {
	hs, subject, _ := paginationTestRepo(t, 0)
	for _, endpoint := range []string{"tags/list", "referrers/" + subject} {
		base := "/v2/" + artifactStoreRepo + "/" + endpoint
		for _, query := range []string{"n=-1", "n=oops", "n=", "n=1&n=2", "last=a&last=b", "last=bad%20cursor", "n=%zz", "artifactType=a&artifactType=b"} {
			t.Run(endpoint+"/"+query, func(t *testing.T) {
				rec := httptest.NewRecorder()
				hs.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base+"?"+query, nil))
				if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"errors"`) {
					t.Fatalf("invalid query accepted: %d %s", rec.Code, rec.Body.String())
				}
			})
		}
		get := paginationGet(t, hs, base+"?n=1")
		head := httptest.NewRecorder()
		hs.ServeHTTP(head, httptest.NewRequest(http.MethodHead, base+"?n=1", nil))
		if head.Code != http.StatusOK || head.Body.Len() != 0 {
			t.Fatalf("HEAD returned a body or error: %d %s", head.Code, head.Body.String())
		}
		for _, key := range []string{"Content-Type", "Content-Length", "Link"} {
			if head.Header().Get(key) != get.Header().Get(key) {
				t.Errorf("HEAD %s differs from GET", key)
			}
		}
	}
}

func TestContainerReferrerDescriptorTooLarge(t *testing.T) {
	descriptor := discoveryDescriptor("huge")
	descriptor.Annotations = map[string]string{"huge": strings.Repeat("x", maxServedManifestBytes)}
	if _, _, err := paginateContainerReferrers([]ociDescriptor{descriptor}, containerPagination{Limit: 1}); err == nil {
		t.Fatal("oversized descriptor must fail explicitly")
	}
}
