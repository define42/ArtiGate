package main

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNugetRejectsUnexpectedNuspecRoot(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, root string }{
		{"SVG", `svg xmlns="http://www.w3.org/2000/svg"`},
		{"XHTML", `html xmlns="http://www.w3.org/1999/xhtml"`},
		{"wrong root", "document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root, _, _ := strings.Cut(tc.root, " ")
			raw := []byte("<" + tc.root + "><metadata><id>Review.Xml</id><version>1.0.0</version></metadata></" + root + ">")
			if _, err := parseNuspec(raw); err == nil {
				t.Fatal("accepted nuspec without a package root")
			}
			up := fakeNugetService(t)
			up.add("Review.Xml", "1.0.0", nugetTestZip(t, nugetTestZipEntry{"Review.Xml.nuspec", raw}))
			low, _ := nugetTestLowServer(t, up.url())
			if _, err := low.CollectNuget(t.Context(), NugetCollectRequest{Packages: []string{"Review.Xml@1.0.0"}}); err == nil {
				t.Fatal("collected a package with an invalid nuspec root")
			}
			if seq := low.peekSequence(streamNuget); seq != 1 {
				t.Fatalf("failed collect advanced sequence to %d", seq)
			}
		})
	}
}

func TestNugetNuspecDownload(t *testing.T) {
	t.Parallel()
	const id = "Review.Xml"
	raw := nugetTestNuspec(id, "1.0.0")
	up := fakeNugetService(t)
	up.add(id, "1.0.0", nugetTestZip(t, nugetTestZipEntry{id + ".nuspec", raw}))
	low, priv := nugetTestLowServer(t, up.url())
	exported, err := low.CollectNuget(t.Context(), NugetCollectRequest{Packages: []string{id + "@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	assertBundleSigned(t, low.cfg.ExportDir, exported.BundleID, priv.Public().(ed25519.PublicKey))
	high := newTestHighServer(t, priv.Public().(ed25519.PublicKey))
	transferAptBundle(t, low, high, exported.BundleID)
	if imported, err := high.ImportNext(); err != nil || !imported.Imported || len(imported.RejectedBundles) != 0 {
		t.Fatalf("signed import = %+v, %v", imported, err)
	}
	server := httptest.NewServer(high)
	defer server.Close()
	endpoint := server.URL + "/nuget/v3-flatcontainer/review.xml/1.0.0/review.xml.nuspec"
	for _, tc := range []struct {
		name, method, byteRange string
		status                  int
		want                    []byte
	}{
		{"GET", http.MethodGet, "", http.StatusOK, raw},
		{"HEAD", http.MethodHead, "", http.StatusOK, nil},
		{"range", http.MethodGet, "bytes=0-15", http.StatusPartialContent, raw[:16]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.byteRange != "" {
				req.Header.Set("Range", tc.byteRange)
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != tc.status || !bytes.Equal(body, tc.want) {
				t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, body, err)
			}
			assertRepositoryDownload(t, resp, "review.xml.nuspec")
			if got := resp.Header.Get("Content-Type"); got != "application/xml" {
				t.Errorf("Content-Type = %q, want application/xml", got)
			}
		})
	}

	// Existing mirrors may already contain metadata accepted by older versions.
	// Download protection must cover these bytes without requiring a re-import.
	legacy := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>document.title="fixture"</script></svg>`)
	writeFile(t, filepath.Join(high.nugetMetadataDir(), "review.xml", "1.0.0.nuspec"), legacy)
	resp, err := server.Client().Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(body, legacy) {
		t.Fatalf("legacy response: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
	assertRepositoryDownload(t, resp, "review.xml.nuspec")
}
