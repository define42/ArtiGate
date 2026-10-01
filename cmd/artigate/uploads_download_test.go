package main

import (
	"crypto/ed25519"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestUploadsDownloadAttachments(t *testing.T) {
	low, key := newAptLowServer(t)
	high := newTestHighServer(t, key.Public().(ed25519.PublicKey))
	files := []uploadPair{
		{"active.html", "<script>window.uploadExecuted = true</script>"},
		{"active.svg", `<svg xmlns="http://www.w3.org/2000/svg"><script>window.uploadExecuted = true</script></svg>`},
		{"index.html", "<script>window.indexExecuted = true</script>"},
		{"extensionless", "<html><script>window.sniffed = true</script></html>"},
		{`résumé "quoted".html`, "<script>window.namedUpload = true</script>"},
		{"archive.bin", "0123456789abcdef"},
	}
	exported := collectUpload(t, low, "downloads", files)
	importNextUploads(t, low, high, exported.BundleID)
	server := httptest.NewServer(csrfGuard(high))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, file := range files {
		t.Run(file.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(method, func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), method, server.URL+"/uploads/downloads/"+url.PathEscape(file.name), nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status = %d, want 200", resp.StatusCode)
					}
					assertUploadAttachment(t, resp, file.name)
					if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(file.content)) {
						t.Errorf("content length = %q, want %d", got, len(file.content))
					}
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					want := file.content
					if method == http.MethodHead {
						want = ""
					}
					if string(body) != want {
						t.Errorf("body = %q, want %q", body, want)
					}
				})
			}
		})
	}
}

func assertUploadAttachment(t *testing.T, resp *http.Response, name string) {
	t.Helper()
	if got := resp.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("content type = %q", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("content type options = %q", got)
	}
	disposition, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || params["filename"] != name {
		t.Errorf("content disposition = %q, error = %v", resp.Header.Get("Content-Disposition"), err)
	}
}

func TestUploadsDownloadRangeAndConditional(t *testing.T) {
	low, key := newAptLowServer(t)
	high := newTestHighServer(t, key.Public().(ed25519.PublicKey))
	const payload = "0123456789abcdef"
	exported := collectUpload(t, low, "downloads", []uploadPair{{"range.html", payload}})
	importNextUploads(t, low, high, exported.BundleID)
	server := httptest.NewServer(high)
	defer server.Close()
	endpoint := server.URL + "/uploads/downloads/range.html"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=4-9")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertUploadAttachment(t, resp, "range.html")
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusPartialContent || string(body) != payload[4:10] {
		t.Fatalf("range response: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
	if got := resp.Header.Get("Content-Range"); got != "bytes 4-9/16" {
		t.Errorf("content range = %q", got)
	}
	modified := resp.Header.Get("Last-Modified")
	if modified == "" {
		t.Fatal("missing Last-Modified")
	}
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("If-Modified-Since", modified)
	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("conditional response status = %d, want 304", resp.StatusCode)
	}
	for _, suffix := range []string{"/uploads/downloads", "/uploads/downloads/", "/uploads/downloads/missing.html"} {
		t.Run(suffix, func(t *testing.T) {
			resp, err := server.Client().Get(server.URL + suffix)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
		})
	}
}
