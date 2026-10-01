package main

import (
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func assertRepositoryDownload(t *testing.T, resp *http.Response, name string) {
	t.Helper()
	disposition, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || params["filename"] != name {
		t.Errorf("Content-Disposition = %q, error = %v", resp.Header.Get("Content-Disposition"), err)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestRepositoryFileDownloads(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body, contentType string
	}{
		{"metadata.xml", `<svg xmlns="http://www.w3.org/2000/svg"><script>document.title="fixture"</script></svg>`, ""},
		{"document.svg", `<svg xmlns="http://www.w3.org/2000/svg"/>`, ""},
		{`résumé "quoted".html`, "<html><script>document.title='fixture'</script></html>", ""},
		{"extensionless", "<html><script>document.title='fixture'</script></html>", ""},
		{"package.nuspec", "<package><metadata/></package>", "application/xml"},
		{"module.info", `{"Version":"v1.0.0"}`, "application/json; charset=utf-8"},
		{"module.mod", "module example.com/test\n", "text/plain; charset=utf-8"},
		{"package.zip", "archive bytes", "application/zip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			abs := filepath.Join(t.TempDir(), tc.name)
			writeFile(t, abs, []byte(tc.body))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(tc.name, ".nuspec") {
					w.Header().Set("Content-Type", tc.contentType)
				}
				serveFile(w, r, abs)
			}))
			defer server.Close()
			endpoint := server.URL + "/repo/" + url.PathEscape(tc.name)
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				req, err := http.NewRequestWithContext(t.Context(), method, endpoint, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK {
					t.Fatalf("%s: status=%d err=%v", method, resp.StatusCode, err)
				}
				assertRepositoryDownload(t, resp, tc.name)
				if tc.contentType != "" && resp.Header.Get("Content-Type") != tc.contentType {
					t.Errorf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), tc.contentType)
				}
				want := tc.body
				if method == http.MethodHead {
					want = ""
				}
				if string(body) != want {
					t.Errorf("%s body = %q, want %q", method, body, want)
				}
			}
		})
	}
}
