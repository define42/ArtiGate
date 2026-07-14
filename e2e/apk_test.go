//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"
)

// The apk collector mirrors whole branch/repository/architecture selections —
// Alpine's real repositories are gigabytes, far beyond a CI run. This test
// keeps everything else real instead: it fetches ONE real package and its
// verbatim APKINDEX stanza from the real Alpine CDN, serves them as a
// miniature one-package repository, mirrors that through the real low+high
// binaries (index parse, size + Q1 control-checksum verification, APKINDEX
// regeneration), and installs the package with the real apk inside an Alpine
// container — pulled from ArtiGate's own container mirror, so no anonymous
// Docker Hub pull can rate-limit the run.
const (
	apkE2EBranch  = "v3.20"
	apkE2EPackage = "libbz2" // tiny, stable, not in the base image, no deps beyond musl
	apkE2EMirror  = "https://dl-cdn.alpinelinux.org/alpine"
	apkE2EImage   = "alpine:3.20" // must match apkE2EBranch
)

func TestApk(t *testing.T) {
	stack.Prepare(t)
	requireDocker(t)

	upstream, version := apkE2EMiniUpstream(t)

	res := stack.Collect(t, "apk", map[string]any{
		"name":          "alpine",
		"uri":           upstream.URL,
		"branches":      []string{apkE2EBranch},
		"repositories":  []string{"main"},
		"architectures": []string{"x86_64"},
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly one package, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "apk", res.Sequence)

	repoPath := "/apk/alpine/" + apkE2EBranch + "/main"
	code, index := httpGet(t, stack.HighURL+repoPath+"/x86_64/APKINDEX.tar.gz")
	if code != 200 {
		t.Fatalf("regenerated APKINDEX = %d", code)
	}
	if idx := apkE2EReadIndex(t, index); !strings.Contains(idx, "P:"+apkE2EPackage+"\n") {
		t.Fatalf("regenerated APKINDEX misses the package stanza:\n%s", idx)
	}

	// The client container comes through ArtiGate's own container mirror.
	imgRes := stack.Collect(t, "containers", map[string]any{
		"images": []string{apkE2EImage},
	})
	stack.WaitImported(t, "containers", imgRes.Sequence)
	ref := stack.HighHost + "/docker.io/library/" + apkE2EImage
	t.Cleanup(func() { _, _ = runAllowFail(t, "", nil, "docker", "rmi", "-f", ref) })
	run(t, "", nil, "docker", "pull", ref)

	// --network host lets apk inside the container reach the loopback high
	// side. The regenerated index is unsigned (no --apk-rsa-key in this
	// stack), so the documented --allow-untrusted flow applies.
	script := fmt.Sprintf(
		"echo http://%s%s > /etc/apk/repositories && apk update --allow-untrusted && apk add --allow-untrusted %s && apk info -e %s",
		stack.HighHost, repoPath, apkE2EPackage, apkE2EPackage)
	out := run(t, "", nil, "docker", "run", "--rm", "--network", "host", ref, "sh", "-ec", script)
	if !strings.Contains(out, "Installing "+apkE2EPackage+" ("+version) {
		t.Fatalf("apk add did not install %s %s:\n%s", apkE2EPackage, version, out)
	}
	if !strings.Contains(out, apkE2EPackage+"\n") && !strings.HasSuffix(strings.TrimSpace(out), apkE2EPackage) {
		t.Fatalf("apk info does not report %s installed:\n%s", apkE2EPackage, out)
	}
}

// apkE2EMiniUpstream fetches the real branch index and the pinned package
// from the Alpine CDN and serves them as a one-package repository, returning
// the server and the package version its stanza declares.
func apkE2EMiniUpstream(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	base := apkE2EMirror + "/" + apkE2EBranch + "/main/x86_64"
	stanza := apkE2EStanza(t, apkE2EFetch(t, base+"/APKINDEX.tar.gz"), apkE2EPackage)
	version := apkE2EField(stanza, "V")
	if version == "" {
		t.Fatalf("stanza carries no version:\n%s", stanza)
	}
	filename := apkE2EPackage + "-" + version + ".apk"
	pkg := apkE2EFetch(t, base+"/"+filename)
	index := apkE2EIndexArchive(t, stanza)

	mux := http.NewServeMux()
	prefix := "/" + apkE2EBranch + "/main/x86_64/"
	mux.HandleFunc(prefix+"APKINDEX.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(index)
	})
	mux.HandleFunc(prefix+filename, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(pkg)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, version
}

// apkE2EFetch downloads one CDN artifact, skipping the test on upstream
// weather (the same policy Collect applies) and failing on anything else.
func apkE2EFetch(t *testing.T, url string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if isTransientUpstreamError(err.Error()) {
			t.Skipf("alpine CDN unavailable: %v", err)
		}
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if isTransientUpstreamError(fmt.Sprintf("status %d", resp.StatusCode)) {
			t.Skipf("alpine CDN answered %d for %s", resp.StatusCode, url)
		}
		t.Fatalf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return b
}

// apkE2EStanza extracts one package's verbatim stanza from a real
// APKINDEX.tar.gz (the leading signature segment reads through transparently
// as a concatenated gzip stream).
func apkE2EStanza(t *testing.T, indexArchive []byte, pkg string) string {
	t.Helper()
	text := apkE2EReadIndex(t, indexArchive)
	for _, block := range strings.Split(text, "\n\n") {
		if strings.Contains("\n"+block+"\n", "\nP:"+pkg+"\n") {
			return strings.Trim(block, "\n")
		}
	}
	t.Fatalf("package %s not found in the %s index", pkg, apkE2EBranch)
	return ""
}

// apkE2EReadIndex returns the APKINDEX member of an APKINDEX.tar.gz.
func apkE2EReadIndex(t *testing.T, archive []byte) string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("index is not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			t.Fatal("archive has no APKINDEX member")
		}
		if err != nil {
			t.Fatalf("reading index archive: %v", err)
		}
		if path.Base(path.Clean(hdr.Name)) != "APKINDEX" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			t.Fatalf("reading APKINDEX: %v", err)
		}
		return string(b)
	}
}

// apkE2EField extracts one single-letter field from a stanza.
func apkE2EField(stanza, key string) string {
	for _, line := range strings.Split(stanza, "\n") {
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return v
		}
	}
	return ""
}

// apkE2EIndexArchive packs a one-stanza APKINDEX.tar.gz the way an unsigned
// upstream would serve it.
func apkE2EIndexArchive(t *testing.T, stanza string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{
		{"DESCRIPTION", "artigate e2e mini repository"},
		{"APKINDEX", stanza + "\n\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
