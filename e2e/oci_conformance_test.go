//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const ociConformanceRepository = "conformance"

// Zot 2.1.21 supports the suite's OCI 1.1 setup writes and native referrers.
const ociConformanceRegistryImage = "ghcr.io/project-zot/zot:v2.1.21@sha256:6b69512c00dceaad05b1144e6079aac6aa7309d7fd200f9947ecb1de09cf48c8"

// TestOCIDistributionConformance runs the unmodified distribution-spec v1.1.1
// pull and discovery workflows. Their random referrer fixtures cannot be
// supplied with OCI_TAG_LIST/OCI_MANIFEST_DIGEST: those options skip setup but
// leave assertions that depend on newly generated fixture bytes. The gateway
// therefore seeds the local upstream, imports through the signed diode, and
// forwards every GET/HEAD assertion to the high side without changing its reply.
func TestOCIDistributionConformance(t *testing.T) {
	suite := requireTool(t, "oci-distribution-conformance")
	config := filepath.Join(t.TempDir(), "zot.json")
	ociWriteFile(t, config, []byte(`{"storage":{"rootDirectory":"/tmp/zot","gc":false},"http":{"address":"0.0.0.0","port":"5000"},"log":{"level":"error"}}`))
	upstream := startOCIRegistryImage(t, ociConformanceRegistryImage, []string{"--volume", config + ":/etc/zot/config.json:ro"})
	pair := startTestPair(t, pairConfig{
		name: "oci-conformance", httpDiode: true,
		containerRegistry: ociFixtureRegistryName + "=" + upstream,
	})
	reports := filepath.Join(stack.WorkDir, "oci-conformance")
	if err := os.MkdirAll(reports, 0o755); err != nil {
		t.Fatal(err)
	}
	gateway := newOCIConformanceGateway(t, pair, upstream)
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)
	env := append(ociClientEnv(t, t.TempDir()),
		"OCI_ROOT_URL="+server.URL,
		"OCI_NAMESPACE="+ociFixtureRegistryName+"/"+ociConformanceRepository,
		"OCI_TEST_PULL=1", "OCI_TEST_CONTENT_DISCOVERY=1",
		"OCI_TEST_PUSH=0", "OCI_TEST_CONTENT_MANAGEMENT=0",
		"OCI_MANIFEST_DIGEST=", "OCI_TAG_NAME=", "OCI_BLOB_DIGEST=", "OCI_TAG_LIST=",
		"OCI_USERNAME=", "OCI_PASSWORD=", "OCI_AUTH_SCOPE=",
		"OCI_REPORT_DIR="+reports, "OCI_HIDE_SKIPPED_WORKFLOWS=1", "OCI_DEBUG=0",
	)
	out, err := runAllowFail(t, reports, env, suite, "-test.v", "-ginkgo.no-color")
	ociWriteFile(t, filepath.Join(reports, "suite.log"), []byte(out))
	gateway.assertCoverage(t)
	for _, name := range []string{"junit.xml", "report.html"} {
		info, statErr := os.Stat(filepath.Join(reports, name))
		if statErr != nil || info.Size() == 0 {
			t.Errorf("missing OCI conformance report %s: %v", name, statErr)
		}
	}
	if err != nil {
		t.Fatalf("official OCI pull/discovery conformance: %v; reports: %s", err, reports)
	}
	t.Logf("official OCI pull/discovery reports: %s", reports)
}

// ociConformanceGateway is only a fixture adapter. POST/PUT/PATCH populate the
// local upstream. GET/HEAD reach the high side after import. Teardown DELETEs
// return the suite's supported 405 response; Docker cleanup removes fixtures.
type ociConformanceGateway struct {
	t        *testing.T
	pair     *testPair
	upstream *httputil.ReverseProxy
	high     *httputil.ReverseProxy

	mu       sync.Mutex
	refs     map[string]bool
	dirty    bool
	writes   int
	reads    int
	imports  int
	problems []string
}

func newOCIConformanceGateway(t *testing.T, pair *testPair, upstream string) *ociConformanceGateway {
	t.Helper()
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	highURL, err := url.Parse(pair.HighURL)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &ociConformanceGateway{t: t, pair: pair, refs: make(map[string]bool)}
	gateway.upstream = httputil.NewSingleHostReverseProxy(upstreamURL)
	gateway.high = httputil.NewSingleHostReverseProxy(highURL)
	return gateway
}

func (g *ociConformanceGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The official suite is sequential; serialize here too so a future client
	// cannot observe a fixture while its signed import is still in progress.
	g.mu.Lock()
	defer g.mu.Unlock()
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		g.seed(w, r)
	case http.MethodGet, http.MethodHead:
		if err := g.importFixtures(r.Context()); err != nil {
			g.problems = append(g.problems, err.Error())
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		g.reads++
		g.high.ServeHTTP(w, r)
	case http.MethodDelete:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"errors":[{"code":"UNSUPPORTED","message":"fixture teardown uses container cleanup"}]}`))
	default:
		g.problems = append(g.problems, "unexpected conformance method "+r.Method)
		http.Error(w, "unsupported fixture operation", http.StatusMethodNotAllowed)
	}
}

func (g *ociConformanceGateway) seed(w http.ResponseWriter, r *http.Request) {
	const upstreamPrefix = "/v2/" + ociConformanceRepository + "/"
	const suitePrefix = "/v2/" + ociFixtureRegistryName + "/" + ociConformanceRepository + "/"
	if !strings.HasPrefix(r.URL.Path, suitePrefix) {
		g.problems = append(g.problems, "unexpected conformance setup path "+r.URL.Path)
		http.Error(w, "unexpected fixture namespace", http.StatusBadRequest)
		return
	}
	originalPath := r.URL.Path
	r.URL.Path = upstreamPrefix + strings.TrimPrefix(r.URL.Path, suitePrefix)
	r.URL.RawPath = ""
	g.upstream.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			g.writes++
			if _, ref, found := strings.Cut(originalPath, "/manifests/"); found && r.Method == http.MethodPut {
				g.refs[ref] = true
				g.dirty = true
			}
		}
		// Distribution may return an absolute upload URL. Keep subsequent
		// setup writes on this gateway, where successful manifests are tracked.
		if location := resp.Header.Get("Location"); location != "" {
			u, err := url.Parse(location)
			if err != nil {
				return err
			}
			u.Scheme, u.Host = "", ""
			u.Path = suitePrefix + strings.TrimPrefix(u.Path, upstreamPrefix)
			resp.Header.Set("Location", u.String())
		}
		return nil
	}
	g.upstream.ServeHTTP(w, r)
}

func (g *ociConformanceGateway) importFixtures(ctx context.Context) error {
	if !g.dirty {
		return nil
	}
	refs := make([]string, 0, len(g.refs))
	for ref := range g.refs {
		separator := ":"
		if strings.HasPrefix(ref, "sha256:") {
			separator = "@"
		}
		refs = append(refs, ociFixtureRegistryName+"/"+ociConformanceRepository+separator+ref)
	}
	slices.Sort(refs)
	result, err := g.pair.collectOnce(g.t, "containers", map[string]any{"images": refs})
	if err != nil {
		return fmt.Errorf("import official conformance fixtures: %w", err)
	}
	if result.DiodeError != "" || len(result.SkippedModules) != 0 || result.ExportedModules != len(refs) {
		return fmt.Errorf("incomplete official conformance fixture transfer: %+v", result)
	}
	if err := waitOCIConformanceImport(ctx, g.pair, result.Sequence); err != nil {
		return err
	}
	g.dirty = false
	g.imports++
	return nil
}

func waitOCIConformanceImport(ctx context.Context, pair *testPair, sequence int64) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pair.HighURL+"/admin/status", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		var status importStatus
		err = json.NewDecoder(resp.Body).Decode(&status)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		for _, stream := range status.Streams {
			if stream.Stream == "containers" && stream.LastImportedSequence >= sequence {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for conformance fixture import %d: %w", sequence, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (g *ociConformanceGateway) assertCoverage(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.problems) != 0 || g.imports == 0 || g.writes == 0 || g.reads == 0 {
		t.Errorf("OCI fixture routing: %d upstream writes, %d signed imports, %d high-side reads; problems: %v",
			g.writes, g.imports, g.reads, g.problems)
	}
	t.Logf("OCI fixture routing: %d upstream setup writes, %d signed imports, %d unchanged high-side GET/HEAD responses",
		g.writes, g.imports, g.reads)
}
