//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestReceiverIsolation deliberately offers a reachable "upstream" on the
// host. A client must reach only the allowed high endpoint, even on redirect,
// and must not inherit host registry/proxy settings or artifact caches.
func TestReceiverIsolation(t *testing.T) {
	python := requireTool(t, "python3")
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("forbidden upstream"))
	}))
	defer upstream.Close()
	high := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/redirect" {
			http.Redirect(w, req, upstream.URL, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("high-side only"))
	}))
	defer high.Close()
	t.Setenv("PIP_EXTRA_INDEX_URL", upstream.URL)
	t.Setenv("HTTP_PROXY", upstream.URL)
	t.Setenv("GOCACHE", t.TempDir())
	rx := newReceiver(t, high.URL)
	rx.Run(t, "", nil, python, "-c", `
import os, socket, sys, urllib.request
high, upstream = sys.argv[1:]
assert urllib.request.urlopen(high, timeout=2).read() == b'high-side only'
for forbidden in (upstream, high + '/redirect', 'http://1.1.1.1:80'):
    try:
        urllib.request.urlopen(forbidden, timeout=2)
    except OSError:
        pass
    else:
        raise AssertionError('receiver escaped to ' + forbidden)
for key in ('PIP_EXTRA_INDEX_URL', 'HTTP_PROXY', 'GOCACHE'):
    assert key not in os.environ, key + ' leaked from host'
assert not os.listdir(os.environ['HOME']), 'receiver HOME was not empty'
open(os.path.join(os.environ['HOME'], 'receiver-state'), 'w').write('same receiver')
`, high.URL, upstream.URL)
	rx.Run(t, "", nil, python, "-c", `import os; assert open(os.path.join(os.environ['HOME'], 'receiver-state')).read() == 'same receiver'`)
	if upstreamHits.Load() != 0 {
		t.Fatalf("receiver contacted forbidden upstream %d times", upstreamHits.Load())
	}
}
