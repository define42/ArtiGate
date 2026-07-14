// artigate implements a low-side multi-ecosystem exporter and a high-side
// read-only repository server for data-diode use.
//
// It intentionally sticks to the Go standard library (the only exceptions:
// pure-Go SQLite for scheduled watches and the exported-content index,
// hashicorp/go-version for container tag constraints, and
// klauspost/reedsolomon for the built-in UDP diode's forward error
// correction). The low side delegates fetching to the installed
// `go`/`git`/`pip`/`mvn`/`npm` tools; the high side never invokes them and
// never fetches upstream.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "keygen":
		runKeygen(os.Args[2:])
	case "low":
		runLow(os.Args[2:])
	case "high":
		runHigh(os.Args[2:])
	case "hashpw":
		runHashpw(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}

const usageText = `Usage:
  artigate keygen --private low.ed25519 --public high.ed25519.pub

  artigate hashpw --user alice        # argon2id hash for ARTIGATE_LOW_AUTH (reads password from stdin)

  artigate low \
    --listen :8080 \
    --root /var/lib/artigate-low \
    --export-dir /var/spool/diode-out \
    --private-key /etc/artigate/low.ed25519 \
    --upstream-goproxy https://proxy.golang.org,direct \
    --goprivate github.com/your-org/* \
    --gonosumdb github.com/your-org/*

  artigate high \
    --listen :8080 \
    --root /var/lib/artigate-high \
    --landing /var/spool/diode-in \
    --public-key /etc/artigate/high.ed25519.pub \
    --import-interval 10s

High-side clients:
  GOPROXY=http://high-proxy:8080/go,off
  GOSUMDB=off

Useful admin endpoints:
  low:  POST /admin/{go,python,maven,apt,rpm,containers,npm,hf,crates,terraform,helm,nuget,apk}/collect
        (append ?dry_run=1 for a size estimate — "N files, X GB new, K bundles" — with no export)
  low:  POST /admin/reexport?stream=go&sequences=42,45-47
  low:  GET  /admin/bundles
  high: POST /admin/import
  high: GET  /admin/missing
  high: GET  /admin/status

Diode transport (env; default is the folder flow via --export-dir/--landing):
  ARTIGATE_DIODE_URL     low:  HTTP endpoint bundles are uploaded to after every export
                               (PUT <url>/<file>); the export dir becomes the retry spool
  ARTIGATE_DIODE_INGEST  high: on|off — accept bundle uploads at PUT/POST /diode/<file>
                               into the landing directory (default off)
  ARTIGATE_DIODE_TOKEN   both: shared bearer token (at least 32 bytes; required for HTTP diode transport)

Built-in UDP data diode (env; a dedicated one-way fiber NIC on each side; the
bundles cross as rate-limited, Reed-Solomon-coded IPv6 multicast — no return path):
  low:   ARTIGATE_PITCHER_INTERFACE=eth1 enables; ARTIGATE_PITCHER_RATE_MBIT=800,
         _MTU=9000, _TXQUEUELEN=10000, _GROUP=ff02::4147, _PORT=4147, _FEC_DATA=32,
         _FEC_PARITY=8 (any 8 of every 40 datagrams may be lost harmlessly),
         _NETSETUP=on|off (on: ArtiGate sets MTU/queues/ipv6 eui64 itself)
  high:  ARTIGATE_CATCHER_INTERFACE=eth1 enables; ARTIGATE_CATCHER_RCVBUF_MB=64,
         plus _MTU, _GROUP, _PORT, _NETSETUP as above
  Docker: network_mode: host, cap_add: [NET_ADMIN], root user (see examples/).

TLS (env, both low and high):
  ARTIGATE_TLS_MODE=unencrypted|acme|own-certificate|auto-generate-certificate
  acme:            ARTIGATE_TLS_DOMAINS, ARTIGATE_ACME_EMAIL, ARTIGATE_ACME_DIRECTORY, ARTIGATE_ACME_CA_ROOT
  own-certificate: ARTIGATE_TLS_CERT, ARTIGATE_TLS_KEY

Auth (env, low side only):
  ARTIGATE_LOW_AUTH=user:<argon2id-hash>[;user2:<hash>...]   (generate hashes with 'hashpw')
  When set, the low-side dashboard requires a form login (session cookie); the high side is never authenticated.
  ARTIGATE_LOW_COOKIE_SECURE=auto|true|false   (default auto: Secure follows ArtiGate's own TLS)
  Set to 'true' when ArtiGate serves plain HTTP behind a TLS-terminating reverse proxy.

Monitoring (env, both sides):
  GET /metrics           Prometheus telemetry (per-stream lag, gap age, bundle counts/bytes,
                         quota, disk, schedule/import outcomes); open like /healthz.
  GET /readyz            readiness: 503 with the failing checks when the side cannot do its
                         job (high: blocked streams, stalled/failing import passes, undrained
                         backlog, exhausted transport quota; low: failed diode transfers,
                         unreadable schedule store, missing export spool); 200 "ok" otherwise
                         (?verbose lists every check). /healthz stays pure liveness.
  ARTIGATE_WEBHOOK_URL   http/https endpoint POSTed a JSON event on schedule_failed (low),
                         bundle_rejected / gap_detected (high); unset disables it.
  ARTIGATE_WEBHOOK_TOKEN optional bearer token sent with each webhook POST.

`

// -----------------------------------------------------------------------------
// Keys
// -----------------------------------------------------------------------------

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	privPath := fs.String("private", "low.ed25519", "private key output path")
	pubPath := fs.String("public", "high.ed25519.pub", "public key output path")
	_ = fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	must(writeKeyFile(*privPath, priv, 0o600))
	must(writeKeyFile(*pubPath, pub, 0o644))
	log.Printf("wrote private key: %s", *privPath)
	log.Printf("wrote public key:  %s", *pubPath)
}

func writeKeyFile(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(b) + "\n")
	return os.WriteFile(p, encoded, mode)
}

func readPrivateKey(p string) (ed25519.PrivateKey, error) {
	b, err := readBase64File(p)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func readPublicKey(p string) (ed25519.PublicKey, error) {
	b, err := readBase64File(p)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func readBase64File(p string) ([]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	return base64.StdEncoding.DecodeString(s)
}

// -----------------------------------------------------------------------------
// Misc helpers
// -----------------------------------------------------------------------------

func serveFile(w http.ResponseWriter, r *http.Request, abs string) {
	if !fileExists(abs) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ext := filepath.Ext(abs)
	switch ext {
	case ".info":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	case ".mod", ".ziphash":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case ".zip":
		w.Header().Set("Content-Type", "application/zip")
	default:
		if ct := mime.TypeByExtension(ext); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}
	http.ServeFile(w, r, abs)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func safeJoin(root, p string) bool {
	root, _ = filepath.Abs(root)
	p, _ = filepath.Abs(p)
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func hostnameOrDefault() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "artigate"
	}
	return h
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func logHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
