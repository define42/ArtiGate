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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	manifestType  = "go-module-bundle"
	completeExt   = ".complete"
	stateFileMode = 0o600
)

// Bundle streams. Each ecosystem is its own independently-sequenced stream, so a
// lost or out-of-order bundle in one stream never blocks the others. The "go"
// stream keeps the pre-multi-stream numbering for backward compatibility.
const (
	streamGo         = "go"
	streamPython     = "python"
	streamMaven      = "maven"
	streamApt        = "apt"
	streamRpm        = "rpm"
	streamContainers = "containers"
	streamNpm        = "npm"
	streamHF         = "hf"
	streamUploads    = "uploads"
)

// knownStreams is the set of built-in ecosystem streams, shown in the low-side
// status even before anything has been exported.
func knownStreams() []string {
	return []string{streamGo, streamPython, streamMaven, streamApt, streamRpm, streamContainers, streamNpm, streamHF, streamUploads}
}

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
  low:  POST /admin/{go,python,maven,apt,rpm,containers,npm,hf}/collect
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

`

// -----------------------------------------------------------------------------
// Shared manifest/state types
// -----------------------------------------------------------------------------

type BundleManifest struct {
	Type             string             `json:"type"`
	Stream           string             `json:"stream,omitempty"`
	Sequence         int64              `json:"sequence"`
	PreviousSequence int64              `json:"previous_sequence"`
	Created          time.Time          `json:"created"`
	Generator        string             `json:"generator"`
	BundleID         string             `json:"bundle_id"`
	Ecosystems       []string           `json:"ecosystems,omitempty"`
	Modules          []ManifestMod      `json:"modules,omitempty"`
	Python           *PythonManifest    `json:"python,omitempty"`
	Maven            *MavenManifest     `json:"maven,omitempty"`
	Apt              *AptManifest       `json:"apt,omitempty"`
	Rpm              *RpmManifest       `json:"rpm,omitempty"`
	Containers       *ContainerManifest `json:"containers,omitempty"`
	Npm              *NpmManifest       `json:"npm,omitempty"`
	HuggingFace      *HFManifest        `json:"huggingface,omitempty"`
	Uploads          *UploadsManifest   `json:"uploads,omitempty"`
	Files            []ManifestFile     `json:"files"`
}

type ManifestMod struct {
	Module  string                  `json:"module"`
	Version string                  `json:"version"`
	Files   map[string]ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Prior marks a file whose content an earlier bundle on this stream
	// already delivered: it is listed (so module/repo references stay
	// complete) but not packed into this bundle's archive. The high side
	// verifies it against the accumulated repository instead of extracting it.
	Prior bool `json:"prior,omitempty"`
}

type ModuleInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// SequenceRange is inclusive. It is used for operator-facing missing bundle
// reports and low-side re-export requests such as "42,45-47".
type SequenceRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

func (r SequenceRange) String() string {
	if r.Start == r.End {
		return strconv.FormatInt(r.Start, 10)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

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
// Low side
// -----------------------------------------------------------------------------

type LowConfig struct {
	Listen          string
	Root            string
	ExportDir       string
	PrivateKeyPath  string
	UpstreamGOPROXY string
	GOSUMDB         string
	GOPRIVATE       string
	GONOSUMDB       string
	GONOPROXY       string
	GOVCS           string
	GoBinary        string
	GoToolchain     string
	PipBinary       string
	MavenBinary     string
	NpmBinary       string
	// NpmRegistry optionally overrides the registry npm resolves against
	// (passed as --registry); empty uses npm's configured default.
	NpmRegistry string
	// HFEndpoint optionally overrides the Hugging Face endpoint models are
	// fetched from (a private mirror, or a test server); empty means
	// https://huggingface.co.
	HFEndpoint    string
	WatchInterval time.Duration
	// ContainerRegistries optionally remaps container registry names to the
	// endpoints they are fetched from, as comma-separated host=baseURL pairs.
	ContainerRegistries string
	// DiodeURL optionally names the HTTP endpoint bundles are uploaded to
	// after every export (ARTIGATE_DIODE_URL); empty keeps the folder-only
	// flow. DiodeToken is its required bearer token (ARTIGATE_DIODE_TOKEN).
	DiodeURL   string
	DiodeToken string
}

type LowState struct {
	// Sequences maps each stream to its next sequence number.
	Sequences map[string]int64 `json:"sequences"`
	// NextSequence is the legacy single-stream counter, migrated into
	// Sequences["go"] on load.
	NextSequence int64 `json:"next_sequence,omitempty"`
}

// RequestRecord is a concrete module@version to fetch into a Go bundle, produced
// by resolving a collect request (an explicit module list or a project go.mod).
type RequestRecord struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

type LowServer struct {
	cfg         LowConfig
	privateKey  ed25519.PrivateKey
	downloadDir string // $GOPATH/pkg/mod/cache/download
	gopath      string
	statePath   string
	// streamLocks serializes bundle production (sequence allocate -> write ->
	// commit) per stream: two exporters on the same stream can never claim the
	// same sequence number and clobber each other's bundle, while different
	// ecosystems (a long APT mirror and a Python collect, say) export
	// concurrently — safe because each stream has its own sequence counter and
	// its own bundle/staging paths. streamLocksMu guards the map itself. These
	// are deliberately separate from mu: mu guards state for fast
	// readers/writers (the proxy hot path, status endpoints) that must not block
	// for the minutes a bundle write can take.
	streamLocksMu sync.Mutex
	streamLocks   map[string]*sync.Mutex
	mu            sync.Mutex
	state         LowState
	// exported is the SQLite-backed per-stream index of files (path + content
	// hash) already forwarded across the diode, driving the skip/delta dedup
	// and the collectors' pre-download skip. It is separate from the
	// stdlib-JSON sequence state so a SQLite problem can never wedge the core
	// export pipeline: the index is only an optimization (collectors fail safe).
	exported *ExportedStore
	// watches holds scheduled recurring collects (SQLite-backed); watchTick is
	// how often the scheduler checks for due ones; watchRunning guards against a
	// watch running concurrently with itself (a tick overlapping a run-now).
	watches        *WatchStore
	watchTick      time.Duration
	watchRunningMu sync.Mutex
	watchRunning   map[int64]bool
	// authEnabled is set when ARTIGATE_LOW_AUTH is configured; it makes the UI
	// render a "Log out" button.
	authEnabled bool
	// pitcher is the built-in UDP diode sender (ARTIGATE_PITCHER_INTERFACE);
	// nil means bundles leave via the export dir or the HTTP diode endpoint.
	pitcher *diodePitcher
	// containerRegistryBases maps a container registry name to the API base URL
	// it is fetched from (parsed from cfg.ContainerRegistries).
	containerRegistryBases map[string]string
}

func runLow(args []string) {
	fs := flag.NewFlagSet("low", flag.ExitOnError)
	cfg := LowConfig{}
	fs.StringVar(&cfg.Listen, "listen", ":8080", "HTTP listen address")
	fs.StringVar(&cfg.Root, "root", "/var/lib/artigate-low", "low-side working directory")
	fs.StringVar(&cfg.ExportDir, "export-dir", "/var/spool/diode-out", "directory where signed bundles are written")
	fs.StringVar(&cfg.PrivateKeyPath, "private-key", "", "base64 Ed25519 private key path")
	fs.StringVar(&cfg.UpstreamGOPROXY, "upstream-goproxy", "https://proxy.golang.org,direct", "GOPROXY used by low-side fetcher; use direct to fetch from GitHub/VCS")
	fs.StringVar(&cfg.GOSUMDB, "gosumdb", "sum.golang.org", "GOSUMDB used by low-side fetcher")
	fs.StringVar(&cfg.GOPRIVATE, "goprivate", "", "GOPRIVATE for private modules")
	fs.StringVar(&cfg.GONOSUMDB, "gonosumdb", "", "GONOSUMDB for private modules")
	fs.StringVar(&cfg.GONOPROXY, "gonoproxy", "", "GONOPROXY for private modules")
	fs.StringVar(&cfg.GOVCS, "govcs", "*:git", "GOVCS used by low-side fetcher")
	fs.StringVar(&cfg.GoBinary, "go", "go", "go command path")
	fs.StringVar(&cfg.GoToolchain, "gotoolchain", "auto", "GOTOOLCHAIN for the low-side fetcher; \"auto\" lets go download a newer toolchain when a module requires one, \"local\" pins the installed toolchain")
	fs.StringVar(&cfg.PipBinary, "python", "python3", "python interpreter used for pip download of Python packages")
	fs.StringVar(&cfg.MavenBinary, "maven", "mvn", "maven command used to resolve Java/Maven artifacts")
	fs.StringVar(&cfg.NpmBinary, "npm", "npm", "npm command used to resolve NPM package graphs")
	fs.StringVar(&cfg.NpmRegistry, "npm-registry", "", "registry URL npm resolves against (default: npm's own configuration)")
	fs.StringVar(&cfg.HFEndpoint, "hf-endpoint", "", "Hugging Face endpoint models are fetched from (default https://huggingface.co); ARTIGATE_HF_TOKEN optionally authenticates gated models")
	fs.StringVar(&cfg.ContainerRegistries, "container-registry", "", "comma-separated host=baseURL overrides for container registries (e.g. docker.io=https://mirror.example.com)")
	fs.DurationVar(&cfg.WatchInterval, "watch-interval", 60*time.Second, "how often the scheduler checks for due watches; 0 disables scheduled watches")
	_ = fs.Parse(args)

	// The diode transport is configured by environment, like TLS and auth.
	cfg.DiodeURL = strings.TrimSpace(os.Getenv("ARTIGATE_DIODE_URL"))
	cfg.DiodeToken = os.Getenv("ARTIGATE_DIODE_TOKEN")
	must(validateDiodeURL(cfg.DiodeURL))
	if cfg.DiodeURL != "" {
		must(validateDiodeToken(cfg.DiodeToken))
	}
	pitcherCfg := mustPitcherConfig(cfg.DiodeURL)

	if cfg.PrivateKeyPath == "" {
		log.Fatal("--private-key is required")
	}
	priv, err := readPrivateKey(cfg.PrivateKeyPath)
	must(err)

	ls, err := NewLowServer(cfg, priv)
	must(err)
	defer func() { _ = ls.Close() }()

	attachPitcher(ls, pitcherCfg)

	if cfg.WatchInterval > 0 {
		go ls.watchLoop(context.Background())
	}

	serveLow(cfg, ls)
}

// serveLow wires up TLS, optional low-side authentication, and the HTTP handler,
// then serves until the process stops.
func serveLow(cfg LowConfig, ls *LowServer) {
	tc, err := tlsConfigFromEnv()
	must(err)
	users, err := parseLowAuth(os.Getenv("ARTIGATE_LOW_AUTH"))
	must(err)

	mux := http.NewServeMux()
	mux.Handle("/", ls)
	var handler http.Handler = mux
	if len(users) > 0 {
		ls.authEnabled = true
		secure, err := cookieSecure(tc.Mode != tlsUnencrypted, os.Getenv("ARTIGATE_LOW_COOKIE_SECURE"))
		must(err)
		am, err := newAuthManager(users, filepath.Join(cfg.Root, "session.key"), secure)
		must(err)
		handler = am.middleware(handler)
	}

	log.Printf("low-side exporter listening on %s (TLS: %s, auth: %s)", cfg.Listen, tc.Mode, authStatus(users))
	log.Printf("low-side go module cache: %s", ls.downloadDir)
	log.Printf("low-side export dir: %s", cfg.ExportDir)
	if cfg.DiodeURL != "" {
		log.Printf("low-side diode endpoint: %s (bundles upload after export; export dir is the retry spool)", cfg.DiodeURL)
	}
	if ls.pitcher != nil {
		p := ls.pitcher
		log.Printf("low-side diode pitcher: %s → %s at ≤ %d Mbit/s (FEC %d+%d, MTU %d; bundles transmit after export, export dir is the retry spool)",
			p.cfg.Interface, p.target(), p.cfg.RateMbit, p.cfg.DataShards, p.cfg.ParityShards, p.cfg.MTU)
	}
	must(listenAndServe(tc, cfg.Listen, cfg.Root, logHTTP(handler)))
}

func NewLowServer(cfg LowConfig, priv ed25519.PrivateKey) (*LowServer, error) {
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	cfg.Root = root
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.ExportDir, 0o755); err != nil {
		return nil, err
	}
	gopath := filepath.Join(cfg.Root, "gopath")
	dl := filepath.Join(gopath, "pkg", "mod", "cache", "download")
	if err := os.MkdirAll(dl, 0o755); err != nil {
		return nil, err
	}
	registryBases, err := parseContainerRegistryOverrides(cfg.ContainerRegistries)
	if err != nil {
		return nil, err
	}
	ls := &LowServer{
		cfg:                    cfg,
		privateKey:             priv,
		downloadDir:            dl,
		gopath:                 gopath,
		statePath:              filepath.Join(cfg.Root, "low-state.json"),
		state:                  LowState{Sequences: map[string]int64{}},
		streamLocks:            map[string]*sync.Mutex{},
		watchTick:              cfg.WatchInterval,
		watchRunning:           map[int64]bool{},
		containerRegistryBases: registryBases,
	}
	if err := ls.loadState(); err != nil {
		return nil, err
	}
	store, err := OpenWatchStore(filepath.Join(cfg.Root, "watches.db"))
	if err != nil {
		return nil, err
	}
	ls.watches = store
	exported, err := OpenExportedStore(filepath.Join(cfg.Root, "exported.db"))
	if err != nil {
		return nil, err
	}
	ls.exported = exported
	return ls, nil
}

// Close releases the low server's resources (the watch and exported-index
// databases, and the diode sender when one is open).
func (s *LowServer) Close() error {
	err := errors.Join(s.watches.Close(), s.exported.Close())
	if s.pitcher != nil {
		err = errors.Join(err, s.pitcher.Close())
	}
	return err
}

func (s *LowServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.serveLowAdmin(w, r) {
		return
	}
	if s.serveLowUI(w, r) {
		return
	}
	// The low side is an exporter, not a module proxy: all fetching is driven by
	// the /admin/*/collect endpoints and the dashboard. Anything else is unknown.
	http.Error(w, "not found", http.StatusNotFound)
}

// serveLowAdmin handles the health check and /admin/* routes. It reports
// whether it has written a response for the request.
func (s *LowServer) serveLowAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.serveLowCollect(w, r) {
		return true
	}
	if s.serveLowWatches(w, r) {
		return true
	}
	switch {
	case r.URL.Path == "/healthz":
		_, _ = w.Write([]byte("ok\n"))
	case r.URL.Path == "/admin/reexport" && r.Method == http.MethodPost:
		res, err := s.HandleReexportRequest(r)
		return respondJSONOrError(w, http.StatusBadRequest, res, err)
	case r.URL.Path == "/admin/bundles" && r.Method == http.MethodGet:
		writeJSON(w, s.BundleStatus())
	case strings.HasPrefix(r.URL.Path, "/admin/"):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		return false
	}
	return true
}

// serveLowCollect dispatches the per-ecosystem collect endpoints. It reports
// whether it handled the request (false for non-POST or unmatched paths, so the
// caller can fall through to its own routing).
func (s *LowServer) serveLowCollect(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	// Each case binds the request to its handler; the collect itself runs below,
	// either buffered (a single JSON result) or streamed (?stream=1, the
	// dashboard's live progress modal). The handler re-reads r.Body when it runs,
	// so streaming defers the collect into streamCollect's goroutine unchanged.
	var run func(context.Context) (ExportResult, error)
	switch r.URL.Path {
	case "/admin/go/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleGoCollect(ctx, r) }
	case "/admin/python/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandlePythonCollect(ctx, r) }
	case "/admin/maven/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleMavenCollect(ctx, r) }
	case "/admin/apt/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleAptCollect(ctx, r) }
	case "/admin/rpm/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleRpmCollect(ctx, r) }
	case "/admin/containers/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleContainerCollect(ctx, r) }
	case "/admin/npm/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleNpmCollect(ctx, r) }
	case "/admin/hf/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleHFCollect(ctx, r) }
	case "/admin/uploads/collect":
		run = func(ctx context.Context) (ExportResult, error) { return s.HandleUploadsCollect(ctx, r) }
	default:
		return false
	}
	if wantsStreamingCollect(r) {
		s.streamCollect(w, r, run)
		return true
	}
	res, err := run(r.Context())
	return respondJSONOrError(w, http.StatusBadRequest, res, err)
}

// respondJSONOrError writes err as an HTTP error with the given status, or res
// as JSON on success. It always reports the request as handled.
func respondJSONOrError(w http.ResponseWriter, errStatus int, res any, err error) bool {
	if err != nil {
		http.Error(w, err.Error(), errStatus)
		return true
	}
	writeJSON(w, res)
	return true
}

func (s *LowServer) goEnv() []string {
	env := os.Environ()
	set := func(k, v string) {
		env = append(env, k+"="+v)
	}
	set("GO111MODULE", "on")
	set("GOPATH", s.gopath)
	set("GOMODCACHE", filepath.Join(s.gopath, "pkg", "mod"))
	set("GOCACHE", filepath.Join(s.cfg.Root, "gobuildcache"))
	set("GOPROXY", s.cfg.UpstreamGOPROXY)
	set("GOSUMDB", s.cfg.GOSUMDB)
	set("GOVCS", s.cfg.GOVCS)
	// Allow the toolchain to be fetched on demand so modules that declare a
	// newer `go` directive than the installed toolchain can still be mirrored.
	// The official golang images pin GOTOOLCHAIN=local, which would otherwise
	// abort with "requires go >= X".
	if s.cfg.GoToolchain != "" {
		set("GOTOOLCHAIN", s.cfg.GoToolchain)
	}
	if s.cfg.GOPRIVATE != "" {
		set("GOPRIVATE", s.cfg.GOPRIVATE)
	}
	if s.cfg.GONOSUMDB != "" {
		set("GONOSUMDB", s.cfg.GONOSUMDB)
	}
	if s.cfg.GONOPROXY != "" {
		set("GONOPROXY", s.cfg.GONOPROXY)
	}
	// Do not prompt for passwords in daemon mode. Configure git/ssh credentials ahead of time.
	set("GIT_TERMINAL_PROMPT", "0")
	return env
}

func (s *LowServer) runGo(ctx context.Context, args ...string) ([]byte, error) {
	return s.runGoDir(ctx, s.cfg.Root, args...)
}

// runGoDir runs the go command in the given working directory. Dependency
// resolution needs a synthetic module directory, hence the configurable dir.
func (s *LowServer) runGoDir(ctx context.Context, dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.GoBinary, args...)
	cmd.Env = s.goEnv()
	cmd.Dir = dir
	// Keep stdout and stderr separate. Callers parse stdout as JSON (go's
	// `-json` output), while go writes progress and toolchain-download notices
	// ("go: downloading go1.X ...") to stderr; merging them would splice a
	// non-JSON "go: ..." line into the stream and break parsing.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return stdout.Bytes(), fmt.Errorf("go %s failed: %w\n%s", strings.Join(args, " "), err, detail)
	}
	return stdout.Bytes(), nil
}

// validateGoModulePath rejects module paths that the go tool would misparse as
// a command-line flag (a leading '-') or that carry argument-unsafe bytes. It
// guards every place a caller-supplied module string becomes a `go` argument,
// so a /admin/go/collect request cannot inject flags such as `-modfile` or `-C`
// into the fetcher.
func validateGoModulePath(modulePath string) error {
	if modulePath == "" {
		return errors.New("empty module path")
	}
	for _, elem := range strings.Split(modulePath, "/") {
		if elem == "" {
			return fmt.Errorf("invalid module path %q: empty path element", modulePath)
		}
		if strings.HasPrefix(elem, "-") {
			return fmt.Errorf("invalid module path %q: element %q must not start with '-'", modulePath, elem)
		}
	}
	for _, r := range modulePath {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("invalid module path %q: contains a control or space character", modulePath)
		}
	}
	return nil
}

// validateGoVersion rejects version strings that could be misparsed as a flag
// or carry argument-unsafe bytes.
func validateGoVersion(version string) error {
	if version == "" {
		return errors.New("empty version")
	}
	if strings.HasPrefix(version, "-") {
		return fmt.Errorf("invalid version %q: must not start with '-'", version)
	}
	for _, r := range version {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("invalid version %q: contains a control or space character", version)
		}
	}
	return nil
}

type goLatestJSON struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
	Error   string    `json:"Error"`
}

func (s *LowServer) goLatest(ctx context.Context, modulePath string) (ModuleInfo, error) {
	if err := validateGoModulePath(modulePath); err != nil {
		return ModuleInfo{}, err
	}
	out, err := s.runGo(ctx, "list", "-m", "-json", modulePath+"@latest")
	if err != nil {
		return ModuleInfo{}, err
	}
	var v goLatestJSON
	if err := json.Unmarshal(out, &v); err != nil {
		return ModuleInfo{}, fmt.Errorf("parse go latest: %w: %s", err, string(out))
	}
	if v.Error != "" {
		return ModuleInfo{}, errors.New(v.Error)
	}
	if v.Version == "" {
		return ModuleInfo{}, errors.New("go latest did not return a version")
	}
	return ModuleInfo{Version: v.Version, Time: v.Time}, nil
}

type goDownloadJSON struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Info     string `json:"Info"`
	GoMod    string `json:"GoMod"`
	Zip      string `json:"Zip"`
	Sum      string `json:"Sum"`
	GoModSum string `json:"GoModSum"`
	Error    string `json:"Error"`
}

func (s *LowServer) fetchVersion(ctx context.Context, modulePath, version string) error {
	if modulePath == "" || version == "" || version == "latest" {
		return fmt.Errorf("fetchVersion needs concrete module and version, got %q@%q", modulePath, version)
	}
	if err := validateGoModulePath(modulePath); err != nil {
		return err
	}
	if err := validateGoVersion(version); err != nil {
		return err
	}
	out, err := s.runGo(ctx, "mod", "download", "-json", modulePath+"@"+version)
	if err != nil {
		return err
	}
	var dl goDownloadJSON
	if err := json.Unmarshal(out, &dl); err != nil {
		return fmt.Errorf("parse go mod download: %w: %s", err, string(out))
	}
	if dl.Error != "" {
		return errors.New(dl.Error)
	}
	if dl.Info == "" || dl.GoMod == "" || dl.Zip == "" {
		return fmt.Errorf("go mod download did not produce complete files for %s@%s", modulePath, version)
	}
	return nil
}

func (s *LowServer) loadState() error {
	b, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return s.saveStateLocked()
	}
	if err != nil {
		return err
	}
	var st LowState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Sequences == nil {
		st.Sequences = map[string]int64{}
	}
	// Migrate a legacy single-stream counter into the "go" stream.
	if st.NextSequence > 0 {
		if _, ok := st.Sequences[streamGo]; !ok {
			st.Sequences[streamGo] = st.NextSequence
		}
		st.NextSequence = 0
	}
	s.state = st
	return nil
}

func (s *LowServer) saveStateLocked() error {
	return writeJSONAtomic(s.statePath, s.state, stateFileMode)
}

type ExportResult struct {
	Stream          string `json:"stream,omitempty"`
	Sequence        int64  `json:"sequence,omitempty"`
	ExportedModules int    `json:"exported_modules"`
	BundleID        string `json:"bundle_id,omitempty"`
	// Skipped is set when a collect produced no bundle because every resolved
	// file had already been forwarded on this stream. No sequence number is
	// consumed.
	Skipped bool `json:"skipped,omitempty"`
	// PriorFiles counts manifest entries that reference content already
	// forwarded on this stream (a delta bundle): listed and verified on
	// import, but neither downloaded again where the upstream declares hashes
	// nor packed into the archive.
	PriorFiles     int            `json:"prior_files,omitempty"`
	Message        string         `json:"message,omitempty"`
	SkippedModules []FailedModule `json:"skipped_modules,omitempty"`
	// DiodeError reports a failed upload to the HTTP diode endpoint. The
	// bundle itself is fine — committed, archived, and still staged in the
	// export dir — so this is a "re-transmit me" signal, not a lost export.
	DiodeError string `json:"diode_error,omitempty"`
}

// FailedModule records a module that could not be fetched during a collect.
// Such modules are skipped so the rest of the batch still exports — one
// unfetchable version (e.g. retracted or deleted upstream) must never block the
// whole bundle. Skipped modules are reported back in the collect result.
type FailedModule struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Error   string `json:"error"`
}

// GoCollectRequest is the body of POST /admin/go/collect.
//
// Modules is a list of specs, each "module@version" for a concrete version, or
// "module" / "module@latest" to resolve the latest version. When ResolveDeps is
// set, the transitive module graph of the listed modules is resolved and
// bundled too (like pip's dependency resolution).
//
// Alternatively, GoMod may carry a project's own go.mod content (with optional
// GoSum), in which case ArtiGate mirrors exactly the module graph that project
// resolves — the most faithful "what this project needs to build" mode. When
// GoMod is set, Modules and ResolveDeps are ignored.
type GoCollectRequest struct {
	Modules     []string `json:"modules"`
	ResolveDeps bool     `json:"resolve_deps"`
	GoMod       string   `json:"go_mod"`
	GoSum       string   `json:"go_sum"`
	// Force disables export dedup for this collect: everything is downloaded
	// and packed even when already forwarded, producing a full self-contained
	// bundle (for disaster recovery or rebuilding a high side from scratch).
	Force bool `json:"force,omitempty"`
}

// HandleGoCollect parses a JSON collect request and runs the collection. The
// body limit is generous because a request may embed a project's go.sum.
func (s *LowServer) HandleGoCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return ExportResult{}, err
	}
	var req GoCollectRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return ExportResult{}, fmt.Errorf("parse go collect request: %w", err)
		}
	}
	return s.CollectGo(ctx, req)
}

// CollectGo fetches Go modules on demand and writes them into a signed bundle on
// the go stream, mirroring the Python collector. The modules can come from an
// explicit list (optionally with their transitive graph) or from a project's own
// go.mod.
func (s *LowServer) CollectGo(ctx context.Context, req GoCollectRequest) (ExportResult, error) {
	// Hold the go stream's lock for the whole allocate->write->commit so a
	// concurrent go exporter cannot claim the same sequence number between peek
	// and commit. Other streams export in parallel.
	mu := s.streamLock(streamGo)
	mu.Lock()
	defer mu.Unlock()

	emitProgress(ctx, "Resolving the Go module graph…")
	records, err := s.resolveGoCollectRecords(ctx, req)
	if err != nil {
		return ExportResult{}, err
	}
	if len(records) == 0 {
		return ExportResult{}, errors.New("no go modules resolved")
	}
	sortRequestRecords(records)
	emitProgress(ctx, "Resolved %d module(s); fetching…", len(records))
	// Fetch before allocating a sequence so the resolved file set can be
	// dedup-checked: a re-collect of already-forwarded modules skips, and a
	// partly-new one exports only the delta.
	mods, files, failed, err := s.fetchBundleContent(ctx, records)
	if err != nil {
		return ExportResult{}, err
	}
	if len(mods) == 0 {
		// Every requested module failed to fetch. Do not write an empty bundle
		// or burn a sequence number the high side would then wait on forever.
		return ExportResult{}, fmt.Errorf("no modules could be fetched: %s", summarizeFailures(failed))
	}
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	res, err := s.exportIfNew(ctx, streamGo, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeGoBundle(ctx, streamGo, seq, mods, files)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	return res, nil
}

// resolveGoCollectRecords turns a collect request into the concrete set of
// module@version records to bundle.
func (s *LowServer) resolveGoCollectRecords(ctx context.Context, req GoCollectRequest) ([]RequestRecord, error) {
	if strings.TrimSpace(req.GoMod) != "" {
		return s.resolveGoModGraph(ctx, req.GoMod, req.GoSum)
	}
	if len(req.Modules) == 0 {
		return nil, errors.New("no go modules provided")
	}
	records, err := s.resolveGoRequests(ctx, req.Modules)
	if err != nil {
		return nil, err
	}
	if req.ResolveDeps {
		return s.resolveGoDependencies(ctx, records)
	}
	return records, nil
}

func (s *LowServer) resolveGoRequests(ctx context.Context, specs []string) ([]RequestRecord, error) {
	records := make([]RequestRecord, 0, len(specs))
	for _, spec := range specs {
		module, version, err := s.resolveGoSpec(ctx, spec)
		if err != nil {
			return nil, err
		}
		records = append(records, RequestRecord{Module: module, Version: version})
	}
	return records, nil
}

// resolveGoSpec splits a "module[@version]" spec, resolving an empty or
// "latest" version to a concrete one via the low-side toolchain.
func (s *LowServer) resolveGoSpec(ctx context.Context, spec string) (module, version string, err error) {
	spec = strings.TrimSpace(spec)
	module = spec
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		module = spec[:i]
		version = spec[i+1:]
	}
	if module == "" {
		return "", "", fmt.Errorf("invalid module spec %q", spec)
	}
	if version == "" || version == "latest" {
		info, err := s.goLatest(ctx, module)
		if err != nil {
			return "", "", err
		}
		version = info.Version
	}
	return module, version, nil
}

type goModDownloadEntry struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Error   string `json:"Error"`
}

// resolveGoDependencies expands a set of root modules into their full
// transitive module graph. It builds a synthetic module that requires the
// roots, then asks the toolchain to download the whole module graph, which also
// populates the cache the bundle is built from.
func (s *LowServer) resolveGoDependencies(ctx context.Context, roots []RequestRecord) ([]RequestRecord, error) {
	dir, cleanup, err := s.tempCollectDir("deps-")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if err := writeSyntheticGoMod(dir, roots); err != nil {
		return nil, err
	}
	return s.downloadModuleGraph(ctx, dir)
}

// resolveGoModGraph mirrors exactly what a project's own go.mod resolves. The
// provided go.mod (and optional go.sum) are written into a temporary module and
// its whole module graph is downloaded, honoring the project's own `go`
// directive and requirements.
func (s *LowServer) resolveGoModGraph(ctx context.Context, goMod, goSum string) ([]RequestRecord, error) {
	dir, cleanup, err := s.tempCollectDir("project-")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		return nil, err
	}
	if strings.TrimSpace(goSum) != "" {
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o644); err != nil {
			return nil, err
		}
	}
	return s.downloadModuleGraph(ctx, dir)
}

// tempCollectDir creates a scratch module directory and returns a cleanup func.
func (s *LowServer) tempCollectDir(prefix string) (string, func(), error) {
	base := filepath.Join(s.cfg.Root, "gocollect")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(base, prefix)
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// downloadModuleGraph downloads the whole module graph of the module rooted at
// dir and returns its concrete module@version records. The download also
// populates the cache the bundle is later built from.
func (s *LowServer) downloadModuleGraph(ctx context.Context, dir string) ([]RequestRecord, error) {
	out, err := s.runGoDir(ctx, dir, "mod", "download", "-json", "all")
	if err != nil {
		return nil, err
	}
	return parseGoModDownload(out)
}

func writeSyntheticGoMod(dir string, roots []RequestRecord) error {
	var b strings.Builder
	b.WriteString("module artigate-collect\n\ngo 1.16\n\n")
	for _, r := range roots {
		fmt.Fprintf(&b, "require %s %s\n", r.Module, r.Version)
	}
	return os.WriteFile(filepath.Join(dir, "go.mod"), []byte(b.String()), 0o644)
}

// parseGoModDownload reads the JSON stream emitted by `go mod download -json`
// into concrete module@version records.
func parseGoModDownload(out []byte) ([]RequestRecord, error) {
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var records []RequestRecord
	for {
		var e goModDownloadEntry
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parse go mod download: %w", err)
		}
		if e.Error != "" {
			return nil, fmt.Errorf("go mod download %s@%s: %s", e.Path, e.Version, e.Error)
		}
		if e.Version == "" {
			continue
		}
		records = append(records, RequestRecord{Module: e.Path, Version: e.Version})
	}
	return records, nil
}

// streamLock returns the per-stream export lock, creating it on first use.
// Holding it serializes a stream's allocate -> write -> commit; different
// streams get different locks and so export (fetch, write) concurrently.
func (s *LowServer) streamLock(stream string) *sync.Mutex {
	s.streamLocksMu.Lock()
	defer s.streamLocksMu.Unlock()
	mu, ok := s.streamLocks[stream]
	if !ok {
		mu = &sync.Mutex{}
		s.streamLocks[stream] = mu
	}
	return mu
}

// peekSequence returns the stream's next sequence number without advancing it.
// Callers must hold the stream's streamLock across the matching
// peek/write/commitSequence so two exporters cannot observe and write the same
// sequence.
func (s *LowServer) peekSequence(stream string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.state.Sequences[stream]
	if seq < 1 {
		seq = 1
	}
	return seq
}

// commitSequence advances the stream past seq after a bundle for it has been
// written successfully.
func (s *LowServer) commitSequence(stream string, seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Sequences[stream] <= seq {
		s.state.Sequences[stream] = seq + 1
	}
	return s.saveStateLocked()
}

// exportIfNew runs the shared allocate -> write -> commit -> record steps for a
// stream, but first applies export dedup: files whose content this stream has
// already forwarded are marked prior (listed in the manifest, left out of the
// archive), and when nothing at all is new it writes no bundle and burns no
// sequence number, returning a skipped result. force disables both, producing
// a full self-contained bundle. write builds and writes the bundle for the
// allocated sequence. The caller must hold the stream lock (every collector
// does) so the peek/commit stay race-free.
//
// A cancelled collect (the dashboard's Stop button aborts the streaming
// request, cancelling ctx) stops here rather than packing and exporting a
// bundle nobody wants. Packing itself also honors cancellation (the archive
// temp file is removed, no sequence is committed); only the final
// sign-and-archive steps run to completion, so a bundle is either fully
// produced or not at all.
func (s *LowServer) exportIfNew(ctx context.Context, stream string, files []ManifestFile, force bool, write func(seq int64) (ExportResult, error)) (ExportResult, error) {
	if err := ctx.Err(); err != nil {
		return ExportResult{}, fmt.Errorf("collect stopped before export: %w", err)
	}
	if !force {
		s.markPriorFiles(stream, files)
	}
	delivered := countDelivered(files)
	if delivered == 0 {
		return ExportResult{Stream: stream, Skipped: true, Message: "no new content since the last export"}, nil
	}
	if prior := len(files) - delivered; prior > 0 {
		emitProgress(ctx, "%d of %d file(s) already forwarded; the bundle carries the %d new one(s)", prior, len(files), delivered)
	}
	seq := s.peekSequence(stream)
	res, err := write(seq)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(stream, seq); err != nil {
		return ExportResult{}, err
	}
	res.PriorFiles = len(files) - delivered
	// Record only after the sequence is committed. If the commit fails the
	// content is not durably part of the stream, so a retry must re-export it
	// rather than see it as already forwarded and skip.
	s.recordForwarded(stream, files)
	// With an HTTP diode endpoint configured, hand the bundle over now; a
	// failed upload is reported on the result, never fatal (the bundle is
	// committed and archived, ready to re-transmit).
	s.uploadBundleIfConfigured(ctx, &res)
	return res, nil
}

// markPriorFiles flags, in place, every file the exported index already
// records as forwarded on this stream. It is additive: files a collector
// already marked prior (it skipped their download, so no bytes are staged)
// stay prior regardless. It fails safe — on a store error nothing more is
// marked, so content is exported rather than wrongly suppressed.
func (s *LowServer) markPriorFiles(stream string, files []ManifestFile) {
	if len(files) == 0 {
		return
	}
	flags, err := s.exported.ForwardedFlags(stream, files)
	if err != nil {
		log.Printf("export index %s: %v; exporting without dedup", stream, err)
		return
	}
	for i := range files {
		if flags[i] {
			files[i].Prior = true
		}
	}
}

// countDelivered reports how many files the bundle's archive will carry.
func countDelivered(files []ManifestFile) int {
	n := 0
	for _, f := range files {
		if !f.Prior {
			n++
		}
	}
	return n
}

// deliveredFiles returns the subset of files the archive must carry (everything
// not marked prior).
func deliveredFiles(files []ManifestFile) []ManifestFile {
	out := make([]ManifestFile, 0, len(files))
	for _, f := range files {
		if !f.Prior {
			out = append(out, f)
		}
	}
	return out
}

// recordForwarded adds every file to the stream's permanent exported index. It
// logs but does not fail on error: the bundle is already committed, and a
// missed update only forgoes a future skip.
func (s *LowServer) recordForwarded(stream string, files []ManifestFile) {
	if len(files) == 0 {
		return
	}
	if err := s.exported.Record(stream, files); err != nil {
		log.Printf("export index %s: record failed: %v", stream, err)
	}
}

// priorFileCheck returns the pre-download skip predicate for one collect: it
// reports whether a file (bundle path plus upstream-declared SHA-256) was
// already forwarded on the stream, so the collector can emit a prior manifest
// entry without fetching the bytes at all. force disables skipping (a full
// bundle is wanted); store errors fail safe (download).
func (s *LowServer) priorFileCheck(stream string, force bool) func(path, sha256 string) bool {
	return func(path, sha256 string) bool {
		if force || sha256 == "" {
			return false
		}
		ok, err := s.exported.IsForwarded(stream, path, sha256)
		if err != nil {
			log.Printf("export index %s: %v; downloading without dedup", stream, err)
			return false
		}
		return ok
	}
}

// writeGoBundle builds, signs, and writes a Go bundle for already-fetched
// modules at the allocated sequence. Fetching happens in CollectGo so the
// resolved file set can be dedup-checked before a sequence is allocated.
func (s *LowServer) writeGoBundle(ctx context.Context, stream string, seq int64, mods []ManifestMod, files []ManifestFile) (ExportResult, error) {
	if seq <= 0 {
		return ExportResult{}, fmt.Errorf("invalid sequence %d", seq)
	}
	id := bundleIDFor(stream, seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Stream:           stream,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         id,
		Ecosystems:       []string{"go"},
		Modules:          mods,
		Files:            files,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	sig := ed25519.Sign(s.privateKey, manifestBytes)

	if err := s.writeBundleArtifacts(ctx, id, s.downloadDir, manifestBytes, sig, files); err != nil {
		return ExportResult{}, err
	}

	return ExportResult{Stream: stream, Sequence: seq, ExportedModules: len(mods), BundleID: id}, nil
}

// summarizeFailures renders a compact, bounded description of skipped modules
// for an error message or log line.
func summarizeFailures(failed []FailedModule) string {
	const limit = 5
	parts := make([]string, 0, len(failed))
	for i, f := range failed {
		if i == limit {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(failed)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf("%s@%s: %s", f.Module, f.Version, f.Error))
	}
	return strings.Join(parts, "; ")
}

// fetchBundleContent fetches every record's module and returns the module
// manifests plus the de-duplicated set of files they reference. A record that
// cannot be fetched (or whose cache files are incomplete) is collected into the
// returned failures rather than aborting the batch, so one unfetchable version
// never blocks every other module from being exported.
func (s *LowServer) fetchBundleContent(ctx context.Context, records []RequestRecord) (mods []ManifestMod, files []ManifestFile, failed []FailedModule, err error) {
	seenFile := map[string]bool{}
	for i, rec := range records {
		emitProgress(ctx, "→ [%d/%d] %s@%s", i+1, len(records), rec.Module, rec.Version)
		if ferr := s.fetchVersion(ctx, rec.Module, rec.Version); ferr != nil {
			emitProgress(ctx, "  ✗ %s@%s: %s", rec.Module, rec.Version, ferr)
			failed = append(failed, FailedModule{Module: rec.Module, Version: rec.Version, Error: ferr.Error()})
			continue
		}
		mf, merr := s.manifestForModule(rec.Module, rec.Version)
		if merr != nil {
			failed = append(failed, FailedModule{Module: rec.Module, Version: rec.Version, Error: merr.Error()})
			continue
		}
		mods = append(mods, mf)
		for _, f := range mf.Files {
			if !seenFile[f.Path] {
				files = append(files, f)
				seenFile[f.Path] = true
			}
		}
	}
	return mods, files, failed, nil
}

// bundleSuffixes returns the three file suffixes that make up one transferable
// bundle.
func bundleSuffixes() []string {
	return []string{".tar.gz", ".manifest.json", ".manifest.json.sig"}
}

// writeBundleArtifacts writes the archive, manifest, and signature for a bundle
// into the export directory, then retains a copy in the persistent bundle
// archive so the exact signed bytes can be replayed on re-export. baseDir is the
// root the manifest file paths are relative to (the Go module cache for Go
// bundles, a staging dir for Python). Files marked prior are listed in the
// manifest only — the archive carries just the new content.
func (s *LowServer) writeBundleArtifacts(ctx context.Context, bundleID, baseDir string, manifestBytes, sig []byte, files []ManifestFile) error {
	if err := os.MkdirAll(s.cfg.ExportDir, 0o755); err != nil {
		return err
	}
	archivePath := filepath.Join(s.cfg.ExportDir, bundleID+".tar.gz")
	manifestPath := filepath.Join(s.cfg.ExportDir, bundleID+".manifest.json")
	sigPath := filepath.Join(s.cfg.ExportDir, bundleID+".manifest.json.sig")

	if err := createTarGzAtomic(ctx, archivePath, baseDir, deliveredFiles(files)); err != nil {
		return err
	}
	if err := writeBytesAtomic(manifestPath, manifestBytes, 0o644); err != nil {
		return err
	}
	if err := writeBytesAtomic(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return err
	}
	return s.archiveBundle(bundleID)
}

// bundleArchiveDir is where every produced bundle is retained so re-export can
// replay the exact signed files regardless of ecosystem.
func (s *LowServer) bundleArchiveDir() string {
	return filepath.Join(s.cfg.Root, "bundles")
}

// archiveBundle copies a freshly written bundle's three files into the archive.
func (s *LowServer) archiveBundle(bundleID string) error {
	dir := s.bundleArchiveDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, suffix := range bundleSuffixes() {
		src := filepath.Join(s.cfg.ExportDir, bundleID+suffix)
		dst := filepath.Join(dir, bundleID+suffix)
		if err := copyFileAtomic(src, dst, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// replayArchivedBundle copies a previously archived bundle back into the export
// directory so it can be transferred again. It works for any ecosystem because
// it replays the exact signed bytes. The bool reports whether an archived bundle
// was found.
func (s *LowServer) replayArchivedBundle(stream string, seq int64) (ExportResult, bool, error) {
	bundleID := bundleIDFor(stream, seq)
	archive := s.bundleArchiveDir()
	if !bundleCompleteInDir(archive, bundleID) {
		return ExportResult{}, false, nil
	}
	if err := os.MkdirAll(s.cfg.ExportDir, 0o755); err != nil {
		return ExportResult{}, false, err
	}
	for _, suffix := range bundleSuffixes() {
		src := filepath.Join(archive, bundleID+suffix)
		dst := filepath.Join(s.cfg.ExportDir, bundleID+suffix)
		if err := copyFileAtomic(src, dst, 0o644); err != nil {
			return ExportResult{}, false, err
		}
	}
	res := ExportResult{
		Stream:          stream,
		Sequence:        seq,
		BundleID:        bundleID,
		ExportedModules: archivedBundleUnitCount(filepath.Join(archive, bundleID+".manifest.json")),
		Message:         "re-exported from archive",
	}
	return res, true, nil
}

// archivedBundleUnitCount reports how many Go modules plus Python projects a
// bundle manifest contains, or 0 if it cannot be read.
func archivedBundleUnitCount(manifestPath string) int {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return 0
	}
	var m BundleManifest
	if json.Unmarshal(b, &m) != nil {
		return 0
	}
	n := len(m.Modules)
	if m.Python != nil {
		n += len(m.Python.Projects)
	}
	return n
}

func sortRequestRecords(records []RequestRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Module == records[j].Module {
			return compareVersions(records[i].Version, records[j].Version) < 0
		}
		return records[i].Module < records[j].Module
	})
}

type ReexportHTTPBody struct {
	Stream    string `json:"stream"`
	Sequences string `json:"sequences"`
}

type ReexportResult struct {
	Stream          string         `json:"stream"`
	RequestedRanges []string       `json:"requested_ranges"`
	Sequences       []int64        `json:"sequences"`
	Reexported      []ExportResult `json:"reexported"`
	Failed          []string       `json:"failed,omitempty"`
}

func (s *LowServer) HandleReexportRequest(r *http.Request) (ReexportResult, error) {
	stream, spec, err := reexportSpecFromRequest(r)
	if err != nil {
		return ReexportResult{}, err
	}
	if spec == "" {
		return ReexportResult{}, errors.New("missing sequence range; use ?stream=go&sequences=42,45-47 or JSON {\"stream\":\"go\",\"sequences\":\"42,45-47\"}")
	}
	// The stream becomes a path component of the archived bundle files, so
	// only known stream names may pass — anything else could point the replay
	// outside the bundle archive.
	if !isKnownStream(stream) {
		return ReexportResult{}, fmt.Errorf("unknown stream %q", stream)
	}
	ranges, err := parseSequenceSpec(spec)
	if err != nil {
		return ReexportResult{}, err
	}
	return s.ReexportSequences(stream, ranges), nil
}

// reexportSpecFromRequest extracts the stream and sequence spec from either the
// ?stream=/?sequences= query parameters, a raw request body, or a JSON body.
// The stream defaults to "go" (the legacy stream) when unspecified.
func reexportSpecFromRequest(r *http.Request) (stream, spec string, err error) {
	stream = strings.TrimSpace(r.URL.Query().Get("stream"))
	if q := strings.TrimSpace(r.URL.Query().Get("sequences")); q != "" {
		return orDefault(stream, streamGo), q, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		var req ReexportHTTPBody
		if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
			return "", "", err
		}
		if req.Stream != "" {
			stream = strings.TrimSpace(req.Stream)
		}
		return orDefault(stream, streamGo), strings.TrimSpace(req.Sequences), nil
	}
	return orDefault(stream, streamGo), trimmed, nil
}

func (s *LowServer) ReexportSequences(stream string, ranges []SequenceRange) ReexportResult {
	seqs := expandSequenceRanges(ranges, 10000)
	res := ReexportResult{Stream: stream, RequestedRanges: rangesToStrings(ranges), Sequences: seqs}
	for _, seq := range seqs {
		out, err := s.ExportSequence(stream, seq)
		if err != nil {
			res.Failed = append(res.Failed, fmt.Sprintf("%d: %v", seq, err))
			continue
		}
		res.Reexported = append(res.Reexported, out)
	}
	return res
}

func (s *LowServer) ExportSequence(stream string, seq int64) (ExportResult, error) {
	// Serialize against the same stream's sequence-allocating export path so a
	// re-export can never write a bundle file concurrently with a fresh export
	// of the same sequence. A re-export of one stream does not block others.
	mu := s.streamLock(stream)
	mu.Lock()
	defer mu.Unlock()

	// Replay the exact archived bundle bytes. Every produced bundle is retained
	// in the archive, so this covers every ecosystem and needs no re-signing.
	res, ok, err := s.replayArchivedBundle(stream, seq)
	if err != nil {
		return ExportResult{}, err
	}
	if ok {
		// A re-transmit goes out over the same transport as the original
		// export: the configured HTTP diode endpoint, or the export dir.
		s.uploadBundleIfConfigured(context.Background(), &res)
		return res, nil
	}
	return ExportResult{}, fmt.Errorf("no archived bundle for %s", bundleIDFor(stream, seq))
}

type LowBundleStatus struct {
	Streams []LowStreamStatus `json:"streams"`
}

type LowStreamStatus struct {
	Stream            string                 `json:"stream"`
	NextSequence      int64                  `json:"next_sequence"`
	ExportedSequences []ExportedSequenceInfo `json:"exported_sequences"`
}

type ExportedSequenceInfo struct {
	Sequence int64  `json:"sequence"`
	BundleID string `json:"bundle_id"`
	// InArchive is true when a retained copy is kept in the low-side archive
	// (<root>/bundles), so the bundle can be re-transmitted on demand.
	InArchive bool `json:"in_archive"`
	// InOutbound is true when the bundle's files are still staged in the export
	// directory. It goes false once the bundle has been forwarded across the
	// diode (the transfer moves the files out) — that is the normal "sent" state,
	// not an error.
	InOutbound bool `json:"in_outbound"`
	// SizeBytes is the bundle's total on-diode size (archive + manifest +
	// signature), taken from the retained copy (or the export dir if only there).
	SizeBytes int64 `json:"size_bytes"`
}

// Stream returns the export status for the named stream, or a zero value with
// that name if the stream is unknown.
func (s LowBundleStatus) Stream(name string) LowStreamStatus {
	for _, ss := range s.Streams {
		if ss.Stream == name {
			return ss
		}
	}
	return LowStreamStatus{Stream: name}
}

func (s *LowServer) BundleStatus() LowBundleStatus {
	s.mu.Lock()
	next := make(map[string]int64, len(s.state.Sequences))
	for stream, n := range s.state.Sequences {
		next[stream] = n
	}
	s.mu.Unlock()

	// A bundle can be in the persistent archive (<root>/bundles), still staged in
	// the export directory, or both, so list the union of the two per stream: a
	// forwarded bundle is archive-only, a not-yet-sent one is in both.
	archived, _ := findBundleStreams(s.bundleArchiveDir())
	exported, _ := findBundleStreams(s.cfg.ExportDir)
	names := map[string]bool{}
	for _, stream := range knownStreams() {
		names[stream] = true
	}
	for stream := range next {
		names[stream] = true
	}
	for _, m := range []map[string][]int64{archived, exported} {
		for stream := range m {
			names[stream] = true
		}
	}
	streams := make([]string, 0, len(names))
	for stream := range names {
		streams = append(streams, stream)
	}
	sort.Strings(streams)

	out := LowBundleStatus{}
	for _, stream := range streams {
		n := next[stream]
		if n < 1 {
			n = 1
		}
		ss := LowStreamStatus{Stream: stream, NextSequence: n}
		for _, seq := range mergeSequenceLists(archived[stream], exported[stream]) {
			id := bundleIDFor(stream, seq)
			size := bundleSizeInDir(s.bundleArchiveDir(), id)
			if size == 0 {
				size = bundleSizeInDir(s.cfg.ExportDir, id)
			}
			ss.ExportedSequences = append(ss.ExportedSequences, ExportedSequenceInfo{
				Sequence:   seq,
				BundleID:   id,
				InArchive:  bundleCompleteInDir(s.bundleArchiveDir(), id),
				InOutbound: bundleCompleteInDir(s.cfg.ExportDir, id),
				SizeBytes:  size,
			})
		}
		out.Streams = append(out.Streams, ss)
	}
	return out
}

// mergeSequenceLists returns the sorted union of two per-stream sequence lists.
func mergeSequenceLists(a, b []int64) []int64 {
	set := make(map[int64]bool, len(a)+len(b))
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	out := make([]int64, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *LowServer) manifestForModule(modulePath, version string) (ManifestMod, error) {
	// Use go's own cache layout by locating the info/mod/zip files from downloadDir.
	relCandidates, err := findVersionFiles(s.downloadDir, modulePath, version)
	if err != nil {
		return ManifestMod{}, err
	}
	files := map[string]ManifestFile{}
	for kind, rel := range relCandidates {
		abs := filepath.Join(s.downloadDir, filepath.FromSlash(rel))
		mf, err := hashManifestFile(abs, rel)
		if err != nil {
			return ManifestMod{}, err
		}
		files[kind] = mf
	}
	for _, k := range []string{"info", "mod", "zip"} {
		if _, ok := files[k]; !ok {
			return ManifestMod{}, fmt.Errorf("missing %s for %s@%s", k, modulePath, version)
		}
	}
	return ManifestMod{Module: modulePath, Version: version, Files: files}, nil
}

// findVersionFiles searches the Go download cache for exactly one .info, .mod and .zip matching module@version.
// It uses the .info content to disambiguate when path escaping is involved.
func findVersionFiles(downloadDir, modulePath, version string) (map[string]string, error) {
	wantedSuffixes := map[string]string{
		"info": ".info",
		"mod":  ".mod",
		"zip":  ".zip",
	}

	// Fast path: derive an escaped-ish path from URL request rules. This handles
	// normal lowercase paths. Fall back to a scan if any file is missing.
	moduleEsc := escapePathApprox(modulePath)
	versionEsc := escapeVersionApprox(version)
	base := filepath.Join(downloadDir, filepath.FromSlash(moduleEsc), "@v")
	matches := map[string]string{}
	for kind, ext := range wantedSuffixes {
		rel := path.Join(moduleEsc, "@v", versionEsc+ext)
		if fileExists(filepath.Join(base, versionEsc+ext)) {
			matches[kind] = rel
		}
	}
	if len(matches) == 3 {
		return matches, nil
	}

	return findVersionFilesByScan(downloadDir, modulePath, version, versionEsc, wantedSuffixes)
}

// findVersionFilesByScan locates the module's files by scanning the cache for
// an .info whose content matches the requested version, then derives the .mod
// and .zip siblings from it. This is robust to path-escaping edge cases.
func findVersionFilesByScan(downloadDir, modulePath, version, versionEsc string, wantedSuffixes map[string]string) (map[string]string, error) {
	foundInfoRel, err := scanForInfoRel(downloadDir, version, versionEsc)
	if err != nil {
		return nil, err
	}
	if foundInfoRel == "" {
		return nil, fmt.Errorf("could not find %s@%s in %s", modulePath, version, downloadDir)
	}
	matches := map[string]string{}
	prefix := strings.TrimSuffix(foundInfoRel, ".info")
	for kind, ext := range wantedSuffixes {
		rel := prefix + ext
		if fileExists(filepath.Join(downloadDir, filepath.FromSlash(rel))) {
			matches[kind] = rel
		}
	}
	if len(matches) != 3 {
		return nil, fmt.Errorf("incomplete cache files for %s@%s", modulePath, version)
	}
	return matches, nil
}

// scanForInfoRel walks the download cache and returns the slash-separated
// relative path of the .info file whose JSON content matches version, or "".
func scanForInfoRel(downloadDir, version, versionEsc string) (string, error) {
	var foundInfoRel string
	err := filepath.WalkDir(downloadDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(d.Name(), ".info") || !strings.HasPrefix(d.Name(), versionEsc) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var info ModuleInfo
		if json.Unmarshal(b, &info) == nil && info.Version == version {
			if rel, err := filepath.Rel(downloadDir, p); err == nil {
				foundInfoRel = filepath.ToSlash(rel)
			}
		}
		return nil
	})
	return foundInfoRel, err
}

// -----------------------------------------------------------------------------
// High side
// -----------------------------------------------------------------------------

type HighConfig struct {
	Listen         string
	Root           string
	Landing        string
	Quarantine     string
	PublicKeyPath  string
	ImportInterval time.Duration
	AptGPGKey      string
	RpmGPGKey      string
	// DiodeIngest accepts bundle uploads at PUT/POST /diode/<file> into the
	// landing directory (ARTIGATE_DIODE_INGEST=on); DiodeToken requires a
	// bearer token on those uploads (ARTIGATE_DIODE_TOKEN).
	DiodeIngest bool
	DiodeToken  string
}

type HighState struct {
	// Imported maps each stream to its last-imported sequence number.
	Imported map[string]int64 `json:"imported"`
	// LastImportedSequence is the legacy single-stream field, migrated into
	// Imported["go"] on load.
	LastImportedSequence int64     `json:"last_imported_sequence,omitempty"`
	ImportedAt           time.Time `json:"imported_at,omitempty"`
}

type HighServer struct {
	cfg         HighConfig
	publicKey   ed25519.PublicKey
	downloadDir string
	statePath   string
	mu          sync.Mutex
	state       HighState
	tree        treeCache
}

func runHigh(args []string) {
	fs := flag.NewFlagSet("high", flag.ExitOnError)
	cfg := HighConfig{}
	fs.StringVar(&cfg.Listen, "listen", ":8080", "HTTP listen address")
	fs.StringVar(&cfg.Root, "root", "/var/lib/artigate-high", "high-side repository root")
	fs.StringVar(&cfg.Landing, "landing", "/var/spool/diode-in", "directory where diode-delivered bundles arrive")
	fs.StringVar(&cfg.Quarantine, "quarantine", "", "directory for out-of-order future bundles; default is <root>/quarantine")
	fs.StringVar(&cfg.PublicKeyPath, "public-key", "", "base64 Ed25519 public key path")
	fs.DurationVar(&cfg.ImportInterval, "import-interval", 10*time.Second, "bundle import scan interval; 0 disables background import")
	fs.StringVar(&cfg.AptGPGKey, "apt-gpg-key", "", "GPG key id used to sign regenerated APT repositories (InRelease); unset serves them unsigned")
	fs.StringVar(&cfg.RpmGPGKey, "rpm-gpg-key", "", "GPG key id used to sign regenerated RPM repositories (repomd.xml.asc); unset serves them unsigned")
	_ = fs.Parse(args)
	if cfg.PublicKeyPath == "" {
		log.Fatal("--public-key is required")
	}
	ingest, err := parseOnOff(os.Getenv("ARTIGATE_DIODE_INGEST"))
	if err != nil {
		log.Fatalf("ARTIGATE_DIODE_INGEST: %v", err)
	}
	cfg.DiodeIngest = ingest
	cfg.DiodeToken = os.Getenv("ARTIGATE_DIODE_TOKEN")
	if cfg.DiodeIngest {
		must(validateDiodeToken(cfg.DiodeToken))
	}
	pub, err := readPublicKey(cfg.PublicKeyPath)
	must(err)
	hs, err := NewHighServer(cfg, pub)
	must(err)
	startCatcherIfConfigured(hs)

	if cfg.ImportInterval > 0 {
		go hs.importLoop()
	}

	tc, err := tlsConfigFromEnv()
	must(err)

	mux := http.NewServeMux()
	mux.Handle("/", hs)
	log.Printf("high-side repository listening on %s (TLS: %s)", cfg.Listen, tc.Mode)
	if cfg.DiodeIngest {
		log.Printf("high-side diode ingest: accepting bundle uploads at /diode/ (%s)", diodeTokenStatus(cfg.DiodeToken))
	}
	log.Printf("high-side repo: %s", hs.downloadDir)
	log.Printf("high-side landing: %s", cfg.Landing)
	log.Printf("high-side quarantine: %s", hs.cfg.Quarantine)
	must(listenAndServe(tc, cfg.Listen, cfg.Root, logHTTP(mux)))
}

func NewHighServer(cfg HighConfig, pub ed25519.PublicKey) (*HighServer, error) {
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	cfg.Root = root
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return nil, err
	}
	if cfg.Quarantine == "" {
		cfg.Quarantine = filepath.Join(cfg.Root, "quarantine")
	}
	if err := os.MkdirAll(cfg.Landing, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Quarantine, 0o755); err != nil {
		return nil, err
	}
	dl := filepath.Join(cfg.Root, "cache", "download")
	if err := os.MkdirAll(dl, 0o755); err != nil {
		return nil, err
	}
	hs := &HighServer{
		cfg:         cfg,
		publicKey:   pub,
		downloadDir: dl,
		statePath:   filepath.Join(cfg.Root, "import-state.json"),
	}
	if err := hs.loadState(); err != nil {
		return nil, err
	}
	return hs, nil
}

func (s *HighServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Each ecosystem claims its own URL space — Go under /go/, like every other
	// ecosystem under its own prefix — and reports whether it handled the
	// request; anything unclaimed is not found.
	for _, serve := range []func(http.ResponseWriter, *http.Request) bool{
		s.serveHighAdmin, s.serveDiode, s.serveGo, s.servePython, s.serveMaven, s.serveApt,
		s.serveRpm, s.serveHF, s.serveContainers, s.serveNpm, s.serveUploads, s.serveUI,
	} {
		if serve(w, r) {
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

// serveGo handles the GOPROXY routes under /go/. It strips the /go prefix and
// reuses the standard proxy request parser, so Go modules occupy their own URL
// namespace (and on-disk subtree, goModuleDir) just like every other ecosystem.
// Clients set GOPROXY=<base>/go,off. It reports whether it wrote a response.
func (s *HighServer) serveGo(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p != "/go" && !strings.HasPrefix(p, "/go/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	req, err := parseProxyRequest(strings.TrimPrefix(p, "/go"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	switch req.Kind {
	case proxyList:
		s.handleHighList(w, r, req)
	case proxyLatest:
		s.handleHighLatest(w, r, req)
	case proxyVersionFile:
		s.handleHighVersionFile(w, r, req)
	case proxyUnknown:
		http.Error(w, "not found", http.StatusNotFound)
	}
	return true
}

// goModuleDir is the high-side subtree holding the mirrored Go module cache
// (GOPROXY layout), namespaced under the download root like the other
// ecosystems (python/, npm/, …) rather than spread across the root.
func (s *HighServer) goModuleDir() string {
	return filepath.Join(s.downloadDir, "go")
}

// serveHighAdmin handles the health check and /admin/* routes. It reports
// whether it has written a response for the request.
func (s *HighServer) serveHighAdmin(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/healthz":
		_, _ = w.Write([]byte("ok\n"))
	case r.URL.Path == "/admin/import" && r.Method == http.MethodPost:
		res, err := s.ImportNext()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		writeJSON(w, res)
	case (r.URL.Path == "/admin/status" || r.URL.Path == "/admin/missing") && r.Method == http.MethodGet:
		status, err := s.ImportStatus()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		writeJSON(w, status)
	case strings.HasPrefix(r.URL.Path, "/admin/uploads"):
		if !s.serveUploadsAdmin(w, r) {
			http.Error(w, "not found", http.StatusNotFound)
		}
	case strings.HasPrefix(r.URL.Path, "/admin/"):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		return false
	}
	return true
}

func (s *HighServer) handleHighList(w http.ResponseWriter, _ *http.Request, req ProxyRequest) {
	versions, err := s.completeVersions(req.ModuleEscaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	versions = filterNonPseudoValid(versions)
	sortVersionsAsc(versions)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, v := range versions {
		_, _ = fmt.Fprintln(w, v)
	}
}

func (s *HighServer) handleHighLatest(w http.ResponseWriter, _ *http.Request, req ProxyRequest) {
	infos, err := s.completeInfos(req.ModuleEscaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	latest, ok := chooseLatest(infos)
	if !ok {
		http.Error(w, "no complete versions", http.StatusNotFound)
		return
	}
	writeJSON(w, latest)
}

func (s *HighServer) handleHighVersionFile(w http.ResponseWriter, r *http.Request, req ProxyRequest) {
	if req.Ext != ".info" && req.Ext != ".mod" && req.Ext != ".zip" && req.Ext != ".ziphash" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.isComplete(req.ModuleEscaped, req.VersionEscaped) {
		http.Error(w, "version not found", http.StatusNotFound)
		return
	}
	abs := filepath.Join(s.goModuleDir(), filepath.FromSlash(req.RelativePath))
	if !safeJoin(s.goModuleDir(), abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}
	serveFile(w, r, abs)
}

func (s *HighServer) completeVersions(moduleEsc string) ([]string, error) {
	infos, err := s.completeInfos(moduleEsc)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(infos))
	for _, info := range infos {
		out = append(out, info.Version)
	}
	return out, nil
}

func (s *HighServer) completeInfos(moduleEsc string) ([]ModuleInfo, error) {
	base := filepath.Join(s.goModuleDir(), filepath.FromSlash(moduleEsc), "@v")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	var infos []ModuleInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".info") {
			continue
		}
		versionEsc := strings.TrimSuffix(e.Name(), ".info")
		if !s.isComplete(moduleEsc, versionEsc) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(base, e.Name()))
		if err != nil {
			continue
		}
		var info ModuleInfo
		if json.Unmarshal(b, &info) != nil || info.Version == "" {
			continue
		}
		infos = append(infos, info)
	}
	if len(infos) == 0 {
		return nil, os.ErrNotExist
	}
	return infos, nil
}

func (s *HighServer) isComplete(moduleEsc, versionEsc string) bool {
	base := filepath.Join(s.goModuleDir(), filepath.FromSlash(moduleEsc), "@v")
	marker := filepath.Join(base, versionEsc+completeExt)
	if !fileExists(marker) {
		return false
	}
	for _, ext := range []string{".info", ".mod", ".zip"} {
		if !fileExists(filepath.Join(base, versionEsc+ext)) {
			return false
		}
	}
	return true
}

func (s *HighServer) loadState() error {
	b, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		s.state = HighState{Imported: map[string]int64{}}
		return s.saveStateLocked()
	}
	if err != nil {
		return err
	}
	var st HighState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Imported == nil {
		st.Imported = map[string]int64{}
	}
	// Migrate a legacy single-stream counter into the "go" stream.
	if st.LastImportedSequence > 0 {
		if _, ok := st.Imported[streamGo]; !ok {
			st.Imported[streamGo] = st.LastImportedSequence
		}
		st.LastImportedSequence = 0
	}
	s.state = st
	return nil
}

func (s *HighServer) saveStateLocked() error {
	return writeJSONAtomic(s.statePath, s.state, stateFileMode)
}

func (s *HighServer) importLoop() {
	t := time.NewTicker(s.cfg.ImportInterval)
	defer t.Stop()
	for range t.C {
		res, err := s.ImportNext()
		if err != nil {
			log.Printf("import failed: %v", err)
			continue
		}
		if res.Imported {
			log.Printf("imported bundles: %s", strings.Join(res.ImportedBundles, ", "))
		}
	}
}

type ImportResult struct {
	Imported        bool     `json:"imported"`
	ImportedBundles []string `json:"imported_bundles,omitempty"`
	Message         string   `json:"message,omitempty"`
}

// ImportStatus reports import progress per stream; each stream sequences,
// quarantines, and reports missing bundles independently of the others.
type ImportStatus struct {
	Streams []StreamImportStatus `json:"streams"`
}

type StreamImportStatus struct {
	Stream               string   `json:"stream"`
	LastImportedSequence int64    `json:"last_imported_sequence"`
	NextExpectedSequence int64    `json:"next_expected_sequence"`
	HighestSeenSequence  int64    `json:"highest_seen_sequence"`
	BlockingMissing      int64    `json:"blocking_missing_sequence,omitempty"`
	MissingRanges        []string `json:"missing_ranges"`
	QuarantinedSequences []int64  `json:"quarantined_sequences"`
	ReadyToImport        bool     `json:"ready_to_import"`
}

// Stream returns the import status for the named stream, or a zero value with
// that name if the stream is unknown.
func (st ImportStatus) Stream(name string) StreamImportStatus {
	for _, s := range st.Streams {
		if s.Stream == name {
			return s
		}
	}
	return StreamImportStatus{Stream: name}
}

func (s *HighServer) ImportStatus() (ImportStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.quarantineFutureBundlesLocked(); err != nil {
		return ImportStatus{}, err
	}
	return s.importStatusLocked()
}

// knownStreamsLocked returns every stream that has imported state or bundles
// waiting in landing/quarantine, sorted for stable output.
func (s *HighServer) knownStreamsLocked() ([]string, error) {
	set := map[string]bool{}
	for stream := range s.state.Imported {
		set[stream] = true
	}
	for _, dir := range []string{s.cfg.Landing, s.cfg.Quarantine} {
		byStream, err := findBundleStreams(dir)
		if err != nil {
			return nil, err
		}
		for stream := range byStream {
			set[stream] = true
		}
	}
	streams := make([]string, 0, len(set))
	for stream := range set {
		streams = append(streams, stream)
	}
	sort.Strings(streams)
	return streams, nil
}

func (s *HighServer) ImportNext() (ImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.quarantineFutureBundlesLocked(); err != nil {
		return ImportResult{}, err
	}
	streams, err := s.knownStreamsLocked()
	if err != nil {
		return ImportResult{}, err
	}

	// Drain each stream independently: a gap in one stream never blocks another.
	var imported []string
	for _, stream := range streams {
		for {
			next := s.state.Imported[stream] + 1
			id := bundleIDFor(stream, next)
			bundleDir, ok := s.findBundleDirLocked(id)
			if !ok {
				break
			}
			manifest, err := s.importBundleFromDirLocked(bundleDir, stream, id, next)
			if err != nil {
				return ImportResult{}, err
			}
			imported = append(imported, manifest.BundleID)
		}
	}

	status, err := s.importStatusLocked()
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{Imported: len(imported) > 0, ImportedBundles: imported, Message: importWaitMessage(status)}, nil
}

// importWaitMessage summarizes which streams are blocked on a missing bundle.
func importWaitMessage(status ImportStatus) string {
	var waits []string
	for _, st := range status.Streams {
		if st.BlockingMissing > 0 {
			waits = append(waits, fmt.Sprintf("%s waiting for %d (missing %s)",
				st.Stream, st.BlockingMissing, strings.Join(st.MissingRanges, ",")))
		}
	}
	if len(waits) == 0 {
		return "all streams up to date"
	}
	return strings.Join(waits, "; ")
}

func (s *HighServer) importBundleFromDirLocked(bundleDir, stream, bundleID string, expectedSeq int64) (BundleManifest, error) {
	manifestPath := filepath.Join(bundleDir, bundleID+".manifest.json")
	sigPath := filepath.Join(bundleDir, bundleID+".manifest.json.sig")
	archivePath := filepath.Join(bundleDir, bundleID+".tar.gz")

	if !fileExists(manifestPath) || !fileExists(sigPath) || !fileExists(archivePath) {
		return BundleManifest{}, fmt.Errorf("bundle %s incomplete: need archive, manifest and signature", bundleID)
	}

	manifest, err := s.loadVerifiedManifest(manifestPath, sigPath, stream, bundleID, expectedSeq)
	if err != nil {
		return BundleManifest{}, err
	}

	staging := filepath.Join(s.cfg.Root, "tmp", bundleID)
	_ = os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return BundleManifest{}, err
	}
	defer os.RemoveAll(staging)

	if err := extractAndVerifyTarGz(archivePath, staging, manifest.Files); err != nil {
		return BundleManifest{}, err
	}
	if err := s.installVerifiedBundle(staging, manifest); err != nil {
		return BundleManifest{}, err
	}

	// The in-memory counter must never run ahead of the durable state: the
	// quarantine pass sorts landing bundles by the in-memory value, so after a
	// failed save it would file this bundle under duplicates/ as already
	// imported while the on-disk state still wants it — and duplicates/ is
	// never searched, wedging the stream there after a restart. On a failed
	// save, roll back so memory matches disk; the bundle stays in landing and
	// the next pass retries the whole import (installs are idempotent).
	prevSeq, hadStream := s.state.Imported[stream]
	prevAt := s.state.ImportedAt
	s.state.Imported[stream] = manifest.Sequence
	s.state.ImportedAt = time.Now().UTC()
	if err := s.saveStateLocked(); err != nil {
		if hadStream {
			s.state.Imported[stream] = prevSeq
		} else {
			delete(s.state.Imported, stream)
		}
		s.state.ImportedAt = prevAt
		return BundleManifest{}, fmt.Errorf("bundle %s: files installed but import state was not persisted (will retry): %w", bundleID, err)
	}
	if err := moveImportedFilesFromDir(bundleDir, filepath.Join(s.cfg.Landing, "imported"), manifest.BundleID); err != nil {
		log.Printf("move imported files: %v", err)
	}
	return manifest, nil
}

// loadVerifiedManifest reads the manifest and its detached signature, verifies
// the signature, and checks the manifest's identifying fields.
func (s *HighServer) loadVerifiedManifest(manifestPath, sigPath, stream, bundleID string, expectedSeq int64) (BundleManifest, error) {
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return BundleManifest{}, err
	}
	sigB64, err := os.ReadFile(sigPath)
	if err != nil {
		return BundleManifest{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return BundleManifest{}, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(s.publicKey, manifestBytes, sig) {
		return BundleManifest{}, fmt.Errorf("signature verification failed for %s", bundleID)
	}

	var manifest BundleManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return BundleManifest{}, err
	}
	if err := s.checkManifestFields(manifest, stream, bundleID, expectedSeq); err != nil {
		return BundleManifest{}, err
	}
	return manifest, nil
}

// checkManifestFields validates the manifest's type, stream, sequencing, and
// identity against what the importer expects next for that stream.
func (s *HighServer) checkManifestFields(manifest BundleManifest, stream, bundleID string, expectedSeq int64) error {
	gotStream := manifest.Stream
	if gotStream == "" {
		gotStream = streamGo // legacy single-stream manifests
	}
	switch {
	case manifest.Type != manifestType:
		return fmt.Errorf("wrong manifest type %q", manifest.Type)
	case gotStream != stream:
		return fmt.Errorf("stream mismatch: got %q, want %q", gotStream, stream)
	case manifest.Sequence != expectedSeq:
		return fmt.Errorf("sequence mismatch: got %d, want %d", manifest.Sequence, expectedSeq)
	case manifest.PreviousSequence != s.state.Imported[stream]:
		return fmt.Errorf("previous sequence mismatch: got %d, want %d", manifest.PreviousSequence, s.state.Imported[stream])
	case manifest.BundleID != bundleID:
		return fmt.Errorf("bundle_id mismatch: got %q, want %q", manifest.BundleID, bundleID)
	}
	return validateManifestCompleteness(manifest)
}

func (s *HighServer) quarantineFutureBundlesLocked() error {
	byStream, err := findBundleStreams(s.cfg.Landing)
	if err != nil {
		return err
	}
	for stream, seqs := range byStream {
		next := s.state.Imported[stream] + 1
		for _, seq := range seqs {
			if err := s.sortLandingBundleLocked(stream, seq, next); err != nil {
				return err
			}
		}
	}
	return nil
}

// sortLandingBundleLocked moves a complete bundle out of the landing directory
// when it cannot be imported next: a future bundle (seq > next) goes to
// quarantine, an already-imported one (seq <= last imported) goes to
// duplicates. The bundle at exactly next is left in place for import.
func (s *HighServer) sortLandingBundleLocked(stream string, seq, next int64) error {
	id := bundleIDFor(stream, seq)
	if !bundleCompleteInDir(s.cfg.Landing, id) {
		return nil
	}
	switch {
	case seq > next:
		return moveBundleFiles(s.cfg.Landing, s.cfg.Quarantine, id)
	case seq <= s.state.Imported[stream]:
		return moveBundleFiles(s.cfg.Landing, filepath.Join(s.cfg.Landing, "duplicates"), id)
	}
	return nil
}

func (s *HighServer) findBundleDirLocked(bundleID string) (string, bool) {
	if bundleCompleteInDir(s.cfg.Landing, bundleID) {
		return s.cfg.Landing, true
	}
	if bundleCompleteInDir(s.cfg.Quarantine, bundleID) {
		return s.cfg.Quarantine, true
	}
	return "", false
}

func (s *HighServer) importStatusLocked() (ImportStatus, error) {
	landing, err := findBundleStreams(s.cfg.Landing)
	if err != nil {
		return ImportStatus{}, err
	}
	quarantined, err := findBundleStreams(s.cfg.Quarantine)
	if err != nil {
		return ImportStatus{}, err
	}
	streams, err := s.knownStreamsLocked()
	if err != nil {
		return ImportStatus{}, err
	}
	out := ImportStatus{Streams: make([]StreamImportStatus, 0, len(streams))}
	for _, stream := range streams {
		out.Streams = append(out.Streams, s.streamStatusLocked(stream, landing[stream], quarantined[stream]))
	}
	return out, nil
}

func (s *HighServer) streamStatusLocked(stream string, landing, quarantined []int64) StreamImportStatus {
	present := map[int64]bool{}
	maxSeen := s.state.Imported[stream]
	maxSeen = markPresentComplete(s.cfg.Landing, stream, landing, present, maxSeen)
	maxSeen = markPresentComplete(s.cfg.Quarantine, stream, quarantined, present, maxSeen)

	next := s.state.Imported[stream] + 1
	missing := missingRanges(next, maxSeen, present)
	st := StreamImportStatus{
		Stream:               stream,
		LastImportedSequence: s.state.Imported[stream],
		NextExpectedSequence: next,
		HighestSeenSequence:  maxSeen,
		MissingRanges:        rangesToStrings(missing),
		QuarantinedSequences: filterCompleteSequences(s.cfg.Quarantine, stream, quarantined),
		ReadyToImport:        present[next],
	}
	if !present[next] && maxSeen >= next {
		st.BlockingMissing = next
	}
	return st
}

// markPresentComplete marks every complete bundle of the stream in dir as
// present and returns the updated highest-seen sequence.
func markPresentComplete(dir, stream string, seqs []int64, present map[int64]bool, maxSeen int64) int64 {
	for _, seq := range seqs {
		if bundleCompleteInDir(dir, bundleIDFor(stream, seq)) {
			present[seq] = true
			if seq > maxSeen {
				maxSeen = seq
			}
		}
	}
	return maxSeen
}

// manifestEcoCheck pairs "this ecosystem has content in the manifest" with the
// validator to run over it.
type manifestEcoCheck struct {
	present bool
	check   func(map[string]bool) error
}

func manifestEcoChecks(m BundleManifest) []manifestEcoCheck {
	return []manifestEcoCheck{
		{len(m.Modules) > 0, func(s map[string]bool) error { return validateManifestModules(m.Modules, s) }},
		{m.Python != nil && len(m.Python.Projects) > 0, func(s map[string]bool) error { return validatePythonProjects(m.Python.Projects, s) }},
		{m.Maven != nil && len(m.Maven.Artifacts) > 0, func(s map[string]bool) error { return validateMavenArtifacts(m.Maven.Artifacts, s) }},
		{m.Apt != nil && len(m.Apt.Mirrors) > 0, func(s map[string]bool) error { return validateAptMirrors(m.Apt.Mirrors, s) }},
		{m.Rpm != nil && len(m.Rpm.Mirrors) > 0, func(s map[string]bool) error { return validateRpmMirrors(m.Rpm.Mirrors, s) }},
		{m.Containers != nil && len(m.Containers.Repos) > 0, func(s map[string]bool) error { return validateContainerRepos(m.Containers.Repos, s, m.Files) }},
		{m.Npm != nil && len(m.Npm.Packages) > 0, func(s map[string]bool) error { return validateNpmPackages(m.Npm.Packages, s) }},
		{m.HuggingFace != nil && (len(m.HuggingFace.Models) > 0 || len(m.HuggingFace.Repos) > 0), func(s map[string]bool) error { return validateHF(m.HuggingFace, s, m.Files) }},
		{m.Uploads != nil && len(m.Uploads.Files) > 0, func(s map[string]bool) error { return validateUploadsManifest(m.Uploads, s, m.Files) }},
	}
}

func validateManifestCompleteness(m BundleManifest) error {
	seen, err := validateManifestFiles(m.Files)
	if err != nil {
		return err
	}
	matched := false
	for _, e := range manifestEcoChecks(m) {
		if !e.present {
			continue
		}
		matched = true
		if err := e.check(seen); err != nil {
			return err
		}
	}
	if !matched {
		return errors.New("manifest contains no modules, python projects, maven artifacts, apt mirrors, rpm mirrors, container repos, npm packages, hugging face models, or uploaded files")
	}
	return nil
}

// validateManifestFiles checks each listed file's path and hash, returning the
// set of valid file paths.
func validateManifestFiles(files []ManifestFile) (map[string]bool, error) {
	seen := map[string]bool{}
	for _, f := range files {
		if err := validateRelPath(f.Path); err != nil {
			return nil, fmt.Errorf("invalid file path %q: %w", f.Path, err)
		}
		if f.SHA256 == "" || len(f.SHA256) != 64 {
			return nil, fmt.Errorf("invalid sha256 for %s", f.Path)
		}
		seen[f.Path] = true
	}
	return seen, nil
}

// validateManifestModules checks that every module lists the required file
// kinds and that each references a file present in the manifest's file set.
func validateManifestModules(mods []ManifestMod, seen map[string]bool) error {
	for _, mod := range mods {
		if mod.Module == "" || mod.Version == "" {
			return errors.New("module entry missing module or version")
		}
		for _, kind := range []string{"info", "mod", "zip"} {
			f, ok := mod.Files[kind]
			if !ok {
				return fmt.Errorf("%s@%s missing %s file", mod.Module, mod.Version, kind)
			}
			if !seen[f.Path] {
				return fmt.Errorf("%s@%s references file not listed in manifest.files: %s", mod.Module, mod.Version, f.Path)
			}
		}
	}
	return nil
}

func (s *HighServer) installVerifiedBundle(staging string, manifest BundleManifest) error {
	if err := s.installVerifiedFiles(staging, manifest.Files, goFilePaths(manifest.Modules)); err != nil {
		return err
	}
	// Regenerate APT repository metadata from the accumulated stanzas of the
	// .deb files now present (never trusting the transferred Release/Packages).
	if err := s.publishApt(manifest.Apt); err != nil {
		return err
	}
	if err := s.publishRpm(manifest.Rpm); err != nil {
		return err
	}
	if err := s.publishContainers(manifest.Containers); err != nil {
		return err
	}
	// Regenerate the served npm metadata from each tarball's own embedded
	// package.json (never trusting a transferred packument).
	if err := s.publishNpm(manifest.Npm); err != nil {
		return err
	}
	if err := s.publishHF(manifest.HuggingFace); err != nil {
		return err
	}
	// Complete markers are written only after all files are installed.
	return s.writeCompleteMarkers(manifest.Modules)
}

// goFilePaths collects the manifest paths that belong to Go modules, so the
// importer can place them under the go/ subtree while the other ecosystems keep
// their already-namespaced paths.
func goFilePaths(mods []ManifestMod) map[string]bool {
	if len(mods) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, m := range mods {
		for _, f := range m.Files {
			set[f.Path] = true
		}
	}
	return set
}

// installVerifiedFiles copies every verified file into the accumulated
// repository. Go module files (bare module paths, listed in goFiles) are placed
// under the go/ subtree; every other ecosystem's paths already carry their own
// prefix and install at the download root.
func (s *HighServer) installVerifiedFiles(staging string, files []ManifestFile, goFiles map[string]bool) error {
	for _, f := range files {
		base := s.downloadDir
		if goFiles[f.Path] {
			base = s.goModuleDir()
		}
		if err := installVerifiedFile(staging, base, f); err != nil {
			return err
		}
	}
	return nil
}

// installVerifiedFile copies one verified file from staging into base, refusing
// to overwrite an existing immutable file with different content. An existing
// file whose content already matches is a no-op, so re-imports are idempotent.
// A prior file (delta bundles) is not in staging at all: it must already sit in
// the accumulated repository from an earlier bundle.
func installVerifiedFile(staging, base string, f ManifestFile) error {
	src := filepath.Join(staging, filepath.FromSlash(f.Path))
	dst := filepath.Join(base, filepath.FromSlash(f.Path))
	if !safeJoin(base, dst) {
		return fmt.Errorf("unsafe destination %s", f.Path)
	}
	if f.Prior {
		return requirePriorFile(dst, f)
	}
	if fileExists(dst) {
		existing, err := sha256File(dst)
		if err != nil {
			return err
		}
		if existing == f.SHA256 {
			return nil
		}
		// Operator-uploaded files are the one mutable subtree: re-uploading a
		// name legitimately replaces its content (copyFileAtomic renames over
		// the old file). Every mirrored ecosystem stays immutable.
		if !strings.HasPrefix(f.Path, "uploads/") {
			return fmt.Errorf("immutable file conflict for %s", f.Path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return copyFileAtomic(src, dst, 0o644)
}

// requirePriorFile verifies a delta bundle's claim that an earlier bundle
// already delivered this file. Existence and size are checked, not the hash:
// the content was verified byte-for-byte when it first landed, files in the
// repository are immutable, and re-hashing every prior file would make a large
// mirror's delta import cost as much as a full one. A miss means the earlier
// bundles of this stream were never imported here (or the repository was
// rebuilt) — recovered by importing them, or by a forced full re-collect on
// the low side.
func requirePriorFile(dst string, f ManifestFile) error {
	st, err := os.Stat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bundle references prior file %s (sha256 %s) that is not in the repository: import this stream's earlier bundles first, or run a forced (full) re-collect on the low side", f.Path, f.SHA256)
	}
	if err != nil {
		return err
	}
	if st.Size() != f.Size {
		return fmt.Errorf("prior file %s: size %d on disk does not match manifest size %d", f.Path, st.Size(), f.Size)
	}
	return nil
}

// writeCompleteMarkers writes a .complete marker for each module once all of
// its files are installed.
func (s *HighServer) writeCompleteMarkers(mods []ManifestMod) error {
	for _, mod := range mods {
		infoPath := mod.Files["info"].Path
		versionEsc := strings.TrimSuffix(path.Base(infoPath), ".info")
		moduleEsc, err := moduleEscFromInfoPath(infoPath)
		if err != nil {
			return err
		}
		marker := filepath.Join(s.goModuleDir(), filepath.FromSlash(moduleEsc), "@v", versionEsc+completeExt)
		if err := writeBytesAtomic(marker, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// moduleEscFromInfoPath derives the escaped module path from the relative path
// of its .info file (e.g. "m/@v/v1.0.0.info" -> "m").
func moduleEscFromInfoPath(infoPath string) (string, error) {
	moduleEsc := strings.TrimSuffix(strings.TrimSuffix(infoPath, "/@v/"+path.Base(infoPath)), "/@v")
	if moduleEsc == infoPath { // fallback to split
		idx := strings.LastIndex(infoPath, "/@v/")
		if idx < 0 {
			return "", fmt.Errorf("cannot derive module path from %s", infoPath)
		}
		moduleEsc = infoPath[:idx]
	}
	return moduleEsc, nil
}

// -----------------------------------------------------------------------------
// GOPROXY request parsing
// -----------------------------------------------------------------------------

type proxyKind int

const (
	proxyUnknown proxyKind = iota
	proxyList
	proxyLatest
	proxyVersionFile
)

type ProxyRequest struct {
	Kind           proxyKind
	ModuleEscaped  string
	Module         string
	VersionEscaped string
	Version        string
	Ext            string
	RelativePath   string
}

func parseProxyRequest(urlPath string) (ProxyRequest, error) {
	rel := strings.TrimPrefix(urlPath, "/")
	rel = path.Clean("/" + rel)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "." || rel == "" {
		return ProxyRequest{}, errors.New("empty path")
	}
	if err := validateRelPath(rel); err != nil {
		return ProxyRequest{}, err
	}

	if strings.HasSuffix(rel, "/@latest") {
		modEsc := strings.TrimSuffix(rel, "/@latest")
		mod, err := unescapeModulePath(modEsc)
		if err != nil {
			return ProxyRequest{}, err
		}
		return ProxyRequest{Kind: proxyLatest, ModuleEscaped: modEsc, Module: mod, RelativePath: rel}, nil
	}

	idx := strings.LastIndex(rel, "/@v/")
	if idx < 0 {
		return ProxyRequest{}, errors.New("not a GOPROXY path")
	}
	modEsc := rel[:idx]
	suffix := rel[idx+len("/@v/"):]
	mod, err := unescapeModulePath(modEsc)
	if err != nil {
		return ProxyRequest{}, err
	}
	if suffix == "list" {
		return ProxyRequest{Kind: proxyList, ModuleEscaped: modEsc, Module: mod, RelativePath: rel}, nil
	}
	for _, ext := range []string{".info", ".mod", ".zip", ".ziphash"} {
		if strings.HasSuffix(suffix, ext) {
			verEsc := strings.TrimSuffix(suffix, ext)
			ver, err := unescapeVersion(verEsc)
			if err != nil {
				return ProxyRequest{}, err
			}
			return ProxyRequest{Kind: proxyVersionFile, ModuleEscaped: modEsc, Module: mod, VersionEscaped: verEsc, Version: ver, Ext: ext, RelativePath: rel}, nil
		}
	}
	return ProxyRequest{}, errors.New("unknown GOPROXY path")
}

// -----------------------------------------------------------------------------
// Semver/latest helpers. These implement enough Go/SemVer ordering for proxy latest.
// -----------------------------------------------------------------------------

var (
	semverRE     = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?(?:\+incompatible)?$`)
	pseudoTimeRE = regexp.MustCompile(`(?:^|[-.])([0-9]{14})-[0-9A-Fa-f]{7,}$`)
)

type parsedSemver struct {
	ok                  bool
	major, minor, patch int64
	pre                 string
}

func parseSemver(v string) parsedSemver {
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return parsedSemver{}
	}
	maj, _ := strconv.ParseInt(m[1], 10, 64)
	minr, _ := strconv.ParseInt(m[2], 10, 64)
	pat, _ := strconv.ParseInt(m[3], 10, 64)
	return parsedSemver{ok: true, major: maj, minor: minr, patch: pat, pre: m[4]}
}

func isValidSemver(v string) bool { return parseSemver(v).ok }

func isPseudoVersion(v string) bool { return pseudoTimeRE.MatchString(v) }

func compareVersions(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	if !pa.ok && !pb.ok {
		return strings.Compare(a, b)
	}
	if !pa.ok {
		return -1
	}
	if !pb.ok {
		return 1
	}
	for _, pair := range [][2]int64{{pa.major, pb.major}, {pa.minor, pb.minor}, {pa.patch, pb.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	// Release > pre-release.
	if pa.pre == "" && pb.pre != "" {
		return 1
	}
	if pa.pre != "" && pb.pre == "" {
		return -1
	}
	return comparePrerelease(pa.pre, pb.pre)
}

func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		if c := comparePrereleaseIdent(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return 0
}

// comparePrereleaseIdent orders a single dot-separated pre-release identifier.
// Numeric identifiers compare numerically and rank below alphanumeric ones.
func comparePrereleaseIdent(a, b string) int {
	ai, aErr := strconv.ParseInt(a, 10, 64)
	bi, bErr := strconv.ParseInt(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		default:
			return 0
		}
	case aErr == nil: // numeric identifiers have lower precedence
		return -1
	case bErr == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func sortVersionsAsc(vs []string) {
	sort.Slice(vs, func(i, j int) bool { return compareVersions(vs[i], vs[j]) < 0 })
}

func filterNonPseudoValid(vs []string) []string {
	out := make([]string, 0, len(vs))
	seen := map[string]bool{}
	for _, v := range vs {
		if !seen[v] && isValidSemver(v) && !isPseudoVersion(v) {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

func chooseLatest(infos []ModuleInfo) (ModuleInfo, bool) {
	var releases, pres, pseudos []ModuleInfo
	for _, info := range infos {
		v := info.Version
		if isPseudoVersion(v) {
			pseudos = append(pseudos, info)
			continue
		}
		p := parseSemver(v)
		if !p.ok {
			continue
		}
		if p.pre == "" {
			releases = append(releases, info)
		} else {
			pres = append(pres, info)
		}
	}
	sortInfoVersionDesc := func(xs []ModuleInfo) {
		sort.Slice(xs, func(i, j int) bool { return compareVersions(xs[i].Version, xs[j].Version) > 0 })
	}
	if len(releases) > 0 {
		sortInfoVersionDesc(releases)
		return releases[0], true
	}
	if len(pres) > 0 {
		sortInfoVersionDesc(pres)
		return pres[0], true
	}
	if len(pseudos) > 0 {
		sort.Slice(pseudos, func(i, j int) bool { return pseudos[i].Time.After(pseudos[j].Time) })
		return pseudos[0], true
	}
	return ModuleInfo{}, false
}

// -----------------------------------------------------------------------------
// Path escaping helpers
// -----------------------------------------------------------------------------

func unescapeModulePath(s string) (string, error) { return unescapeBang(s) }
func unescapeVersion(s string) (string, error)    { return unescapeBang(s) }

func unescapeBang(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '!' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", errors.New("invalid escaped path: trailing bang")
		}
		n := s[i+1]
		if n < 'a' || n > 'z' {
			return "", fmt.Errorf("invalid escaped path: !%c", n)
		}
		b.WriteByte(n - ('a' - 'A'))
		i++
	}
	return b.String(), nil
}

func escapePathApprox(s string) string    { return escapeBang(s) }
func escapeVersionApprox(s string) string { return escapeBang(s) }

func escapeBang(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func validateRelPath(rel string) error {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return errors.New("invalid relative path")
	}
	clean := path.Clean(rel)
	if clean == "." || clean != rel || strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return errors.New("invalid relative path")
	}
	return nil
}

// -----------------------------------------------------------------------------
// Archive, hashes, atomic files
// -----------------------------------------------------------------------------

func hashManifestFile(abs, rel string) (ManifestFile, error) {
	st, err := os.Stat(abs)
	if err != nil {
		return ManifestFile{}, err
	}
	if st.IsDir() {
		return ManifestFile{}, fmt.Errorf("%s is a directory", abs)
	}
	h, err := sha256File(abs)
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: filepath.ToSlash(rel), SHA256: h, Size: st.Size()}, nil
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// createTarGzAtomic packs the files into dst. Packing a large bundle takes
// real time (gzip over gigabytes), so it drives the dashboard's progress bar
// through the context's download sink and honors cancellation between chunks
// — a stopped collect aborts here and the temp file is removed, so a bundle
// is either fully produced or not at all.
func createTarGzAtomic(ctx context.Context, dst string, baseDir string, files []ManifestFile) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	var total int64
	for _, mf := range files {
		total += mf.Size
	}
	tracker := newProgressTracker(ctx, "packing "+filepath.Base(dst), total)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, mf := range files {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("packing stopped: %w", err)
		}
		if err := addFileToTar(ctx, tw, baseDir, mf, tracker); err != nil {
			return err
		}
	}
	tracker.finish()
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

// addFileToTar writes a single repository file into the tar stream with a
// deterministic header, counting its bytes toward the pack tracker.
func addFileToTar(ctx context.Context, tw *tar.Writer, baseDir string, mf ManifestFile, tracker *progressTracker) error {
	if err := validateRelPath(mf.Path); err != nil {
		return err
	}
	abs := filepath.Join(baseDir, filepath.FromSlash(mf.Path))
	st, err := os.Stat(abs)
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: mf.Path, Mode: 0o644, Size: st.Size(), ModTime: time.Unix(0, 0).UTC()}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	in, err := os.Open(abs)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(tw, &packSource{ctx: ctx, r: in, tracker: tracker})
	closeErr := in.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// packSource feeds one file into the archive, counting bytes toward the pack
// tracker and aborting between chunks when the collect is cancelled.
type packSource struct {
	ctx     context.Context
	r       io.Reader
	tracker *progressTracker
}

func (p *packSource) Read(b []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, fmt.Errorf("packing stopped: %w", err)
	}
	n, err := p.r.Read(b)
	p.tracker.add(int64(n))
	return n, err
}

// expectedArchiveFiles maps the file paths a bundle's archive must contain:
// every manifest file except prior references, which are not packed — the
// install step verifies those against the accumulated repository instead. A
// bundle whose archive carries a file it also marks prior fails extraction as
// "unexpected file", since the two claims contradict each other.
func expectedArchiveFiles(files []ManifestFile) (map[string]ManifestFile, error) {
	expected := map[string]ManifestFile{}
	for _, f := range files {
		if err := validateRelPath(f.Path); err != nil {
			return nil, err
		}
		if !f.Prior {
			expected[f.Path] = f
		}
	}
	return expected, nil
}

func extractAndVerifyTarGz(archivePath, staging string, files []ManifestFile) error {
	expected, err := expectedArchiveFiles(files)
	if err != nil {
		return err
	}
	seen := map[string]bool{}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := extractTarEntry(tr, hdr, staging, expected); err != nil {
			return err
		}
		seen[hdr.Name] = true
	}
	for p := range expected {
		if !seen[p] {
			return fmt.Errorf("archive missing file %s", p)
		}
	}
	return nil
}

// extractTarEntry validates one tar entry against the manifest, then writes it
// into staging while verifying its size and SHA-256.
func extractTarEntry(tr *tar.Reader, hdr *tar.Header, staging string, expected map[string]ManifestFile) error {
	if hdr.Typeflag != tar.TypeReg {
		return fmt.Errorf("archive contains non-regular file %s", hdr.Name)
	}
	mf, ok := expected[hdr.Name]
	if !ok {
		return fmt.Errorf("archive contains unexpected file %s", hdr.Name)
	}
	if hdr.Size != mf.Size {
		return fmt.Errorf("size mismatch for %s: got %d want %d", hdr.Name, hdr.Size, mf.Size)
	}
	dst := filepath.Join(staging, filepath.FromSlash(hdr.Name))
	if !safeJoin(staging, dst) {
		return fmt.Errorf("unsafe archive path %s", hdr.Name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, h), tr)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != mf.SHA256 {
		return fmt.Errorf("sha256 mismatch for %s: got %s want %s", hdr.Name, got, mf.SHA256)
	}
	return nil
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeJSONAtomic(p string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeBytesAtomic(p, b, mode)
}

func writeBytesAtomic(p string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	// fsync the contents before the rename so a crash cannot leave a truncated
	// or zero-length file where the previous good one was. This backs the state
	// files, bundle manifests, signatures, and .complete markers.
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	ok = true
	fsyncDir(dir)
	return nil
}

// fsyncDir flushes a directory so a rename into it survives a crash. It is
// best-effort: some filesystems do not support directory fsync, and a failure
// to open or sync the directory must not fail an otherwise-completed write.
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
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

// bundleManifestNameRE captures the stream name and sequence from a manifest
// filename like "go-bundle-000042.manifest.json" or "apt-bundle-000001...". The
// digits match six-or-more so numbering stays zero-padded to six for
// readability without capping at 999999 (%06d is a minimum width).
var bundleManifestNameRE = regexp.MustCompile(`^([a-z0-9]+)-bundle-([0-9]{6,})\.manifest\.json$`)

// bundleIDFor renders the on-disk id for a stream's sequence, e.g.
// "go-bundle-000042" or "apt-bundle-000001". Each ecosystem has its own stream,
// so a lost or stalled bundle in one stream never blocks the others.
func bundleIDFor(stream string, seq int64) string {
	return fmt.Sprintf("%s-bundle-%06d", stream, seq)
}

// parseBundleName extracts the stream and sequence from a manifest filename.
func parseBundleName(name string) (stream string, seq int64, ok bool) {
	m := bundleManifestNameRE.FindStringSubmatch(name)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return m[1], n, true
}

// bundleIDForSequence is a convenience for the "go" stream (its ids match the
// pre-multi-stream scheme, easing migration).
func bundleIDForSequence(seq int64) string { return bundleIDFor(streamGo, seq) }

func bundleCompleteInDir(dir, bundleID string) bool {
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		if !fileExists(filepath.Join(dir, bundleID+suffix)) {
			return false
		}
	}
	return true
}

// bundleSizeInDir returns the total size in bytes of the bundle's files present
// in dir (archive + manifest + signature); missing files simply contribute 0.
func bundleSizeInDir(dir, bundleID string) int64 {
	var total int64
	for _, suffix := range bundleSuffixes() {
		if fi, err := os.Stat(filepath.Join(dir, bundleID+suffix)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// findBundleStreams groups the manifest files in dir by stream, returning each
// stream's sorted sequence numbers.
func findBundleStreams(dir string) (map[string][]int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]int64{}, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]map[int64]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if stream, seq, ok := parseBundleName(e.Name()); ok {
			if seen[stream] == nil {
				seen[stream] = map[int64]bool{}
			}
			seen[stream][seq] = true
		}
	}
	out := make(map[string][]int64, len(seen))
	for stream, set := range seen {
		seqs := make([]int64, 0, len(set))
		for seq := range set {
			seqs = append(seqs, seq)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		out[stream] = seqs
	}
	return out, nil
}

func filterCompleteSequences(dir, stream string, seqs []int64) []int64 {
	out := make([]int64, 0, len(seqs))
	for _, seq := range seqs {
		if bundleCompleteInDir(dir, bundleIDFor(stream, seq)) {
			out = append(out, seq)
		}
	}
	return out
}

func moveBundleFiles(srcDir, dstDir, bundleID string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, suffix := range bundleSuffixes() {
		src := filepath.Join(srcDir, bundleID+suffix)
		if !fileExists(src) {
			continue
		}
		if err := moveFile(src, filepath.Join(dstDir, bundleID+suffix), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// moveFile moves src to dst. It uses rename when possible, and falls back to
// copy+remove when they are on different filesystems. That happens in
// containerized deployments where the landing directory and the repository root
// are separate mounts/volumes, in which case rename returns EXDEV
// ("invalid cross-device link").
func moveFile(src, dst string, mode os.FileMode) error {
	_ = os.Remove(dst)
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyFileAtomic(src, dst, mode); err != nil {
		return err
	}
	return os.Remove(src)
}

func moveImportedFilesFromDir(srcDir, importedDir, bundleID string) error {
	return moveBundleFiles(srcDir, importedDir, bundleID)
}

func parseSequenceSpec(spec string) ([]SequenceRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("empty sequence range")
	}
	var ranges []SequenceRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r, err := parseSequenceRangePart(part)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	if len(ranges) == 0 {
		return nil, errors.New("empty sequence range")
	}
	return mergeSequenceRanges(ranges), nil
}

// parseSequenceRangePart parses a single "N" or "N-M" token into an inclusive,
// positive, non-descending range.
func parseSequenceRangePart(part string) (SequenceRange, error) {
	r, err := parseRangeBounds(part)
	if err != nil {
		return SequenceRange{}, err
	}
	if r.Start <= 0 || r.End <= 0 || r.End < r.Start {
		return SequenceRange{}, fmt.Errorf("invalid sequence range %q", part)
	}
	return r, nil
}

func parseRangeBounds(part string) (SequenceRange, error) {
	if !strings.Contains(part, "-") {
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return SequenceRange{}, fmt.Errorf("invalid sequence %q", part)
		}
		return SequenceRange{Start: n, End: n}, nil
	}
	parts := strings.SplitN(part, "-", 2)
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return SequenceRange{}, fmt.Errorf("invalid range start %q", parts[0])
	}
	end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return SequenceRange{}, fmt.Errorf("invalid range end %q", parts[1])
	}
	return SequenceRange{Start: start, End: end}, nil
}

func mergeSequenceRanges(in []SequenceRange) []SequenceRange {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start == in[j].Start {
			return in[i].End < in[j].End
		}
		return in[i].Start < in[j].Start
	})
	out := []SequenceRange{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End+1 {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func expandSequenceRanges(ranges []SequenceRange, limit int) []int64 {
	var out []int64
	for _, r := range ranges {
		for n := r.Start; n <= r.End; n++ {
			if limit > 0 && len(out) >= limit {
				return out
			}
			out = append(out, n)
		}
	}
	return out
}

func rangesToStrings(ranges []SequenceRange) []string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, r.String())
	}
	return out
}

func missingRanges(start, end int64, present map[int64]bool) []SequenceRange {
	if end < start {
		return nil
	}
	var out []SequenceRange
	var cur *SequenceRange
	for n := start; n <= end; n++ {
		if present[n] {
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if cur == nil {
			cur = &SequenceRange{Start: n, End: n}
		} else {
			cur.End = n
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}
