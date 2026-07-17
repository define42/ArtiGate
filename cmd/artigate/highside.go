package main

// The high side: the unauthenticated server for already-verified public
// content. It trusts nothing transferred — a bundle imports only after its
// Ed25519ph manifest signature, per-stream sequence, and every file's SHA-256
// check out — and anything else lands in quarantine or rejected/, bounded by
// retention reaping. This file holds the high server, the strictly sequential
// verify-and-import pipeline, and the Go module proxy endpoints; the other
// ecosystems' serve sides live in their own files.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// maxFutureSequenceGap bounds untrusted quarantine state. Normal operation
// produces consecutive bundles, so ten thousand outstanding predecessors is
// already far beyond a credible delivery reordering window.
const maxFutureSequenceGap int64 = 10_000

const (
	// rejectedRetention bounds how long terminally rejected bundles occupy the
	// shared unverified-bytes quota before being reaped. A rejected bundle never
	// imports on its own — recovery is a low-side re-export — so retaining it
	// only preserves its reason file for diagnostics, and only for a while.
	rejectedRetention = 7 * 24 * time.Hour
	// incompleteLandingRetention bounds how long a partial landing set (missing
	// one of the three bundle files) is kept. A real transfer completes in
	// minutes to hours; a set still incomplete long after was orphaned by an
	// interrupted transfer and would otherwise pin the quota forever.
	incompleteLandingRetention = 48 * time.Hour
	// processedLandingRetention bounds how long already-processed bundle files
	// (landing/imported and landing/duplicates) are kept for diagnostics. The
	// authoritative replay copy lives in the low side's bundle archive, so
	// retaining these forever would accumulate a compressed second copy of
	// everything ever imported and eventually fill the landing volume.
	processedLandingRetention = 7 * 24 * time.Hour
)

type HighConfig struct {
	Listen         string
	Root           string
	Landing        string
	Quarantine     string
	PublicKeyPath  string
	ImportInterval time.Duration
	AptGPGKey      string
	RpmGPGKey      string
	// ApkRSAKey is a PEM RSA private key path used to sign regenerated Alpine
	// APKINDEX files; ApkKeyName is the filename clients install the matching
	// public key under (/etc/apk/keys/<name>). Unset serves indexes unsigned
	// (clients then need --allow-untrusted).
	ApkRSAKey  string
	ApkKeyName string
	// DiodeIngest accepts bundle uploads at PUT/POST /diode/<file> into the
	// landing directory (ARTIGATE_DIODE_INGEST=on); DiodeToken requires a
	// bearer token on those uploads (ARTIGATE_DIODE_TOKEN).
	DiodeIngest bool
	DiodeToken  string
	// AllowRemoteAdmin permits the high side's state-changing admin endpoints
	// (POST /admin/uploads/delete, POST /admin/import) to be driven from other
	// hosts (ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN=on). By default they are restricted
	// to loopback callers, because the high side is otherwise unauthenticated and
	// these endpoints mutate served content. Read-only serving is unaffected.
	AllowRemoteAdmin bool
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
	ingestMu    sync.Mutex
	state       HighState
	tree        treeCache
	importKick  chan struct{}
	importOnce  sync.Once
	// metrics holds the in-memory import/reject/gap counters the /metrics
	// endpoint reports; notifier posts failure webhooks (nil when unconfigured).
	metrics  *highMetrics
	notifier *webhookNotifier
	// npmAudit memoizes the regenerated npm bulk-audit index (see
	// osvnpmaudit.go) so audit requests do not re-parse it from disk.
	npmAudit npmAuditCache
	// pyDigests memoizes each wheel's SHA-256 and Requires-Python so the
	// unauthenticated /simple/<project>/ page does not re-hash and re-open
	// every wheel on every pip request (see pyProjectFiles).
	pyDigests pyDigestCache
	// detailDigests memoizes artifact SHA-256 digests for the unauthenticated
	// /ui/api/detail panel, so repeated detail requests do not re-hash the
	// selected artifact on every hit (see detailDigestCache).
	detailDigests detailDigestCache
	// derivedBlocks tracks osv derived-state files (stored metadata, the npm
	// audit index) whose stale bytes a failed publish could not get off the
	// disk; the osv read paths treat a blocked path as absent (see
	// suppressStaleDerived in osv.go).
	derivedBlocks derivedBlockSet
}

// applyHighEnvConfig fills the environment-driven high-side settings (diode
// ingest + token, remote-admin override), failing fast on an invalid value.
func applyHighEnvConfig(cfg *HighConfig) {
	ingest, err := parseOnOff(os.Getenv("ARTIGATE_DIODE_INGEST"))
	if err != nil {
		log.Fatalf("ARTIGATE_DIODE_INGEST: %v", err)
	}
	cfg.DiodeIngest = ingest
	cfg.DiodeToken = os.Getenv("ARTIGATE_DIODE_TOKEN")
	if cfg.DiodeIngest {
		must(validateDiodeToken(cfg.DiodeToken))
	}
	allowRemoteAdmin, err := parseOnOff(os.Getenv("ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN"))
	if err != nil {
		log.Fatalf("ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN: %v", err)
	}
	cfg.AllowRemoteAdmin = allowRemoteAdmin
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
	fs.StringVar(&cfg.ApkRSAKey, "apk-rsa-key", "", "PEM RSA private key path used to sign regenerated Alpine APKINDEX files; unset serves them unsigned")
	fs.StringVar(&cfg.ApkKeyName, "apk-key-name", "artigate.rsa.pub", "filename Alpine clients install the APK signing public key under (/etc/apk/keys/<name>)")
	_ = fs.Parse(args)
	// Identity first, before anything can fatal: on an air-gapped box the log
	// is often the only place an operator can read what this binary is.
	log.Printf("artigate high %s", versionSummary())
	if cfg.PublicKeyPath == "" {
		log.Fatal("--public-key is required")
	}
	applyHighEnvConfig(&cfg)
	pub, err := readPublicKey(cfg.PublicKeyPath)
	must(err)
	hs, err := NewHighServer(cfg, pub)
	must(err)
	hs.notifier = mustWebhookNotifier("high")
	startCatcherIfConfigured(hs)

	// A SIGINT/SIGTERM cancels this context, stopping the import loop and
	// draining the HTTP server on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.ImportInterval > 0 {
		go hs.importLoop(ctx)
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
	// The mutating admin endpoints are already loopback-gated; the CSRF guard
	// additionally blocks a same-host browser from being used cross-site against
	// them. Diode ingest PUTs come from non-browser clients and pass through.
	must(listenAndServe(ctx, tc, cfg.Listen, cfg.Root, logHTTP(csrfGuard(mux))))
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
	// <root>/tmp holds only per-bundle import staging, normally removed by the
	// importing pass itself. A hard kill (OOM, power loss) mid-import strands
	// the extracted copy — potentially many gigabytes — and nothing else ever
	// looks at it. No import can be running at construction, so sweep it.
	if err := os.RemoveAll(filepath.Join(cfg.Root, "tmp")); err != nil {
		return nil, err
	}
	// Bundles imported by a pre-sumdb-serving binary installed sumdb/ files
	// at the download root; move them where serveGoSumDB reads them.
	migrateLegacyGoSumDBDir(dl)
	hs := &HighServer{
		cfg:         cfg,
		publicKey:   pub,
		downloadDir: dl,
		statePath:   filepath.Join(cfg.Root, "import-state.json"),
		importKick:  make(chan struct{}, 1),
		metrics:     newHighMetrics(),
	}
	// Start the /readyz pass clock at construction: the import pipeline is
	// presumed fresh at startup and must complete a real pass within the grace
	// window, instead of reporting an infinite age (or failing readiness while
	// the very first tick is still pending).
	hs.metrics.recordImportPass(nil, time.Now().UTC())
	if err := hs.loadState(); err != nil {
		return nil, err
	}
	return hs, nil
}

// requestImport coalesces any number of HTTP/UDP completion notifications onto
// one worker and one pending slot. A burst can never create unbounded goroutines.
// Each import runs under panic recovery: the worker outlives every bundle, and
// one malformed bundle hitting an import bug must not crash the high side.
func (s *HighServer) requestImport() {
	s.importOnce.Do(func() {
		go func() {
			for range s.importKick {
				recoverWorkerPanic("diode import after landing", func() {
					if _, err := s.ImportNext(); err != nil {
						log.Printf("diode import after landing: %v", err)
					}
				})
			}
		}()
	})
	select {
	case s.importKick <- struct{}{}:
	default:
	}
}

func (s *HighServer) unverifiedTransportBytes() (int64, error) {
	return s.unverifiedTransportBytesExcept(nil)
}

// unverifiedTransportBytesExcept totals the bytes of transport data that has not
// yet been verified and installed — across the landing, quarantine, and rejected
// directories. A bundle that is swept out of landing into quarantine or rejected
// before its signature is checked still occupies disk, so all three must count
// against the single quota; measuring landing alone would let an attacker reset
// the quota by getting each bundle sorted out of it. skip, when non-nil, excludes
// matching file names (the UDP catcher passes it to leave out its own in-progress
// temp files, which it accounts for separately).
func (s *HighServer) unverifiedTransportBytesExcept(skip func(string) bool) (int64, error) {
	var total int64
	for _, dir := range []string{s.cfg.Landing, s.cfg.Quarantine, filepath.Join(s.cfg.Root, "rejected")} {
		n, err := directoryRegularFileBytesExcept(dir, skip)
		if err != nil {
			return 0, err
		}
		if n > math.MaxInt64-total {
			return 0, errors.New("unverified storage size overflow")
		}
		total += n
	}
	return total, nil
}

func (s *HighServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Each ecosystem claims its own URL space — Go under /go/, like every other
	// ecosystem under its own prefix — and reports whether it handled the
	// request; anything unclaimed is not found. The ecosystems get a look in
	// registry order, which is what makes that order load-bearing (hf before
	// containers; see ecosystems).
	if s.serveHighAdmin(w, r) || s.serveDiode(w, r) {
		return
	}
	for _, e := range ecosystems() {
		if e.serve(s, w, r) {
			return
		}
	}
	if s.serveUI(w, r) {
		return
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
	// The checksum-database passthrough lives beside the module endpoints
	// ($GOPROXY/sumdb/<name>/...) and must be routed before module parsing:
	// its paths are not module files. No module can collide with the sumdb/
	// prefix — a first path element without a dot is not a valid module path.
	if s.serveGoSumDB(w, r, strings.TrimPrefix(p, "/go")) {
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

// requireLocalAdmin gates the high side's state-changing admin endpoints. The
// high side serves already-verified public content unauthenticated, but its
// mutation endpoints must not be reachable from arbitrary hosts: by default they
// are restricted to loopback callers (including a reverse proxy on the same
// host), unless ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN is set. It writes a 403 and
// reports false when the caller is not allowed.
func (s *HighServer) requireLocalAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AllowRemoteAdmin || remoteAddrIsLoopback(r) {
		return true
	}
	http.Error(w, "admin endpoint restricted to local callers; set ARTIGATE_HIGH_ALLOW_REMOTE_ADMIN to permit remote access behind an authenticating proxy", http.StatusForbidden)
	return false
}

// serveHighAdmin handles the monitoring endpoints and /admin/* routes. It
// reports whether it has written a response for the request.
func (s *HighServer) serveHighAdmin(w http.ResponseWriter, r *http.Request) bool {
	if serveObservability(w, r, s.serveReadyz, s.serveMetrics) {
		return true
	}
	switch {
	case r.URL.Path == "/admin/import" && r.Method == http.MethodPost:
		if !s.requireLocalAdmin(w, r) {
			return true
		}
		res, err := s.ImportNext()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		writeJSON(w, res)
	case (r.URL.Path == "/admin/status" || r.URL.Path == "/admin/missing") && r.Method == http.MethodGet:
		// Read-only: these monitoring endpoints are unauthenticated, so they
		// must not run the quarantine sweep (which moves files and fires
		// webhooks). The background import loop and diode kick own that sweep.
		status, err := s.importStatusReadOnly()
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

// importLoop drives the timer-based import pipeline. Each pass runs under
// panic recovery: the loop outlives every bundle, and one malformed bundle
// hitting an import bug must not crash the high side.
func (s *HighServer) importLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.ImportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		recoverWorkerPanic("import", s.importTick)
	}
}

// importTick runs one timer-driven import attempt and logs its outcome.
func (s *HighServer) importTick() {
	res, err := s.ImportNext()
	if err != nil {
		s.metrics.recordImportError()
		log.Printf("import failed: %v", err)
		return
	}
	if res.Imported {
		log.Printf("imported bundles: %s", strings.Join(res.ImportedBundles, ", "))
	}
}

type ImportResult struct {
	Imported        bool     `json:"imported"`
	ImportedBundles []string `json:"imported_bundles,omitempty"`
	RejectedBundles []string `json:"rejected_bundles,omitempty"`
	Message         string   `json:"message,omitempty"`
}

// ImportStatus reports import progress per stream; each stream sequences,
// quarantines, and reports missing bundles independently of the others.
type ImportStatus struct {
	// Version and ManifestFormat identify the serving binary — what this
	// air-gapped high side runs and the newest bundle wire format it can
	// import — so /admin/status answers a fleet-upgrade check remotely.
	Version        string               `json:"version"`
	ManifestFormat int                  `json:"manifest_format"`
	Streams        []StreamImportStatus `json:"streams"`
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

// importStatusReadOnly reports the same per-stream status as ImportStatus but
// without the quarantine sweep, so an unauthenticated observer (the /metrics
// scrape, /readyz, the dashboard overview poll, and the /admin/status and
// /admin/missing monitoring endpoints) reports state without moving files on
// disk or firing quarantine webhooks.
func (s *HighServer) importStatusReadOnly() (ImportStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.importStatusLocked()
}

// knownStreamsLocked returns supported streams that have imported state or
// bundles waiting in landing/quarantine, sorted for stable output. Untrusted
// filename prefixes can never create importer streams.
func (s *HighServer) knownStreamsLocked() ([]string, error) {
	set := map[string]bool{}
	for stream := range s.state.Imported {
		if isKnownStream(stream) {
			set[stream] = true
		}
	}
	for _, dir := range []string{s.cfg.Landing, s.cfg.Quarantine} {
		byStream, err := findBundleStreams(dir)
		if err != nil {
			return nil, err
		}
		for stream := range byStream {
			if isKnownStream(stream) {
				set[stream] = true
			}
		}
	}
	streams := make([]string, 0, len(set))
	for stream := range set {
		streams = append(streams, stream)
	}
	sort.Strings(streams)
	return streams, nil
}

// ImportNext runs one full import pass and records its completion time and
// outcome for the /readyz pipeline/backlog checks, whichever path triggered it
// (the background loop, a diode-ingest kick, or a manual /admin/import).
func (s *HighServer) ImportNext() (ImportResult, error) {
	res, err := s.importPass()
	s.metrics.recordImportPass(err, time.Now().UTC())
	return res, err
}

func (s *HighServer) importPass() (ImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.quarantineFutureBundlesLocked(); err != nil {
		return ImportResult{}, err
	}
	streams, err := s.knownStreamsLocked()
	if err != nil {
		return ImportResult{}, err
	}

	var imported, rejected []string
	var streamErrors []error
	for _, stream := range streams {
		drained, fatalErr := s.drainStreamLocked(stream)
		imported = append(imported, drained.imported...)
		rejected = append(rejected, drained.rejected...)
		if fatalErr != nil {
			return ImportResult{
				Imported: len(imported) > 0, ImportedBundles: imported, RejectedBundles: rejected,
			}, fatalErr
		}
		if drained.operationalErr != nil {
			streamErrors = append(streamErrors, drained.operationalErr)
		}
	}

	s.reapUnverifiedLocked(time.Now())

	status, err := s.importStatusLocked()
	if err != nil {
		return ImportResult{}, err
	}
	s.observeGapsAndNotify(status)
	message := importWaitMessage(status)
	if len(rejected) > 0 {
		message = fmt.Sprintf("rejected invalid bundle(s): %s; %s", strings.Join(rejected, ", "), message)
	}
	result := ImportResult{
		Imported: len(imported) > 0, ImportedBundles: imported,
		RejectedBundles: rejected, Message: message,
	}
	return result, errors.Join(streamErrors...)
}

// observeGapsAndNotify updates the gap-age state from a fresh import status and
// fires one gap_detected webhook for each stream that just became blocked by a
// missing bundle. It is edge-triggered: a persistent gap notifies once and then
// only ages. Called from the import loop (not the /metrics scrape) so scraping
// never emits webhooks.
func (s *HighServer) observeGapsAndNotify(status ImportStatus) {
	if s.metrics == nil {
		return
	}
	for _, ev := range s.metrics.observeGaps(status, time.Now().UTC()) {
		s.notifier.notify("gap_detected", map[string]any{
			"stream": ev.stream, "blocking_sequence": ev.seq,
		})
	}
}

type streamDrainResult struct {
	imported       []string
	rejected       []string
	operationalErr error
}

// drainStreamLocked imports one stream until it reaches a gap or failure.
// Invalid bytes are rejected; retryable failures stay in place.
func (s *HighServer) drainStreamLocked(stream string) (streamDrainResult, error) {
	var result streamDrainResult
	for {
		next := s.state.Imported[stream] + 1
		id := bundleIDFor(stream, next)
		bundleDir, ok := s.findBundleDirLocked(id)
		if !ok {
			return result, nil
		}
		manifest, err := s.importBundleFromDirLocked(bundleDir, stream, id, next)
		if err == nil {
			result.imported = append(result.imported, manifest.BundleID)
			continue
		}
		return s.handleStreamImportError(result, bundleDir, id, err)
	}
}

func (s *HighServer) handleStreamImportError(result streamDrainResult, bundleDir, id string, err error) (streamDrainResult, error) {
	var invalid *invalidBundleError
	if !errors.As(err, &invalid) {
		result.operationalErr = fmt.Errorf("import %s: %w", id, err)
		return result, nil
	}
	reason := fmt.Sprintf("bundle %s rejected during import: %v", id, err)
	if moveErr := s.rejectBundleLocked(bundleDir, id, reason); moveErr != nil {
		return result, fmt.Errorf("%s; additionally failed to move it to rejected/: %w", reason, moveErr)
	}
	log.Print(reason)
	result.rejected = append(result.rejected, id)
	return result, nil
}

// invalidBundleError marks bytes that can never become importable without
// replacement. Operational errors and missing prior delta content are left
// unmarked so the same signed bundle remains available for retry.
type invalidBundleError struct{ err error }

func (e *invalidBundleError) Error() string { return e.err.Error() }
func (e *invalidBundleError) Unwrap() error { return e.err }

func invalidBundle(err error) error {
	return &invalidBundleError{err: err}
}

// manifestTooNewError marks a validly signed manifest whose wire format is
// newer than this binary understands — a newer low side is exporting to an
// older high side. The bytes are not invalid: the same bundle imports as soon
// as the high side is upgraded, so it must stay in landing as a retryable
// condition (blocking its stream, and surfacing through the import-pass error
// on /readyz) rather than be terminally rejected, whose only recovery would
// be a low-side re-export across the diode.
type manifestTooNewError struct {
	bundleID string
	format   int
}

func (e *manifestTooNewError) Error() string {
	return fmt.Sprintf("bundle %s uses manifest format %d, but this high side (version %s) understands only formats up to %d: "+
		"upgrade the ArtiGate high side; the bundle stays in landing and imports after the upgrade",
		e.bundleID, e.format, versionString(), manifestFormatCurrent)
}

// classifyManifestError keeps a too-new-format manifest retryable — the
// signed bytes become importable the moment the binary is upgraded — while
// every other manifest failure stays terminal for these bytes.
func classifyManifestError(err error) error {
	var tooNew *manifestTooNewError
	if errors.As(err, &tooNew) {
		return err
	}
	return invalidBundle(err)
}

// classifyExtractError decides whether a bundle extraction failure means the
// bundle is content-invalid (→ rejected) or was merely an operational local-I/O
// fault such as a full staging disk (→ retryable, left in place). Marking a
// disk-full extraction of a 64 GiB bundle as invalid would permanently eject a
// validly-signed bundle and wedge the stream, so those faults, tagged
// stagingIOError during extraction, stay unmarked.
func classifyExtractError(err error) error {
	var ioErr *stagingIOError
	if errors.As(err, &ioErr) {
		return ioErr.err
	}
	return invalidBundle(err)
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
	if err := validateBundleArtifactSizes(archivePath, manifestPath, sigPath); err != nil {
		return BundleManifest{}, err
	}

	manifest, err := s.loadVerifiedManifest(manifestPath, sigPath, stream, bundleID, expectedSeq)
	if err != nil {
		return BundleManifest{}, classifyManifestError(err)
	}

	staging := filepath.Join(s.cfg.Root, "tmp", bundleID)
	_ = os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return BundleManifest{}, err
	}
	defer os.RemoveAll(staging)

	if err := extractAndVerifyTarGz(archivePath, staging, manifest.Files); err != nil {
		return BundleManifest{}, classifyExtractError(err)
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
	if err := s.commitImportedStateLocked(stream, bundleID, manifest.Sequence); err != nil {
		return BundleManifest{}, err
	}
	// The freshly installed artifacts must show up in the dashboard tree right
	// away, not after the scan cache's TTL.
	s.tree.invalidate()
	if err := moveImportedFilesFromDir(bundleDir, filepath.Join(s.cfg.Landing, "imported"), manifest.BundleID); err != nil {
		log.Printf("move imported files: %v", err)
	}
	return manifest, nil
}

func validateBundleArtifactSizes(paths ...string) error {
	for _, p := range paths {
		limit, _ := bundleFileSizeLimit(filepath.Base(p))
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if info.Size() > limit {
			return invalidBundle(fmt.Errorf("%s is %s, exceeds %s limit", filepath.Base(p), formatBytes(info.Size()), formatBytes(limit)))
		}
	}
	return nil
}

func (s *HighServer) commitImportedStateLocked(stream, bundleID string, sequence int64) error {
	prevSeq, hadStream := s.state.Imported[stream]
	prevAt := s.state.ImportedAt
	s.state.Imported[stream] = sequence
	s.state.ImportedAt = time.Now().UTC()
	if err := s.saveStateLocked(); err != nil {
		if hadStream {
			s.state.Imported[stream] = prevSeq
		} else {
			delete(s.state.Imported, stream)
		}
		s.state.ImportedAt = prevAt
		return fmt.Errorf("bundle %s: files installed but import state was not persisted (will retry): %w", bundleID, err)
	}
	s.metrics.recordImport(stream, s.state.ImportedAt)
	return nil
}

// loadVerifiedManifest verifies new Ed25519ph manifests from a streaming SHA-512
// digest before loading their bounded JSON. Raw Ed25519 signatures remain
// readable so bundles archived by older ArtiGate versions can still be replayed.
func (s *HighServer) loadVerifiedManifest(manifestPath, sigPath, stream, bundleID string, expectedSeq int64) (BundleManifest, error) {
	sigB64, err := readFileLimit(sigPath, diodeMaxSignatureBytes)
	if err != nil {
		return BundleManifest{}, err
	}
	sigText := strings.TrimSpace(string(sigB64))
	prehashed := strings.HasPrefix(sigText, manifestSignaturePHPrefix)
	if prehashed {
		sigText = strings.TrimPrefix(sigText, manifestSignaturePHPrefix)
	}
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		return BundleManifest{}, fmt.Errorf("decode signature: %w", err)
	}
	var verifiedDigest []byte
	if prehashed {
		verifiedDigest, err = hashFileLimitSHA512(manifestPath, diodeMaxManifestBytes)
		if err != nil {
			return BundleManifest{}, err
		}
		if err := ed25519.VerifyWithOptions(s.publicKey, verifiedDigest, sig, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
			return BundleManifest{}, fmt.Errorf("signature verification failed for %s", bundleID)
		}
	}

	manifestBytes, err := readFileLimit(manifestPath, diodeMaxManifestBytes)
	if err != nil {
		return BundleManifest{}, err
	}
	if prehashed {
		got := sha512.Sum512(manifestBytes)
		if !bytes.Equal(got[:], verifiedDigest) {
			return BundleManifest{}, fmt.Errorf("manifest %s changed while it was being verified", bundleID)
		}
	} else if !ed25519.Verify(s.publicKey, manifestBytes, sig) {
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

func hashFileLimitSHA512(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha512.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, fmt.Errorf("%s exceeds %s limit", filepath.Base(name), formatBytes(limit))
	}
	return h.Sum(nil), nil
}

func readFileLimit(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s exceeds %s limit", filepath.Base(name), formatBytes(limit))
	}
	return b, nil
}

// manifestStream returns the stream a manifest belongs to; legacy manifests
// without one are the go stream.
func manifestStream(m BundleManifest) string {
	if m.Stream == "" {
		return streamGo
	}
	return m.Stream
}

// checkManifestFields validates the manifest's wire format, type, stream,
// sequencing, and identity against what the importer expects next for that
// stream. The format check runs first: on a newer format none of the other
// fields can be trusted to mean what this binary thinks they mean.
func (s *HighServer) checkManifestFields(manifest BundleManifest, stream, bundleID string, expectedSeq int64) error {
	if manifest.Format > manifestFormatCurrent {
		return &manifestTooNewError{bundleID: bundleID, format: manifest.Format}
	}
	gotStream := manifestStream(manifest)
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
	if err := s.sortLandingStreamsLocked(byStream); err != nil {
		return err
	}
	return s.rejectInvalidQuarantineLocked()
}

func (s *HighServer) sortLandingStreamsLocked(byStream map[string][]int64) error {
	for stream, seqs := range byStream {
		if !isKnownStream(stream) {
			if err := s.rejectUnsupportedLandingStreamLocked(stream, seqs); err != nil {
				return err
			}
			continue
		}
		next := s.state.Imported[stream] + 1
		for _, seq := range seqs {
			if err := s.sortLandingBundleLocked(stream, seq, next); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *HighServer) rejectUnsupportedLandingStreamLocked(stream string, seqs []int64) error {
	for _, seq := range seqs {
		id := bundleIDFor(stream, seq)
		if err := s.rejectBundleLocked(s.cfg.Landing, id, fmt.Sprintf("unsupported bundle stream %q", stream)); err != nil {
			return err
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
	case seq > next && seq-next > maxFutureSequenceGap:
		return s.rejectBundleLocked(s.cfg.Landing, id,
			fmt.Sprintf("sequence %d is more than %d ahead of next expected sequence %d", seq, maxFutureSequenceGap, next))
	case seq > next:
		return moveBundleFiles(s.cfg.Landing, s.cfg.Quarantine, id)
	case seq <= s.state.Imported[stream]:
		return moveBundleFiles(s.cfg.Landing, filepath.Join(s.cfg.Landing, "duplicates"), id)
	}
	return nil
}

// rejectInvalidQuarantineLocked also cleans hostile files already placed in
// quarantine by an older release or by a folder transport.
func (s *HighServer) rejectInvalidQuarantineLocked() error {
	byStream, err := findBundleStreams(s.cfg.Quarantine)
	if err != nil {
		return err
	}
	for stream, seqs := range byStream {
		next := s.state.Imported[stream] + 1
		for _, seq := range seqs {
			if isKnownStream(stream) && !(seq > next && seq-next > maxFutureSequenceGap) {
				continue
			}
			id := bundleIDFor(stream, seq)
			reason := fmt.Sprintf("unsupported bundle stream %q", stream)
			if isKnownStream(stream) {
				reason = fmt.Sprintf("sequence %d is more than %d ahead of next expected sequence %d", seq, maxFutureSequenceGap, next)
			}
			if err := s.rejectBundleLocked(s.cfg.Quarantine, id, reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectBundleLocked moves every present file for a bundle into a retained
// rejected directory and writes a bounded operator-readable reason alongside
// it. The rejected directory is never scanned as import input.
func (s *HighServer) rejectBundleLocked(srcDir, bundleID, reason string) error {
	dstDir := filepath.Join(s.cfg.Root, "rejected")
	if err := moveBundleFiles(srcDir, dstDir, bundleID); err != nil {
		return err
	}
	const maxReason = 4 << 10
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	if err := writeBytesAtomic(filepath.Join(dstDir, bundleID+".reason.txt"), []byte(reason+"\n"), 0o644); err != nil {
		return err
	}
	// Every rejection path — import-time signature/hash failures and sort-time
	// unsupported/too-far bundles — funnels through here, so it is the single
	// place to count rejections and notify. Delivery is async and never blocks
	// the import that holds s.mu.
	stream := streamOfBundleID(bundleID)
	s.metrics.recordReject(stream)
	s.notifier.notify("bundle_rejected", map[string]any{
		"stream": stream, "bundle": bundleID, "reason": reason,
	})
	return nil
}

// streamOfBundleID extracts the stream name from a bundle id like
// "go-bundle-000042"; it returns "" for an unrecognized id.
func streamOfBundleID(bundleID string) string {
	if i := strings.Index(bundleID, "-bundle-"); i > 0 {
		return bundleID[:i]
	}
	return ""
}

// reapUnverifiedLocked frees the shared unverified-bytes quota from data that
// can never import on its own: terminally rejected bundles past their retention,
// and orphaned partial landing sets. Quarantine is deliberately never reaped —
// it holds valid future bundles waiting for an earlier one to fill a gap.
// Callers hold s.mu.
func (s *HighServer) reapUnverifiedLocked(now time.Time) {
	if n, err := reapFilesOlderThan(filepath.Join(s.cfg.Root, "rejected"), now.Add(-rejectedRetention)); err != nil {
		log.Printf("reap rejected: %v", err)
	} else if n > 0 {
		log.Printf("reaped %d expired rejected file(s)", n)
	}
	// Processed bundles (already imported, or duplicates of imports) are moved
	// into landing subdirectories that no import pass ever reads again; without
	// retention they grow by one full bundle per import, forever.
	for _, sub := range []string{"imported", "duplicates"} {
		if n, err := reapFilesOlderThan(filepath.Join(s.cfg.Landing, sub), now.Add(-processedLandingRetention)); err != nil {
			log.Printf("reap landing/%s: %v", sub, err)
		} else if n > 0 {
			log.Printf("reaped %d processed bundle file(s) from landing/%s", n, sub)
		}
	}
	if n, err := reapIncompleteLanding(s.cfg.Landing, now.Add(-incompleteLandingRetention)); err != nil {
		log.Printf("reap incomplete landing: %v", err)
	} else if n > 0 {
		log.Printf("reaped %d orphaned partial landing file(s)", n)
	}
	if n, err := reapStaleTransportTemps(s.cfg.Landing, now.Add(-incompleteLandingRetention)); err != nil {
		log.Printf("reap stale transport temp files: %v", err)
	} else if n > 0 {
		log.Printf("reaped %d stale transport temp file(s)", n)
	}
}

// reapStaleTransportTemps deletes orphaned transport temp files last modified
// before cutoff: UDP reassembly temps and HTTP ingest upload temps whose
// process was killed mid-transfer. Both count against the unverified storage
// quota, so an orphan would pin it forever. In-flight transfers keep a recent
// mtime (writes touch the file continuously, and the catcher expires stale
// transfers itself), so only long-abandoned temps are removed here.
func reapStaleTransportTemps(dir string, cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var removed int
	for _, e := range entries {
		if e.IsDir() || !(isUDPTempName(e.Name()) || isIngestUploadTempName(e.Name())) {
			continue
		}
		if removeIfOlder(filepath.Join(dir, e.Name()), cutoff) {
			removed++
		}
	}
	return removed, nil
}

// reapFilesOlderThan deletes the directory's regular files last modified before
// cutoff (the retention sweep behind rejected/, landing/imported, and
// landing/duplicates).
func reapFilesOlderThan(dir string, cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var removed int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if removeIfOlder(filepath.Join(dir, e.Name()), cutoff) {
			removed++
		}
	}
	return removed, nil
}

// reapIncompleteLanding deletes the files of landing bundle sets that are still
// incomplete (missing at least one of the three bundle files) and whose newest
// file predates cutoff — orphans of an interrupted transfer that would otherwise
// pin the unverified-bytes quota forever. Complete sets (pending import),
// subdirectories, and UDP reassembly temp files are left untouched.
func reapIncompleteLanding(dir string, cutoff time.Time) (int, error) {
	members, newest, err := landingBundleGroups(dir)
	if err != nil {
		return 0, err
	}
	var removed int
	for base, names := range members {
		if bundleCompleteInDir(dir, base) || !newest[base].Before(cutoff) {
			continue
		}
		for _, name := range names {
			if removeIfOlder(filepath.Join(dir, name), cutoff) {
				removed++
			}
		}
	}
	return removed, nil
}

// landingBundleGroups maps each landing bundle base name to its present files and
// the newest of their modification times. Subdirectories, UDP reassembly temp
// files, and files with no known bundle suffix are skipped.
func landingBundleGroups(dir string) (members map[string][]string, newest map[string]time.Time, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	members = map[string][]string{}
	newest = map[string]time.Time{}
	for _, e := range entries {
		if e.IsDir() || isUDPTempName(e.Name()) {
			continue
		}
		base := bundleBaseName(e.Name())
		if base == e.Name() {
			continue // not a bundle file (no known suffix)
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		members[base] = append(members[base], e.Name())
		if info.ModTime().After(newest[base]) {
			newest[base] = info.ModTime()
		}
	}
	return members, newest, nil
}

// removeIfOlder removes p only if it still exists as a regular file last modified
// before cutoff. The re-stat guards against deleting a file that was rewritten
// (for example a landing bundle re-uploaded) between the directory listing and
// the delete.
func removeIfOlder(p string, cutoff time.Time) bool {
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || !info.ModTime().Before(cutoff) {
		return false
	}
	return os.Remove(p) == nil
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
	out := ImportStatus{
		Version:        versionString(),
		ManifestFormat: manifestFormatCurrent,
		Streams:        make([]StreamImportStatus, 0, len(streams)),
	}
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

// noManifestContentError names, per ecosystem, the content a valid manifest
// could have carried; a manifest carrying none of it is rejected with this.
func noManifestContentError() error {
	ecos := ecosystems()
	kinds := make([]string, 0, len(ecos))
	for _, e := range ecos {
		kinds = append(kinds, e.contentDesc)
	}
	return fmt.Errorf("manifest contains no %s, or content-part marker", strings.Join(kinds, ", "))
}

// validateBundlePart checks a split collect's content-part marker: sane
// bounds, and the part must actually deliver content — its whole purpose is
// carrying files the split's final bundle will reference as prior.
func validateBundlePart(p *BundlePartInfo, files []ManifestFile) error {
	if p.Index < 1 || p.Count < 2 || p.Index > p.Count {
		return fmt.Errorf("invalid bundle part %d of %d", p.Index, p.Count)
	}
	if countDelivered(files) == 0 {
		return errors.New("bundle part delivers no files")
	}
	return nil
}

func validateManifestCompleteness(m BundleManifest) error {
	seen, err := validateManifestFiles(m.Files)
	if err != nil {
		return err
	}
	matched := false
	for _, e := range ecosystems() {
		if !e.manifestContent(m) {
			continue
		}
		matched = true
		if err := e.validateContent(m, seen); err != nil {
			return err
		}
	}
	if m.Part != nil {
		matched = true
		if err := validateBundlePart(m.Part, m.Files); err != nil {
			return err
		}
	}
	if !matched {
		return noManifestContentError()
	}
	return nil
}

// validateManifestFiles checks each listed file's path and hash, returning the
// set of valid file paths.
func validateManifestFiles(files []ManifestFile) (map[string]bool, error) {
	seen := map[string]bool{}
	for _, f := range files {
		if err := validateManifestFileEntry(f); err != nil {
			return nil, err
		}
		if seen[f.Path] {
			return nil, fmt.Errorf("duplicate file path %s", f.Path)
		}
		seen[f.Path] = true
	}
	// No listed path may double as a parent directory of another: no tree can
	// hold both, so extraction or install would fail with an EEXIST/ENOTDIR
	// indistinguishable from an operational staging fault, and the bundle
	// would be retried forever instead of rejected. Prior files count too —
	// they name paths the accumulated repository already holds as files.
	for _, f := range files {
		for dir := path.Dir(f.Path); dir != "."; dir = path.Dir(dir) {
			if seen[dir] {
				return nil, fmt.Errorf("file path %s collides with parent directory of %s", dir, f.Path)
			}
		}
	}
	return seen, nil
}

// validateManifestFileEntry checks one listed file's path and hash.
func validateManifestFileEntry(f ManifestFile) error {
	if err := validateRelPath(f.Path); err != nil {
		return fmt.Errorf("invalid file path %q: %w", f.Path, err)
	}
	if f.SHA256 == "" || len(f.SHA256) != 64 {
		return fmt.Errorf("invalid sha256 for %s", f.Path)
	}
	// The sumdb/ namespace may only hold protocol-shaped checksum-database
	// files — validated here, on the untrusted side, exactly as strictly as
	// the low side shapes them at capture time.
	return validateManifestSumDBPath(f.Path)
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
	goFiles := goFilePaths(manifest.Modules)
	// A content part carries no module records to derive placement from; on
	// the go stream every file it delivers is a module file and belongs under
	// the go/ subtree, where the split's final bundle will verify it as prior.
	if manifest.Part != nil && manifestStream(manifest) == streamGo {
		goFiles = allManifestFilePaths(manifest.Files)
	}
	// Checksum-database files ride in go bundles without a module record;
	// they belong under the go/ subtree too, where serveGoSumDB reads them.
	goFiles = withGoSumDBFilePaths(goFiles, manifest)
	if err := s.installVerifiedFiles(staging, manifest.Files, goFiles); err != nil {
		return err
	}
	// Each ecosystem regenerates its served repository metadata from the
	// artifacts actually installed (never trusting a transferred index); a
	// publish hook no-ops on a manifest without its ecosystem's content.
	for _, e := range ecosystems() {
		if e.publish == nil {
			continue
		}
		if err := e.publish(s, manifest); err != nil {
			return err
		}
	}
	// Complete markers are written only after all files are installed.
	return s.writeCompleteMarkers(manifest.Modules)
}

// allManifestFilePaths returns the set of every listed file path.
func allManifestFilePaths(files []ManifestFile) map[string]bool {
	set := make(map[string]bool, len(files))
	for _, f := range files {
		set[f.Path] = true
	}
	return set
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
		if !mutableRepoPath(f.Path) {
			return fmt.Errorf("immutable file conflict for %s", f.Path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return moveVerifiedFile(src, dst)
}

// moveVerifiedFile publishes one verified staged file at its repository path.
// Staging lives under the same root as the repository, so a rename moves the
// bytes for free and atomically — extraction already fsynced them — where a
// copy would rewrite (and re-fsync) every byte of every import a second time.
// A staging directory mounted on its own filesystem (EXDEV) falls back to the
// copying path, as does any other rename failure whose cause a copy attempt
// will report more precisely.
func moveVerifiedFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return copyFileAtomic(src, dst, 0o644)
}

// mutableRepoPath reports whether a verified bundle may replace an existing
// file at this path with different content (copyFileAtomic renames over the
// old file). Mirrored package artifacts are immutable — a later bundle can
// never rewrite history. Three kinds of paths are legitimately mutable:
// operator uploads, where re-uploading a name replaces it by design; OSV
// advisory databases, which are continuously updated snapshots re-delivered
// at one canonical per-ecosystem path; and the Go checksum database's moving
// parts (its latest tree head, and lookups whose embedded tree note was
// refreshed). All only ever arrive hash-verified inside signed, sequenced
// bundles.
func mutableRepoPath(p string) bool {
	return strings.HasPrefix(p, "uploads/") || strings.HasPrefix(p, "osv/") || mutableSumDBPath(p)
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
