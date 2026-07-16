package main

// The low side: the privileged control plane. It holds the Ed25519 signing
// key, resolves and fetches upstream content (delegating to the installed
// tools), and turns each collect into signed, per-stream sequenced bundles in
// the export directory for the diode to carry across. This file holds the low
// server itself and the machinery shared by every ecosystem — sequence
// allocation and commit, export dedup, oversize-collect splitting, bundle
// archiving and re-export — plus the Go module collector; the other ecosystem
// adapters live in their own files (python.go, npm.go, apt.go, ...).

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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

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
	HFEndpoint string
	// CratesIndex optionally overrides the sparse registry index Rust crates
	// are resolved from; empty means https://index.crates.io.
	CratesIndex string
	// TerraformRegistry optionally overrides the registry Terraform providers
	// and modules are fetched from (point it at https://registry.opentofu.org
	// to mirror OpenTofu); empty means https://registry.terraform.io.
	TerraformRegistry string
	// NugetSource optionally overrides the NuGet v3 service index packages are
	// resolved from; empty means https://api.nuget.org/v3/index.json.
	NugetSource string
	// OsvUpstream optionally overrides the base URL OSV vulnerability
	// databases (per-ecosystem all.zip archives) are fetched from; empty
	// means https://osv-vulnerabilities.storage.googleapis.com.
	OsvUpstream string
	// GitBinary is the git command used to fetch Terraform modules that
	// resolve to git sources.
	GitBinary string
	// CondaChannelBase optionally overrides the base URL bare conda channel
	// names resolve under; empty means https://conda.anaconda.org.
	CondaChannelBase string
	// RubyGemsURL optionally overrides the gem server gems and their compact
	// index are fetched from; empty means https://rubygems.org.
	RubyGemsURL string
	// ComposerRepoURL optionally overrides the Composer repository package
	// metadata and dists are resolved from; empty means
	// https://repo.packagist.org.
	ComposerRepoURL string
	// VSXRegistryURL optionally overrides the Open VSX registry VS Code
	// extensions are fetched from; empty means https://open-vsx.org.
	VSXRegistryURL string
	// GalaxyServerURL optionally overrides the Galaxy server Ansible
	// collections are fetched from; empty means https://galaxy.ansible.com.
	GalaxyServerURL string
	// CRANMirror optionally overrides the CRAN mirror R packages are fetched
	// from; empty means https://cloud.r-project.org.
	CRANMirror string
	// PyPIJSON optionally overrides the JSON API base sdists are resolved
	// from when a Python collect opts into source distributions; empty means
	// https://pypi.org/pypi.
	PyPIJSON      string
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
	// how often the scheduler checks for due ones.
	watches   *WatchStore
	watchTick time.Duration
	// jobs is the per-stream collect queue: every manual and scheduled collect
	// runs as a job on it, giving all dashboard sessions one shared view of
	// what is queued, running, and recently finished (and why it failed). It
	// also keeps a watch from running concurrently with itself (a due tick
	// overlapping a run-now).
	jobs *jobManager
	// authEnabled is set when ARTIGATE_LOW_AUTH is configured; it makes the UI
	// render a "Log out" button.
	authEnabled bool
	// pitcher is the built-in UDP diode sender (ARTIGATE_PITCHER_INTERFACE);
	// nil means bundles leave via the export dir or the HTTP diode endpoint.
	pitcher *diodePitcher
	// containerRegistryBases maps a container registry name to the API base URL
	// it is fetched from (parsed from cfg.ContainerRegistries).
	containerRegistryBases map[string]string
	// splitBudget overrides the per-bundle estimated-archive budget that
	// triggers splitting a collect into multiple sequenced bundles; zero means
	// the transport limit (diodeMaxArchiveBytes). Tests shrink it to exercise
	// splitting without gigabytes of fixture data.
	splitBudget int64
	// metrics holds the in-memory schedule/collect counters the /metrics
	// endpoint reports; notifier posts failure webhooks (nil when unconfigured).
	metrics  *lowMetrics
	notifier *webhookNotifier
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
	registerLowEcosystemFlags(fs, &cfg)
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
	// After the pitcher attaches (so both push transports count): re-mark
	// bundles still staged from before the restart, whose in-memory failure
	// records died with the old process.
	ls.restoreDiodeTransferBacklog()

	serveLow(cfg, ls)
}

// registerLowEcosystemFlags declares each registered ecosystem's tool and
// upstream overrides on the low-side flag set (flag help output is sorted by
// name, so registration order does not matter).
func registerLowEcosystemFlags(fs *flag.FlagSet, cfg *LowConfig) {
	for _, e := range ecosystems() {
		if e.flags != nil {
			e.flags(fs, cfg)
		}
	}
}

// serveLow wires up TLS, optional low-side authentication, the scheduler, and the
// HTTP handler, then serves until the process stops or a SIGINT/SIGTERM arrives.
func serveLow(cfg LowConfig, ls *LowServer) {
	tc, err := tlsConfigFromEnv()
	must(err)
	users, err := parseLowAuth(os.Getenv("ARTIGATE_LOW_AUTH"))
	must(err)
	guardLowExposure(cfg.Listen, len(users) > 0, tc.Mode)
	ls.notifier = mustWebhookNotifier("low")

	// A SIGINT/SIGTERM (Ctrl-C, docker stop, systemd stop) cancels this context,
	// stopping the scheduler and draining the HTTP server before runLow's
	// deferred store closes run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.WatchInterval > 0 {
		go ls.watchLoop(ctx)
	}
	// Cancel queued and running jobs as soon as the stop signal arrives, so
	// requests waiting on a job unblock and the HTTP server can drain.
	go func() {
		<-ctx.Done()
		ls.jobs.shutdown()
	}()

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
	// Guard state-changing requests against cross-site (CSRF) abuse in every
	// deployment mode, including loopback-without-auth where no session cookie
	// (and thus no SameSite protection) exists.
	handler = csrfGuard(handler)

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
	must(listenAndServe(ctx, tc, cfg.Listen, cfg.Root, logHTTP(handler)))
}

// guardLowExposure fails closed when the low side — which holds the signing key
// and can therefore have arbitrary content signed through it — would be reachable
// from other hosts without a login. The operator must either set ARTIGATE_LOW_AUTH,
// bind the listener to loopback, or explicitly acknowledge an external
// authenticating layer with ARTIGATE_LOW_ALLOW_UNAUTHENTICATED=true. It also warns
// when credentials would traverse a non-loopback plaintext hop.
func guardLowExposure(listen string, authEnabled bool, tlsMode tlsMode) {
	loopback := listenAddrIsLoopback(listen)
	if !authEnabled && !loopback {
		allow, err := parseOnOff(os.Getenv("ARTIGATE_LOW_ALLOW_UNAUTHENTICATED"))
		must(err)
		if !allow {
			log.Fatalf("refusing to start: the low side listens on %s (reachable from other hosts) with no authentication. "+
				"The low side holds the signing key, so an unauthenticated listener lets anyone have arbitrary content signed and sent across the diode. "+
				"Set ARTIGATE_LOW_AUTH (see 'artigate hashpw'), bind --listen to loopback (e.g. 127.0.0.1:8080), "+
				"or set ARTIGATE_LOW_ALLOW_UNAUTHENTICATED=true if a trusted authenticating reverse proxy fronts it.", listen)
		}
		log.Printf("WARNING: low side is unauthenticated on a non-loopback address (%s); relying on an external authenticating layer per ARTIGATE_LOW_ALLOW_UNAUTHENTICATED", listen)
	}
	if authEnabled && !loopback && tlsMode == tlsUnencrypted && !envIsTrue(os.Getenv("ARTIGATE_LOW_COOKIE_SECURE")) {
		log.Printf("WARNING: low side serves plaintext HTTP on a non-loopback address (%s); the login password and session cookie can be observed on the wire. Terminate TLS (ARTIGATE_TLS_MODE) or set ARTIGATE_LOW_COOKIE_SECURE=true behind an HTTPS proxy.", listen)
	}
}

// envIsTrue reports whether an environment toggle holds an affirmative value.
func envIsTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// isStateChangingMethod reports whether m can mutate server state and therefore
// warrants CSRF protection. Safe methods (GET/HEAD/OPTIONS/TRACE) are exempt.
func isStateChangingMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

// isCrossSiteBrowserRequest reports whether r is a browser-issued cross-site
// request. It prefers the Fetch-Metadata Sec-Fetch-Site header sent by modern
// browsers and falls back to comparing Origin against the request Host. A
// non-browser client (curl, the diode uploader, CI) sends neither and is treated
// as same-site: CSRF is a browser-confused-deputy problem, not theirs.
func isCrossSiteBrowserRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return false
	case "same-site", "cross-site":
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return true
	}
	return !strings.EqualFold(u.Host, r.Host)
}

// csrfGuard rejects browser-issued cross-site state-changing requests. On the
// low side the signing control plane has no SameSite cookie protection in the
// supported loopback-without-auth mode; on the high side it backs up the
// loopback gate on the mutating admin endpoints. Safe methods and non-browser
// clients (curl, the diode uploader) pass through unaffected.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStateChangingMethod(r.Method) && isCrossSiteBrowserRequest(r) {
			http.Error(w, "cross-site request refused; state changes are accepted only from the dashboard", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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
	// A crashed collect can strand its scratch — including a netrc holding a
	// login — under the root; scrub it before serving so no secret persists
	// across restarts.
	if err := scrubGoCollectScratch(cfg.Root); err != nil {
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
		jobs:                   newJobManager(),
		containerRegistryBases: registryBases,
		metrics:                newLowMetrics(),
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
		_ = store.Close() // don't leak the watch DB when the exported index fails to open
		return nil, err
	}
	ls.exported = exported
	return ls, nil
}

// Close releases the low server's resources (the watch and exported-index
// databases, and the diode sender when one is open).
func (s *LowServer) Close() error {
	// Stop the job queue first: its completion hooks write to the watch store,
	// which must still be open when the last canceled job records its outcome.
	s.jobs.shutdown()
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

// serveLowAdmin handles the monitoring endpoints and /admin/* routes. It
// reports whether it has written a response for the request.
func (s *LowServer) serveLowAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.serveLowCollect(w, r) {
		return true
	}
	if s.serveLowWatches(w, r) {
		return true
	}
	if s.serveLowJobs(w, r) {
		return true
	}
	if serveObservability(w, r, s.serveReadyz, s.serveMetrics) {
		return true
	}
	switch {
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

// collectHandlers maps each registered ecosystem's collect endpoint to its
// request handler. Every route is named by its stream (collectStreamFromPath
// relies on it).
func (s *LowServer) collectHandlers() map[string]func(context.Context, *http.Request) (ExportResult, error) {
	ecos := ecosystems()
	handlers := make(map[string]func(context.Context, *http.Request) (ExportResult, error), len(ecos))
	for _, e := range ecos {
		collect := e.collect
		handlers["/admin/"+e.stream+"/collect"] = func(ctx context.Context, r *http.Request) (ExportResult, error) {
			return collect(s, ctx, r)
		}
	}
	return handlers
}

// serveLowCollect dispatches the per-ecosystem collect endpoints. It reports
// whether it handled the request (false for non-POST or unmatched paths, so the
// caller can fall through to its own routing).
func (s *LowServer) serveLowCollect(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	// The handler binds the request; the collect itself runs as a job on its
	// stream's queue. A plain POST waits for the job and answers with the
	// buffered JSON result as always; ?stream=1 (the dashboard's live progress
	// modal) follows the job's NDJSON event stream instead. The handler
	// re-reads r.Body when the job runs — enqueueCollect buffers it.
	// ?dry_run=1 marks the job's context so the collect stops at the export
	// threshold and answers with a size estimate.
	handle, ok := s.collectHandlers()[r.URL.Path]
	if !ok {
		return false
	}
	dryRun := wantsDryRunCollect(r)
	run := func(ctx context.Context) (ExportResult, error) {
		if dryRun {
			ctx = withDryRunCollect(ctx)
		}
		return handle(ctx, r)
	}
	s.runCollectJob(w, r, collectStreamFromPath(r.URL.Path), run)
	return true
}

// runCollectJob enqueues one collect on its stream's queue and answers the
// request: streaming clients (?stream=1) follow the job's NDJSON events,
// everyone else waits for the buffered JSON result as before.
func (s *LowServer) runCollectJob(w http.ResponseWriter, r *http.Request, stream string,
	run func(context.Context) (ExportResult, error),
) {
	job, ok := s.enqueueCollect(w, r, stream, run)
	if !ok {
		return // enqueueCollect wrote the error
	}
	if wantsStreamingCollect(r) {
		followJobNDJSON(w, r, job, true)
		return
	}
	waitCollectJob(w, r, job)
}

// collectStreamFromPath extracts the stream key from a collect endpoint path:
// /admin/<stream>/collect. Every collect route is named by its stream
// constant, so no mapping table is needed.
func collectStreamFromPath(path string) string {
	return strings.TrimSuffix(strings.TrimPrefix(path, "/admin/"), "/collect")
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

func (s *LowServer) goEnv(ctx context.Context) []string {
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
	// A credentialed collect's hosts join the configured private patterns so
	// they skip the public proxy and checksum database (see goauth.go).
	// GONOSUMDB and GONOPROXY default to GOPRIVATE while unset, so goNoVarValue
	// appends the auth hosts to that effective base — otherwise augmenting them
	// during a credentialed collect would drop GOPRIVATE's coverage for the run.
	hosts := goAuthHostPatterns(ctx)
	if v := mergePatterns(s.cfg.GOPRIVATE, hosts); v != "" {
		set("GOPRIVATE", v)
	}
	if v := goNoVarValue(s.cfg.GONOSUMDB, s.cfg.GOPRIVATE, hosts); v != "" {
		set("GONOSUMDB", v)
	}
	if v := goNoVarValue(s.cfg.GONOPROXY, s.cfg.GOPRIVATE, hosts); v != "" {
		set("GONOPROXY", v)
	}
	// Do not prompt for passwords in daemon mode. Configure git/ssh credentials ahead of time.
	set("GIT_TERMINAL_PROMPT", "0")
	// The collect's injected login environment: NETRC/GOAUTH for the
	// toolchain's own requests, GIT_CONFIG_* credential helpers for git.
	env = append(env, goAuthEnvEntries(ctx)...)
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
	cmd.Env = s.goEnv(ctx)
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
	// Bundles lists every bundle a split collect produced, in export order;
	// the last one carries the ecosystem metadata (and is BundleID). Unset
	// when the collect fit in a single bundle.
	Bundles []string `json:"bundles,omitempty"`
	// DiodeError reports a failed upload to the HTTP diode endpoint. The
	// bundle itself is fine — committed, archived, and still staged in the
	// export dir — so this is a "re-transmit me" signal, not a lost export.
	DiodeError string `json:"diode_error,omitempty"`
	// DryRun marks the result of a ?dry_run=1 collect: Estimate reports what
	// a real collect would export; nothing was written, no sequence number
	// was consumed, and nothing was recorded as forwarded.
	DryRun   bool             `json:"dry_run,omitempty"`
	Estimate *CollectEstimate `json:"estimate,omitempty"`
	// SumDB summarizes the Go checksum-database capture that rode along with
	// a go collect. Unset on other streams and when GOSUMDB is off.
	SumDB *GoSumDBStatus `json:"sumdb,omitempty"`
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
	// Auth optionally authenticates this collect against one private module
	// host (injected into the go/git subprocesses; see goauth.go). It is used
	// for this collect only and never stored; standing credentials belong in
	// ARTIGATE_GO_AUTH (watch specs must never carry logins — they are
	// persisted and echoed in plaintext).
	Auth *HostCollectAuth `json:"auth,omitempty"`
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
	creds, err := goCollectCredentials(req)
	if err != nil {
		return ExportResult{}, err
	}
	auth, authCleanup, err := buildGoAuthEnv(s.cfg.Root, creds)
	if err != nil {
		return ExportResult{}, err
	}
	defer authCleanup()
	if auth != nil {
		ctx = withGoAuth(ctx, auth)
	}
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
	// Capture the checksum-database records for the fetched modules so the
	// high side can answer the GOPROXY sumdb passthrough; a capture problem
	// never blocks the modules from exporting.
	sumdbFiles, sumdbStatus := s.captureGoSumDB(ctx, requestRecordsOf(mods), req.Force)
	files = append(files, sumdbFiles...)
	emitProgress(ctx, "Packing %d file(s) into a signed bundle…", len(files))
	res, err := s.exportIfNew(ctx, streamGo, s.downloadDir, files, req.Force, func(seq int64) (ExportResult, error) {
		return s.writeGoBundle(ctx, streamGo, seq, mods, files)
	})
	if err != nil {
		return ExportResult{}, err
	}
	res.SkippedModules = failed
	res.SumDB = sumdbStatus
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
//
// A sequence number must never be reused once a complete signed bundle for it
// exists on disk: the bundle is written and archived before the claim is
// persisted, so a crash — or a failed state save followed by a restart —
// leaves low-state.json behind the bundles. The naive counter would then hand
// the same number out again and silently overwrite a signed bundle that may
// already have crossed the diode, forking the stream (the high side shelves
// the replacement as a duplicate and its content is lost). So allocation
// skips past any sequence whose bundle is already complete in the export dir
// or the persistent archive; the original bundle stays intact and
// transferable, and the retry's content ships under the next free number.
// Incomplete artifacts (a crash mid-write) do not burn the number: such a
// bundle can never be imported, and burning it would leave a gap the
// strictly-sequential high side could never fill.
func (s *LowServer) peekSequence(stream string) int64 {
	s.mu.Lock()
	seq := s.state.Sequences[stream]
	s.mu.Unlock()
	if seq < 1 {
		seq = 1
	}
	first := seq
	for s.bundleExistsForSequence(stream, seq) {
		if seq == math.MaxInt64 {
			break
		}
		seq++
	}
	if seq != first {
		log.Printf("stream %s: sequence(s) %d-%d already have complete bundles on disk (state save lost before a restart?); continuing at %d", stream, first, seq-1, seq)
	}
	return seq
}

// allocateSequence validates the candidate selected from durable state and
// completed bundles. Any partial same-ID artifact is treated as crash residue
// requiring operator attention: overwriting it could replace bytes that were
// already observed, while skipping it would create an unfillable sequence gap.
func (s *LowServer) allocateSequence(stream string) (int64, error) {
	seq := s.peekSequence(stream)
	if seq == math.MaxInt64 {
		return 0, fmt.Errorf("stream %s exhausted its sequence space", stream)
	}
	id := bundleIDFor(stream, seq)
	for _, dir := range []string{s.cfg.ExportDir, s.bundleArchiveDir()} {
		if bundleArtifactsExistInDir(dir, id) {
			return 0, fmt.Errorf("bundle %s has incomplete artifacts in %s; refusing to overwrite crash residue (remove or recover those files before retrying)", id, dir)
		}
	}
	return seq, nil
}

// bundleExistsForSequence reports whether a complete signed bundle for the
// stream's sequence already exists anywhere durable — still staged in the
// export dir, retained in the archive, or both.
func (s *LowServer) bundleExistsForSequence(stream string, seq int64) bool {
	id := bundleIDFor(stream, seq)
	return bundleCompleteInDir(s.cfg.ExportDir, id) || bundleCompleteInDir(s.bundleArchiveDir(), id)
}

// commitSequence advances the stream past seq after a bundle for it has been
// written successfully.
//
// On a failed save the in-memory counter deliberately stays advanced — the
// opposite of the high side's import counter, which rolls back to match disk.
// The low side's invariant is never-reuse: the bundle for seq is already on
// disk, so serving the old number again in this process would overwrite it.
// Memory running ahead only risks the restart case, which peekSequence covers
// by skipping past sequences whose bundles already exist.
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
// a full self-contained bundle. write builds and writes the ecosystem's bundle
// for the allocated sequence; baseDir is the root its file paths are relative
// to. The caller must hold the stream lock (every collector does) so the
// peek/commit stay race-free.
//
// A collect whose new content would overflow the transport's per-archive
// limit (a full safetensors repository easily exceeds diodeMaxArchiveBytes)
// is split automatically: the content ships in consecutive sequenced
// content-part bundles, each within the limit, and the ecosystem's own bundle
// goes last, listing the parts' files as prior. Each part is committed,
// recorded, and handed to the diode transport as it is produced, so a failure
// midway loses nothing — a retry collect skips the already-forwarded parts
// and continues with the rest.
//
// A cancelled collect (the dashboard's Stop button aborts the streaming
// request, cancelling ctx) stops here rather than packing and exporting a
// bundle nobody wants. Packing itself also honors cancellation (the archive
// temp file is removed, no sequence is committed); only the final
// sign-and-archive steps run to completion, so a bundle is either fully
// produced or not at all.
//
// A dry-run collect (?dry_run=1, carried on ctx) stops right after the dedup
// marking: it answers with a size estimate of what would have been exported
// and touches nothing — see dryRunExportResult.
func (s *LowServer) exportIfNew(ctx context.Context, stream, baseDir string, files []ManifestFile, force bool, write func(seq int64) (ExportResult, error)) (ExportResult, error) {
	if err := ctx.Err(); err != nil {
		return ExportResult{}, fmt.Errorf("collect stopped before export: %w", err)
	}
	if !force {
		s.markPriorFiles(stream, files)
	}
	if isDryRunCollect(ctx) {
		return s.dryRunExportResult(ctx, stream, files)
	}
	delivered := countDelivered(files)
	if delivered == 0 {
		return ExportResult{Stream: stream, Skipped: true, Message: "no new content since the last export"}, nil
	}
	if prior := len(files) - delivered; prior > 0 {
		emitProgress(ctx, "%d of %d file(s) already forwarded; the bundle carries the %d new one(s)", prior, len(files), delivered)
	}
	chunks, err := splitDeliveredFiles(files, s.bundleSplitBudget())
	if err != nil {
		return ExportResult{}, s.decorateSplitError(err)
	}
	parts, err := s.exportContentParts(ctx, stream, baseDir, files, chunks)
	var res ExportResult
	if err == nil {
		res, err = s.exportSequencedBundle(ctx, stream, files, write)
	}
	if err != nil {
		if n := len(parts.ids); n > 0 {
			err = fmt.Errorf("%d of %d bundle(s) already exported and committed (%s); a retry collect will continue with the remaining content: %w",
				n, len(chunks), strings.Join(parts.ids, ", "), err)
		}
		return ExportResult{}, err
	}
	res.PriorFiles = len(files) - delivered
	parts.finish(&res)
	return res, nil
}

// exportSequencedBundle allocates the stream's next sequence, writes one
// bundle for it, commits the claim, records the files as forwarded, and hands
// the bundle to the configured diode transport. It is the tail every exported
// bundle goes through — a collect's only bundle, each content part of a split,
// and the split's final ecosystem bundle.
func (s *LowServer) exportSequencedBundle(ctx context.Context, stream string, files []ManifestFile, write func(seq int64) (ExportResult, error)) (ExportResult, error) {
	seq, err := s.allocateSequence(stream)
	if err != nil {
		return ExportResult{}, err
	}
	res, err := write(seq)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(stream, seq); err != nil {
		// The bundle exists and is transferable, but the claim on its number
		// is not durable. peekSequence sees the bundle on disk, so a retry —
		// even after a restart — allocates a fresh sequence rather than
		// overwriting this one.
		return ExportResult{}, fmt.Errorf("bundle %s written, but its sequence claim was not persisted (a retry will use a fresh sequence): %w", bundleIDFor(stream, seq), err)
	}
	// Record only after the sequence is committed. If the commit fails the
	// content is not durably part of the stream, so a retry must re-export it
	// rather than see it as already forwarded and skip.
	s.recordForwarded(stream, files)
	// With a diode transport configured, hand the bundle over now; a failed
	// transfer is reported on the result, never fatal (the bundle is
	// committed and archived, ready to re-transmit).
	s.uploadBundleIfConfigured(ctx, &res)
	return res, nil
}

// bundleSplitBudget is the estimated-archive-size budget one bundle may use
// before a collect is split. It defaults to the transport's hard per-archive
// limit — the same one the high side enforces at import, so an oversized
// archive would not merely fail to transfer, it would be rejected at its
// sequence number and wedge the stream. With the built-in UDP pitcher
// enabled, the wire's block-count bound also applies: a small block geometry
// caps a transfer below the archive limit, and a bundle beyond it would be
// committed and recorded only for the send to refuse it — leaving the high
// side waiting on a sequence that cannot cross until the operator changes
// pitcher settings. The estimate always exceeds the finished archive, so a
// bundle within budget is guaranteed both importable and transmittable.
func (s *LowServer) bundleSplitBudget() int64 {
	if s.splitBudget > 0 {
		return s.splitBudget
	}
	budget := int64(diodeMaxArchiveBytes)
	if s.pitcher != nil {
		budget = min(budget, s.pitcher.maxWireFileBytes())
	}
	return budget
}

// decorateSplitError appends the actionable pitcher hint to a split refusal
// when the wire's block-count bound — not the archive cap — is the limit the
// file failed against.
func (s *LowServer) decorateSplitError(err error) error {
	if s.splitBudget > 0 || s.pitcher == nil {
		return err
	}
	if wire := s.pitcher.maxWireFileBytes(); wire < diodeMaxArchiveBytes {
		return fmt.Errorf("%w (the UDP pitcher's block geometry caps one wire transfer at %s; raise ARTIGATE_PITCHER_MTU or ARTIGATE_PITCHER_FEC_DATA to carry bigger bundles)",
			err, formatBytes(wire))
	}
	return err
}

const (
	// bundlePackBaseOverheadBytes over-covers a tar.gz archive's fixed cost:
	// the gzip header and trailer plus tar's end-of-archive blocks.
	bundlePackBaseOverheadBytes = 4096
	// bundlePackFileOverheadBytes over-covers one file's fixed cost in the
	// archive: a 512-byte tar header plus padding to the next 512 boundary.
	bundlePackFileOverheadBytes = 2048
)

// estimatedPackedBytes bounds one file's contribution to a tar.gz archive
// from above. Model weights and package tarballs are already compressed or
// incompressible, so no compression is assumed — and gzip inflates
// incompressible input slightly (stored deflate blocks add ~0.008%; the
// size>>7 term allows 0.8%), so the estimate must exceed the raw size for the
// budget to guarantee the finished archive stays under the transport limit.
func estimatedPackedBytes(size int64) int64 {
	return size + size>>7 + bundlePackFileOverheadBytes
}

// splitDeliveredFiles partitions the delivered (non-prior) files, in path
// order, into consecutive index groups whose estimated packed archive size
// stays within budget. A single group means the collect fits one bundle. A
// file too large for any bundle fails the collect before a sequence is
// allocated — exporting it would wedge the stream on an unimportable bundle.
func splitDeliveredFiles(files []ManifestFile, budget int64) ([][]int, error) {
	idx := make([]int, 0, len(files))
	for i := range files {
		if !files[i].Prior {
			idx = append(idx, i)
		}
	}
	sort.Slice(idx, func(a, b int) bool { return files[idx[a]].Path < files[idx[b]].Path })
	var chunks [][]int
	var cur []int
	used := int64(bundlePackBaseOverheadBytes)
	for _, fi := range idx {
		cost := estimatedPackedBytes(files[fi].Size)
		if bundlePackBaseOverheadBytes+cost > budget {
			return nil, fmt.Errorf("file %s (%s) does not fit a bundle: even alone its estimated archive would exceed the %s transport limit",
				files[fi].Path, formatBytes(files[fi].Size), formatBytes(budget))
		}
		if len(cur) > 0 && used+cost > budget {
			chunks = append(chunks, cur)
			cur, used = nil, bundlePackBaseOverheadBytes
		}
		cur = append(cur, fi)
		used += cost
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks, nil
}

// contentPartsResult accumulates what a split's content parts produced, to be
// folded into the final bundle's ExportResult.
type contentPartsResult struct {
	ids       []string
	diodeErrs []string
}

// finish folds the content parts into the collect's final result: the full
// bundle list and any per-part transfer failures (each part is independently
// re-transmittable from the Status page).
func (p contentPartsResult) finish(res *ExportResult) {
	if len(p.ids) == 0 {
		return
	}
	res.Bundles = make([]string, 0, len(p.ids)+1)
	res.Bundles = append(append(res.Bundles, p.ids...), res.BundleID)
	if res.DiodeError != "" {
		p.diodeErrs = append(p.diodeErrs, res.DiodeError)
	}
	res.DiodeError = strings.Join(p.diodeErrs, "; ")
}

// exportContentParts ships every chunk but the last as a content-part bundle,
// marking its files prior in place so the final bundle — written by the
// ecosystem's own writer from the same slice — lists them without packing
// them again. Parts are committed and transferred one at a time; an error
// leaves the already-committed parts durable on the stream.
func (s *LowServer) exportContentParts(ctx context.Context, stream, baseDir string, files []ManifestFile, chunks [][]int) (contentPartsResult, error) {
	var parts contentPartsResult
	if len(chunks) < 2 {
		return parts, nil
	}
	count := len(chunks)
	emitProgress(ctx, "Content exceeds the %s per-bundle transport limit; splitting into %d sequenced bundles", formatBytes(s.bundleSplitBudget()), count)
	for i, chunk := range chunks[:count-1] {
		if err := ctx.Err(); err != nil {
			return parts, fmt.Errorf("collect stopped between bundle parts: %w", err)
		}
		part := make([]ManifestFile, 0, len(chunk))
		for _, fi := range chunk {
			part = append(part, files[fi])
		}
		emitProgress(ctx, "→ bundle %d/%d (%d file(s))", i+1, count, len(part))
		res, err := s.exportSequencedBundle(ctx, stream, part, func(seq int64) (ExportResult, error) {
			return s.writeBundlePart(ctx, stream, seq, baseDir, part, i+1, count)
		})
		if err != nil {
			return parts, err
		}
		parts.ids = append(parts.ids, res.BundleID)
		if res.DiodeError != "" {
			parts.diodeErrs = append(parts.diodeErrs, res.BundleID+": "+res.DiodeError)
		}
		for _, fi := range chunk {
			files[fi].Prior = true
		}
	}
	emitProgress(ctx, "→ bundle %d/%d (final, with the %s metadata)", count, count, stream)
	return parts, nil
}

// writeBundlePart builds, signs, and writes one content part of a split
// collect: a bundle that carries a slice of the collect's files and no
// ecosystem metadata. The high side installs its files into the accumulated
// repository and regenerates nothing — the split's final bundle, importing
// after it, carries the metadata that references them.
func (s *LowServer) writeBundlePart(ctx context.Context, stream string, seq int64, baseDir string, files []ManifestFile, index, count int) (ExportResult, error) {
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
		Ecosystems:       []string{stream},
		Part:             &BundlePartInfo{Index: index, Count: count},
		Files:            files,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.writeBundleArtifacts(ctx, id, baseDir, manifestBytes, files); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Stream: stream, Sequence: seq, BundleID: id, Message: fmt.Sprintf("content part %d of %d", index, count)}, nil
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
	if err := s.writeBundleArtifacts(ctx, id, s.downloadDir, manifestBytes, files); err != nil {
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
func (s *LowServer) writeBundleArtifacts(ctx context.Context, bundleID, baseDir string, manifestBytes []byte, files []ManifestFile) error {
	// Any bundle artifact already carrying this id means its sequence may have
	// been observed:
	// overwriting would fork the stream into two different signed bundles with
	// the same number, one of which may already have crossed the diode.
	// Sequence allocation skips such numbers, so reaching this is a bug — fail
	// loudly rather than clobber the original.
	if bundleArtifactsExistInDir(s.cfg.ExportDir, bundleID) || bundleArtifactsExistInDir(s.bundleArchiveDir(), bundleID) {
		return fmt.Errorf("bundle %s already has artifacts on disk; refusing to overwrite a previously produced bundle", bundleID)
	}
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
	sig, err := signManifestPH(s.privateKey, manifestBytes)
	if err != nil {
		return err
	}
	encodedSig := manifestSignaturePHPrefix + base64.StdEncoding.EncodeToString(sig) + "\n"
	if err := writeBytesAtomic(sigPath, []byte(encodedSig), 0o644); err != nil {
		return err
	}
	return s.archiveBundle(bundleID)
}

func signManifestPH(privateKey ed25519.PrivateKey, manifestBytes []byte) ([]byte, error) {
	digest := sha512.Sum512(manifestBytes)
	return privateKey.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512})
}

// bundleArchiveDir is where every produced bundle is retained so re-export can
// replay the exact signed files regardless of ecosystem.
func (s *LowServer) bundleArchiveDir() string {
	return filepath.Join(s.cfg.Root, "bundles")
}

// archiveBundle records a freshly written bundle's three files in the archive.
func (s *LowServer) archiveBundle(bundleID string) error {
	dir := s.bundleArchiveDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, suffix := range bundleSuffixes() {
		src := filepath.Join(s.cfg.ExportDir, bundleID+suffix)
		dst := filepath.Join(dir, bundleID+suffix)
		if err := linkOrCopyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// linkOrCopyFile makes dst another name for src's already-fsynced bytes. The
// bundle files this backs are immutable signed artifacts, and the export spool
// and archive share a filesystem in the default layout, so a hardlink replaces
// what used to be a full read+write copy of a potentially multi-gigabyte
// archive on every export and every re-export. Cross-device layouts (EXDEV) —
// or a filesystem without hardlinks — fall back to the copy. An existing dst
// is replaced so replay stays idempotent, matching the copy path's rename-over
// behavior.
func linkOrCopyFile(src, dst string) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(src, tmp); err != nil {
		return copyFileAtomic(src, dst, 0o644)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
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
		if err := linkOrCopyFile(src, dst); err != nil {
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
