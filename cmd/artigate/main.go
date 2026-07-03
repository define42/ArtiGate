// artigate implements a low-side Go module pull-through/export server
// and a high-side read-only Go module repository server for data-diode use.
//
// It intentionally uses only the Go standard library. The low side delegates
// GitHub/direct VCS fetching to the installed `go` command. The high side never
// invokes `go` and never fetches upstream.
package main

import (
	"archive/tar"
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
	"time"
)

const (
	manifestType  = "go-module-bundle"
	completeExt   = ".complete"
	stateFileMode = 0o600
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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  artigate keygen --private low.ed25519 --public high.ed25519.pub

  artigate low \
    --listen :8080 \
    --root /var/lib/artigate-low \
    --export-dir /var/spool/diode-out \
    --private-key /etc/artigate/low.ed25519 \
    --upstream-goproxy https://proxy.golang.org,direct \
    --goprivate github.com/your-org/* \
    --gonosumdb github.com/your-org/* \
    --export-interval 60s

  artigate high \
    --listen :8080 \
    --root /var/lib/artigate-high \
    --landing /var/spool/diode-in \
    --public-key /etc/artigate/high.ed25519.pub \
    --import-interval 10s

Low-side clients:
  GOPROXY=http://low-proxy:8080,off

High-side clients:
  GOPROXY=http://high-proxy:8080,off
  GOSUMDB=off

Useful admin endpoints:
  low:  POST /admin/export
  low:  POST /admin/reexport?sequences=42,45-47
  low:  GET  /admin/bundles
  high: POST /admin/import
  high: GET  /admin/missing
  high: GET  /admin/status

`)
}

// -----------------------------------------------------------------------------
// Shared manifest/state types
// -----------------------------------------------------------------------------

type BundleManifest struct {
	Type             string          `json:"type"`
	Sequence         int64           `json:"sequence"`
	PreviousSequence int64           `json:"previous_sequence"`
	Created          time.Time       `json:"created"`
	Generator        string          `json:"generator"`
	BundleID         string          `json:"bundle_id"`
	Ecosystems       []string        `json:"ecosystems,omitempty"`
	Modules          []ManifestMod   `json:"modules,omitempty"`
	Python           *PythonManifest `json:"python,omitempty"`
	Files            []ManifestFile  `json:"files"`
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
	ExportInterval  time.Duration
	AutoApprove     bool
	GoBinary        string
	PipBinary       string
}

type LowState struct {
	NextSequence int64                     `json:"next_sequence"`
	Requests     map[string]*RequestRecord `json:"requests"`
}

type RequestRecord struct {
	Module      string    `json:"module"`
	Version     string    `json:"version"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Approved    bool      `json:"approved"`
	ExportedSeq int64     `json:"exported_sequence,omitempty"`
	ExportedAt  time.Time `json:"exported_at,omitempty"`
}

type LowServer struct {
	cfg         LowConfig
	privateKey  ed25519.PrivateKey
	downloadDir string // $GOPATH/pkg/mod/cache/download
	gopath      string
	statePath   string
	mu          sync.Mutex
	state       LowState
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
	fs.DurationVar(&cfg.ExportInterval, "export-interval", 60*time.Second, "automatic export interval; 0 disables background export")
	fs.BoolVar(&cfg.AutoApprove, "auto-approve", true, "automatically approve discovered module versions for export")
	fs.StringVar(&cfg.GoBinary, "go", "go", "go command path")
	fs.StringVar(&cfg.PipBinary, "python", "python3", "python interpreter used for pip download of Python packages")
	_ = fs.Parse(args)

	if cfg.PrivateKeyPath == "" {
		log.Fatal("--private-key is required")
	}
	priv, err := readPrivateKey(cfg.PrivateKeyPath)
	must(err)

	ls, err := NewLowServer(cfg, priv)
	must(err)

	if cfg.ExportInterval > 0 {
		go ls.exportLoop()
	}

	mux := http.NewServeMux()
	mux.Handle("/", ls)
	log.Printf("low-side proxy listening on %s", cfg.Listen)
	log.Printf("low-side cache: %s", ls.downloadDir)
	log.Printf("low-side export dir: %s", cfg.ExportDir)
	must(http.ListenAndServe(cfg.Listen, logHTTP(mux)))
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
	ls := &LowServer{
		cfg:         cfg,
		privateKey:  priv,
		downloadDir: dl,
		gopath:      gopath,
		statePath:   filepath.Join(cfg.Root, "low-state.json"),
		state:       LowState{NextSequence: 1, Requests: map[string]*RequestRecord{}},
	}
	if err := ls.loadState(); err != nil {
		return nil, err
	}
	return ls, nil
}

func (s *LowServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.serveLowAdmin(w, r) {
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := parseProxyRequest(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Kind {
	case proxyList:
		s.handleLowList(w, r, req)
	case proxyLatest:
		s.handleLowLatest(w, r, req)
	case proxyVersionFile:
		s.handleLowVersionFile(w, r, req)
	case proxyUnknown:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// serveLowAdmin handles the health check and /admin/* routes. It reports
// whether it has written a response for the request.
func (s *LowServer) serveLowAdmin(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/healthz":
		_, _ = w.Write([]byte("ok\n"))
	case r.URL.Path == "/admin/export" && r.Method == http.MethodPost:
		res, err := s.ExportPending(r.Context())
		return respondJSONOrError(w, http.StatusInternalServerError, res, err)
	case r.URL.Path == "/admin/reexport" && r.Method == http.MethodPost:
		res, err := s.HandleReexportRequest(r.Context(), r)
		return respondJSONOrError(w, http.StatusBadRequest, res, err)
	case r.URL.Path == "/admin/bundles" && r.Method == http.MethodGet:
		writeJSON(w, s.BundleStatus())
	case r.URL.Path == "/admin/go/collect" && r.Method == http.MethodPost:
		res, err := s.HandleGoCollect(r.Context(), r)
		return respondJSONOrError(w, http.StatusBadRequest, res, err)
	case r.URL.Path == "/admin/python/collect" && r.Method == http.MethodPost:
		res, err := s.HandlePythonCollect(r.Context(), r)
		return respondJSONOrError(w, http.StatusBadRequest, res, err)
	case strings.HasPrefix(r.URL.Path, "/admin/"):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		return false
	}
	return true
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

func (s *LowServer) handleLowList(w http.ResponseWriter, r *http.Request, req ProxyRequest) {
	versions, err := s.goListVersions(r.Context(), req.Module)
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

func (s *LowServer) handleLowLatest(w http.ResponseWriter, r *http.Request, req ProxyRequest) {
	info, err := s.goLatest(r.Context(), req.Module)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := s.fetchVersion(r.Context(), req.Module, info.Version); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.recordRequest(req.Module, info.Version)
	writeJSON(w, info)
}

func (s *LowServer) handleLowVersionFile(w http.ResponseWriter, r *http.Request, req ProxyRequest) {
	rel := req.RelativePath
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(rel))
	if !safeJoin(s.downloadDir, abs) {
		http.Error(w, "unsafe path", http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(abs); err != nil {
		if req.Ext == ".ziphash" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err := s.fetchVersion(r.Context(), req.Module, req.Version); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}

	s.recordRequest(req.Module, req.Version)
	serveFile(w, r, abs)
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.GoBinary, args...)
	cmd.Env = s.goEnv()
	cmd.Dir = s.cfg.Root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("go %s failed: %w\n%s", strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

type goListVersionsJSON struct {
	Path     string   `json:"Path"`
	Versions []string `json:"Versions"`
	Error    string   `json:"Error"`
}

func (s *LowServer) goListVersions(ctx context.Context, modulePath string) ([]string, error) {
	out, err := s.runGo(ctx, "list", "-m", "-versions", "-json", modulePath)
	if err != nil {
		return nil, err
	}
	var v goListVersionsJSON
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, fmt.Errorf("parse go list versions: %w: %s", err, string(out))
	}
	if v.Error != "" {
		return nil, errors.New(v.Error)
	}
	return v.Versions, nil
}

type goLatestJSON struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
	Error   string    `json:"Error"`
}

func (s *LowServer) goLatest(ctx context.Context, modulePath string) (ModuleInfo, error) {
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

func (s *LowServer) recordRequest(modulePath, version string) {
	if modulePath == "" || version == "" || version == "latest" {
		return
	}
	now := time.Now().UTC()
	key := modulePath + "@" + version
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.Requests[key]
	if !ok {
		rec = &RequestRecord{Module: modulePath, Version: version, FirstSeen: now, Approved: s.cfg.AutoApprove}
		s.state.Requests[key] = rec
	}
	rec.LastSeen = now
	if s.cfg.AutoApprove {
		rec.Approved = true
	}
	if err := s.saveStateLocked(); err != nil {
		log.Printf("save low state: %v", err)
	}
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
	if st.NextSequence <= 0 {
		st.NextSequence = 1
	}
	if st.Requests == nil {
		st.Requests = map[string]*RequestRecord{}
	}
	s.state = st
	return nil
}

func (s *LowServer) saveStateLocked() error {
	return writeJSONAtomic(s.statePath, s.state, stateFileMode)
}

func (s *LowServer) exportLoop() {
	t := time.NewTicker(s.cfg.ExportInterval)
	defer t.Stop()
	for range t.C {
		res, err := s.ExportPending(context.Background())
		if err != nil {
			log.Printf("export failed: %v", err)
			continue
		}
		if res.ExportedModules > 0 {
			log.Printf("exported bundle sequence=%d modules=%d", res.Sequence, res.ExportedModules)
		}
	}
}

type ExportResult struct {
	Sequence        int64  `json:"sequence,omitempty"`
	ExportedModules int    `json:"exported_modules"`
	BundleID        string `json:"bundle_id,omitempty"`
	Message         string `json:"message,omitempty"`
}

func (s *LowServer) ExportPending(ctx context.Context) (ExportResult, error) {
	s.mu.Lock()
	var pending []RequestRecord
	seq := s.state.NextSequence
	for _, rec := range s.state.Requests {
		if rec.Approved && rec.ExportedSeq == 0 {
			pending = append(pending, *rec)
		}
	}
	s.mu.Unlock()

	if len(pending) == 0 {
		return ExportResult{ExportedModules: 0, Message: "no pending modules"}, nil
	}

	res, err := s.writeBundle(ctx, seq, pending)
	if err != nil {
		return ExportResult{}, err
	}

	now := time.Now().UTC()
	s.mu.Lock()
	for _, rec := range pending {
		key := rec.Module + "@" + rec.Version
		if cur := s.state.Requests[key]; cur != nil && cur.ExportedSeq == 0 {
			cur.ExportedSeq = seq
			cur.ExportedAt = now
		}
	}
	if s.state.NextSequence <= seq {
		s.state.NextSequence = seq + 1
	}
	err = s.saveStateLocked()
	s.mu.Unlock()
	if err != nil {
		return ExportResult{}, err
	}

	return res, nil
}

// GoCollectRequest is the body of POST /admin/go/collect. Each entry is a
// module spec: "module@version" for a concrete version, or "module" /
// "module@latest" to resolve the latest version via the low-side toolchain.
type GoCollectRequest struct {
	Modules []string `json:"modules"`
}

// HandleGoCollect parses a JSON collect request and runs the collection.
func (s *LowServer) HandleGoCollect(ctx context.Context, r *http.Request) (ExportResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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

// CollectGo fetches an explicit list of Go modules on demand (resolving
// "latest" where needed) and writes them into a signed bundle on the shared
// ArtiGate sequence stream. This complements the pull-through proxy for cases
// where the set of modules is known ahead of time, mirroring the Python
// collector.
func (s *LowServer) CollectGo(ctx context.Context, req GoCollectRequest) (ExportResult, error) {
	if len(req.Modules) == 0 {
		return ExportResult{}, errors.New("no go modules provided")
	}
	records, err := s.resolveGoRequests(ctx, req.Modules)
	if err != nil {
		return ExportResult{}, err
	}
	// Peek the sequence, fetch+write, and only commit on success so a failed
	// fetch never burns a sequence number and leaves a gap the high side would
	// block on.
	seq := s.peekSequence()
	res, err := s.writeBundle(ctx, seq, records)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.commitSequence(seq); err != nil {
		return ExportResult{}, err
	}
	return res, nil
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

// peekSequence returns the next sequence number to write without advancing it.
func (s *LowServer) peekSequence() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.state.NextSequence
	if seq < 1 {
		seq = 1
	}
	return seq
}

// commitSequence advances the stream past seq after a bundle for it has been
// written successfully.
func (s *LowServer) commitSequence(seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.NextSequence <= seq {
		s.state.NextSequence = seq + 1
	}
	return s.saveStateLocked()
}

func (s *LowServer) writeBundle(ctx context.Context, seq int64, records []RequestRecord) (ExportResult, error) {
	if seq <= 0 {
		return ExportResult{}, fmt.Errorf("invalid sequence %d", seq)
	}
	if len(records) == 0 {
		return ExportResult{Sequence: seq, ExportedModules: 0, Message: "no modules for sequence"}, nil
	}
	sortRequestRecords(records)

	mods, files, err := s.fetchBundleContent(ctx, records)
	if err != nil {
		return ExportResult{}, err
	}

	bundleID := bundleIDForSequence(seq)
	manifest := BundleManifest{
		Type:             manifestType,
		Sequence:         seq,
		PreviousSequence: seq - 1,
		Created:          time.Now().UTC(),
		Generator:        hostnameOrDefault(),
		BundleID:         bundleID,
		Ecosystems:       []string{"go"},
		Modules:          mods,
		Files:            files,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	sig := ed25519.Sign(s.privateKey, manifestBytes)

	if err := s.writeBundleArtifacts(bundleID, s.downloadDir, manifestBytes, sig, files); err != nil {
		return ExportResult{}, err
	}

	return ExportResult{Sequence: seq, ExportedModules: len(mods), BundleID: bundleID}, nil
}

// fetchBundleContent fetches every record's module and returns the module
// manifests plus the de-duplicated set of files they reference.
func (s *LowServer) fetchBundleContent(ctx context.Context, records []RequestRecord) ([]ManifestMod, []ManifestFile, error) {
	var mods []ManifestMod
	var files []ManifestFile
	seenFile := map[string]bool{}
	for _, rec := range records {
		if err := s.fetchVersion(ctx, rec.Module, rec.Version); err != nil {
			return nil, nil, fmt.Errorf("fetch %s@%s: %w", rec.Module, rec.Version, err)
		}
		mf, err := s.manifestForModule(rec.Module, rec.Version)
		if err != nil {
			return nil, nil, err
		}
		mods = append(mods, mf)
		for _, f := range mf.Files {
			if !seenFile[f.Path] {
				files = append(files, f)
				seenFile[f.Path] = true
			}
		}
	}
	return mods, files, nil
}

// writeBundleArtifacts writes the archive, manifest, and signature for a bundle
// into the export directory. baseDir is the root the manifest file paths are
// relative to (the Go module cache for Go bundles, a staging dir for Python).
func (s *LowServer) writeBundleArtifacts(bundleID, baseDir string, manifestBytes, sig []byte, files []ManifestFile) error {
	if err := os.MkdirAll(s.cfg.ExportDir, 0o755); err != nil {
		return err
	}
	archivePath := filepath.Join(s.cfg.ExportDir, bundleID+".tar.gz")
	manifestPath := filepath.Join(s.cfg.ExportDir, bundleID+".manifest.json")
	sigPath := filepath.Join(s.cfg.ExportDir, bundleID+".manifest.json.sig")

	if err := createTarGzAtomic(archivePath, baseDir, files); err != nil {
		return err
	}
	if err := writeBytesAtomic(manifestPath, manifestBytes, 0o644); err != nil {
		return err
	}
	return writeBytesAtomic(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
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
	Sequences string `json:"sequences"`
}

type ReexportResult struct {
	RequestedRanges []string       `json:"requested_ranges"`
	Sequences       []int64        `json:"sequences"`
	Reexported      []ExportResult `json:"reexported"`
	Failed          []string       `json:"failed,omitempty"`
}

func (s *LowServer) HandleReexportRequest(ctx context.Context, r *http.Request) (ReexportResult, error) {
	spec, err := reexportSpecFromRequest(r)
	if err != nil {
		return ReexportResult{}, err
	}
	if spec == "" {
		return ReexportResult{}, errors.New("missing sequence range; use ?sequences=42,45-47 or JSON {\"sequences\":\"42,45-47\"}")
	}
	ranges, err := parseSequenceSpec(spec)
	if err != nil {
		return ReexportResult{}, err
	}
	return s.ReexportSequences(ctx, ranges), nil
}

// reexportSpecFromRequest extracts the sequence spec from either the
// ?sequences= query parameter, a raw request body, or a JSON body.
func reexportSpecFromRequest(r *http.Request) (string, error) {
	if spec := strings.TrimSpace(r.URL.Query().Get("sequences")); spec != "" {
		return spec, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		var req ReexportHTTPBody
		if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
			return "", err
		}
		return strings.TrimSpace(req.Sequences), nil
	}
	return trimmed, nil
}

func (s *LowServer) ReexportSequences(ctx context.Context, ranges []SequenceRange) ReexportResult {
	seqs := expandSequenceRanges(ranges, 10000)
	res := ReexportResult{RequestedRanges: rangesToStrings(ranges), Sequences: seqs}
	for _, seq := range seqs {
		out, err := s.ExportSequence(ctx, seq)
		if err != nil {
			res.Failed = append(res.Failed, fmt.Sprintf("%d: %v", seq, err))
			continue
		}
		res.Reexported = append(res.Reexported, out)
	}
	return res
}

func (s *LowServer) ExportSequence(ctx context.Context, seq int64) (ExportResult, error) {
	s.mu.Lock()
	var records []RequestRecord
	for _, rec := range s.state.Requests {
		if rec.ExportedSeq == seq {
			records = append(records, *rec)
		}
	}
	s.mu.Unlock()
	if len(records) == 0 {
		return ExportResult{}, fmt.Errorf("no recorded modules for sequence %d", seq)
	}
	return s.writeBundle(ctx, seq, records)
}

type LowBundleStatus struct {
	NextSequence      int64                  `json:"next_sequence"`
	PendingModules    int                    `json:"pending_modules"`
	ExportedSequences []ExportedSequenceInfo `json:"exported_sequences"`
}

type ExportedSequenceInfo struct {
	Sequence     int64  `json:"sequence"`
	BundleID     string `json:"bundle_id"`
	Modules      int    `json:"modules"`
	FilesPresent bool   `json:"files_present"`
}

func (s *LowServer) BundleStatus() LowBundleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySeq := map[int64]int{}
	pending := 0
	for _, rec := range s.state.Requests {
		if rec.Approved && rec.ExportedSeq == 0 {
			pending++
		}
		if rec.ExportedSeq > 0 {
			bySeq[rec.ExportedSeq]++
		}
	}
	seqs := make([]int64, 0, len(bySeq))
	for seq := range bySeq {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	out := LowBundleStatus{NextSequence: s.state.NextSequence, PendingModules: pending}
	for _, seq := range seqs {
		bundleID := bundleIDForSequence(seq)
		out.ExportedSequences = append(out.ExportedSequences, ExportedSequenceInfo{
			Sequence:     seq,
			BundleID:     bundleID,
			Modules:      bySeq[seq],
			FilesPresent: bundleCompleteInDir(s.cfg.ExportDir, bundleID),
		})
	}
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
}

type HighState struct {
	LastImportedSequence int64     `json:"last_imported_sequence"`
	LastImportedBundle   string    `json:"last_imported_bundle,omitempty"`
	ImportedAt           time.Time `json:"imported_at,omitempty"`
}

type HighServer struct {
	cfg         HighConfig
	publicKey   ed25519.PublicKey
	downloadDir string
	statePath   string
	mu          sync.Mutex
	state       HighState
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
	_ = fs.Parse(args)
	if cfg.PublicKeyPath == "" {
		log.Fatal("--public-key is required")
	}
	pub, err := readPublicKey(cfg.PublicKeyPath)
	must(err)
	hs, err := NewHighServer(cfg, pub)
	must(err)

	if cfg.ImportInterval > 0 {
		go hs.importLoop()
	}

	mux := http.NewServeMux()
	mux.Handle("/", hs)
	log.Printf("high-side repository listening on %s", cfg.Listen)
	log.Printf("high-side repo: %s", hs.downloadDir)
	log.Printf("high-side landing: %s", cfg.Landing)
	log.Printf("high-side quarantine: %s", hs.cfg.Quarantine)
	must(http.ListenAndServe(cfg.Listen, logHTTP(mux)))
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
	if s.serveHighAdmin(w, r) {
		return
	}
	if s.servePython(w, r) {
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := parseProxyRequest(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
	abs := filepath.Join(s.downloadDir, filepath.FromSlash(req.RelativePath))
	if !safeJoin(s.downloadDir, abs) {
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
	base := filepath.Join(s.downloadDir, filepath.FromSlash(moduleEsc), "@v")
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
	base := filepath.Join(s.downloadDir, filepath.FromSlash(moduleEsc), "@v")
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
		s.state = HighState{}
		return s.saveStateLocked()
	}
	if err != nil {
		return err
	}
	var st HighState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
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
			log.Printf("imported bundle sequence=%d modules=%d", res.Sequence, res.Modules)
		}
	}
}

type ImportResult struct {
	Imported             bool     `json:"imported"`
	Sequence             int64    `json:"sequence,omitempty"`
	Modules              int      `json:"modules,omitempty"`
	ImportedSequences    []int64  `json:"imported_sequences,omitempty"`
	QuarantinedSequences []int64  `json:"quarantined_sequences,omitempty"`
	MissingRanges        []string `json:"missing_ranges,omitempty"`
	Message              string   `json:"message,omitempty"`
}

type ImportStatus struct {
	LastImportedSequence int64    `json:"last_imported_sequence"`
	NextExpectedSequence int64    `json:"next_expected_sequence"`
	HighestSeenSequence  int64    `json:"highest_seen_sequence"`
	BlockingMissing      int64    `json:"blocking_missing_sequence,omitempty"`
	MissingRanges        []string `json:"missing_ranges"`
	LandingSequences     []int64  `json:"landing_sequences"`
	QuarantinedSequences []int64  `json:"quarantined_sequences"`
	ReadyToImport        bool     `json:"ready_to_import"`
}

func (s *HighServer) ImportStatus() (ImportStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.quarantineFutureBundlesLocked(); err != nil {
		return ImportStatus{}, err
	}
	return s.importStatusLocked()
}

func (s *HighServer) ImportNext() (ImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var importedSeqs []int64
	modules := 0

	for {
		if err := s.quarantineFutureBundlesLocked(); err != nil {
			return ImportResult{}, err
		}

		next := s.state.LastImportedSequence + 1
		bundleID := bundleIDForSequence(next)
		bundleDir, ok := s.findBundleDirLocked(bundleID)
		if !ok {
			status, err := s.importStatusLocked()
			if err != nil {
				return ImportResult{}, err
			}
			msg := fmt.Sprintf("waiting for bundle sequence %d", next)
			if len(status.MissingRanges) > 0 {
				msg = fmt.Sprintf("%s; missing ranges: %s", msg, strings.Join(status.MissingRanges, ","))
			}
			return ImportResult{
				Imported:             len(importedSeqs) > 0,
				Sequence:             s.state.LastImportedSequence,
				Modules:              modules,
				ImportedSequences:    importedSeqs,
				QuarantinedSequences: status.QuarantinedSequences,
				MissingRanges:        status.MissingRanges,
				Message:              msg,
			}, nil
		}

		manifest, err := s.importBundleFromDirLocked(bundleDir, bundleID, next)
		if err != nil {
			return ImportResult{}, err
		}
		importedSeqs = append(importedSeqs, manifest.Sequence)
		modules += len(manifest.Modules)
	}
}

func (s *HighServer) importBundleFromDirLocked(bundleDir, bundleID string, expectedSeq int64) (BundleManifest, error) {
	manifestPath := filepath.Join(bundleDir, bundleID+".manifest.json")
	sigPath := filepath.Join(bundleDir, bundleID+".manifest.json.sig")
	archivePath := filepath.Join(bundleDir, bundleID+".tar.gz")

	if !fileExists(manifestPath) || !fileExists(sigPath) || !fileExists(archivePath) {
		return BundleManifest{}, fmt.Errorf("bundle %s incomplete: need archive, manifest and signature", bundleID)
	}

	manifest, err := s.loadVerifiedManifest(manifestPath, sigPath, bundleID, expectedSeq)
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

	s.state.LastImportedSequence = manifest.Sequence
	s.state.LastImportedBundle = manifest.BundleID
	s.state.ImportedAt = time.Now().UTC()
	if err := s.saveStateLocked(); err != nil {
		return BundleManifest{}, err
	}
	if err := moveImportedFilesFromDir(bundleDir, filepath.Join(s.cfg.Landing, "imported"), manifest.BundleID); err != nil {
		log.Printf("move imported files: %v", err)
	}
	return manifest, nil
}

// loadVerifiedManifest reads the manifest and its detached signature, verifies
// the signature, and checks the manifest's identifying fields.
func (s *HighServer) loadVerifiedManifest(manifestPath, sigPath, bundleID string, expectedSeq int64) (BundleManifest, error) {
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
	if err := s.checkManifestFields(manifest, bundleID, expectedSeq); err != nil {
		return BundleManifest{}, err
	}
	return manifest, nil
}

// checkManifestFields validates the manifest's type, sequencing, and identity
// against what the importer expects next.
func (s *HighServer) checkManifestFields(manifest BundleManifest, bundleID string, expectedSeq int64) error {
	switch {
	case manifest.Type != manifestType:
		return fmt.Errorf("wrong manifest type %q", manifest.Type)
	case manifest.Sequence != expectedSeq:
		return fmt.Errorf("sequence mismatch: got %d, want %d", manifest.Sequence, expectedSeq)
	case manifest.PreviousSequence != s.state.LastImportedSequence:
		return fmt.Errorf("previous sequence mismatch: got %d, want %d", manifest.PreviousSequence, s.state.LastImportedSequence)
	case manifest.BundleID != bundleID:
		return fmt.Errorf("bundle_id mismatch: got %q, want %q", manifest.BundleID, bundleID)
	}
	return validateManifestCompleteness(manifest)
}

func (s *HighServer) quarantineFutureBundlesLocked() error {
	next := s.state.LastImportedSequence + 1
	seqs, err := findBundleSequences(s.cfg.Landing)
	if err != nil {
		return err
	}
	for _, seq := range seqs {
		bundleID := bundleIDForSequence(seq)
		if !bundleCompleteInDir(s.cfg.Landing, bundleID) {
			continue
		}
		switch {
		case seq > next:
			if err := moveBundleFiles(s.cfg.Landing, s.cfg.Quarantine, bundleID); err != nil {
				return err
			}
		case seq <= s.state.LastImportedSequence:
			dupDir := filepath.Join(s.cfg.Landing, "duplicates")
			if err := moveBundleFiles(s.cfg.Landing, dupDir, bundleID); err != nil {
				return err
			}
		}
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
	landing, err := findBundleSequences(s.cfg.Landing)
	if err != nil {
		return ImportStatus{}, err
	}
	quarantined, err := findBundleSequences(s.cfg.Quarantine)
	if err != nil {
		return ImportStatus{}, err
	}

	present := map[int64]bool{}
	maxSeen := s.state.LastImportedSequence
	maxSeen = markPresentComplete(s.cfg.Landing, landing, present, maxSeen)
	maxSeen = markPresentComplete(s.cfg.Quarantine, quarantined, present, maxSeen)

	next := s.state.LastImportedSequence + 1
	missing := missingRanges(next, maxSeen, present)
	status := ImportStatus{
		LastImportedSequence: s.state.LastImportedSequence,
		NextExpectedSequence: next,
		HighestSeenSequence:  maxSeen,
		MissingRanges:        rangesToStrings(missing),
		LandingSequences:     filterCompleteSequences(s.cfg.Landing, landing),
		QuarantinedSequences: filterCompleteSequences(s.cfg.Quarantine, quarantined),
		ReadyToImport:        present[next],
	}
	if !present[next] && maxSeen >= next {
		status.BlockingMissing = next
	}
	return status, nil
}

// markPresentComplete marks every complete bundle in dir as present and returns
// the updated highest-seen sequence.
func markPresentComplete(dir string, seqs []int64, present map[int64]bool, maxSeen int64) int64 {
	for _, seq := range seqs {
		if bundleCompleteInDir(dir, bundleIDForSequence(seq)) {
			present[seq] = true
			if seq > maxSeen {
				maxSeen = seq
			}
		}
	}
	return maxSeen
}

func validateManifestCompleteness(m BundleManifest) error {
	seen, err := validateManifestFiles(m.Files)
	if err != nil {
		return err
	}
	hasGo := len(m.Modules) > 0
	hasPython := m.Python != nil && len(m.Python.Projects) > 0
	if !hasGo && !hasPython {
		return errors.New("manifest contains no modules or python projects")
	}
	if hasGo {
		if err := validateManifestModules(m.Modules, seen); err != nil {
			return err
		}
	}
	if hasPython {
		if err := validatePythonProjects(m.Python.Projects, seen); err != nil {
			return err
		}
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
	if err := s.installVerifiedFiles(staging, manifest.Files); err != nil {
		return err
	}
	// Complete markers are written only after all files are installed.
	return s.writeCompleteMarkers(manifest.Modules)
}

// installVerifiedFiles copies every verified file into the accumulated
// repository, refusing to overwrite an existing immutable file with different
// content.
func (s *HighServer) installVerifiedFiles(staging string, files []ManifestFile) error {
	for _, f := range files {
		src := filepath.Join(staging, filepath.FromSlash(f.Path))
		dst := filepath.Join(s.downloadDir, filepath.FromSlash(f.Path))
		if !safeJoin(s.downloadDir, dst) {
			return fmt.Errorf("unsafe destination %s", f.Path)
		}
		if fileExists(dst) {
			existing, err := sha256File(dst)
			if err != nil {
				return err
			}
			if existing != f.SHA256 {
				return fmt.Errorf("immutable file conflict for %s", f.Path)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := copyFileAtomic(src, dst, 0o644); err != nil {
			return err
		}
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
		marker := filepath.Join(s.downloadDir, filepath.FromSlash(moduleEsc), "@v", versionEsc+completeExt)
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

func createTarGzAtomic(dst string, baseDir string, files []ManifestFile) error {
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
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, mf := range files {
		if err := addFileToTar(tw, baseDir, mf); err != nil {
			return err
		}
	}
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
// deterministic header.
func addFileToTar(tw *tar.Writer, baseDir string, mf ManifestFile) error {
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
	_, copyErr := io.Copy(tw, in)
	closeErr := in.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func extractAndVerifyTarGz(archivePath, staging string, files []ManifestFile) error {
	expected := map[string]ManifestFile{}
	for _, f := range files {
		if err := validateRelPath(f.Path); err != nil {
			return err
		}
		expected[f.Path] = f
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
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
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

var bundleManifestNameRE = regexp.MustCompile(`^go-bundle-([0-9]{6})\.manifest\.json$`)

func bundleIDForSequence(seq int64) string {
	return fmt.Sprintf("go-bundle-%06d", seq)
}

func parseBundleSeqFromManifestName(name string) (int64, bool) {
	m := bundleManifestNameRE.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	return n, err == nil
}

func bundleCompleteInDir(dir, bundleID string) bool {
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		if !fileExists(filepath.Join(dir, bundleID+suffix)) {
			return false
		}
	}
	return true
}

func findBundleSequences(dir string) ([]int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		seq, ok := parseBundleSeqFromManifestName(e.Name())
		if ok {
			seen[seq] = true
		}
	}
	seqs := make([]int64, 0, len(seen))
	for seq := range seen {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}

func filterCompleteSequences(dir string, seqs []int64) []int64 {
	out := make([]int64, 0, len(seqs))
	for _, seq := range seqs {
		if bundleCompleteInDir(dir, bundleIDForSequence(seq)) {
			out = append(out, seq)
		}
	}
	return out
}

func moveBundleFiles(srcDir, dstDir, bundleID string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		src := filepath.Join(srcDir, bundleID+suffix)
		if !fileExists(src) {
			continue
		}
		dst := filepath.Join(dstDir, bundleID+suffix)
		_ = os.Remove(dst)
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	return nil
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
