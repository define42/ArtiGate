package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoCollectCredentials(t *testing.T) {
	t.Setenv(goAuthEnv, "gitlab.example.com=envuser:envpass")
	// The mirror streams' variable must not reach a Go collect: buildGoAuthEnv
	// treats every credentialed host as module-private, so a git/apt/rpm/apk
	// login for github.com would flip public github.com/... fetches off the
	// proxy and sumdb.
	t.Setenv(upstreamAuthEnv, "github.com=gituser:gitpass")

	// Without request auth the standing env credentials apply (the scheduled
	// path).
	creds, err := goCollectCredentials(GoCollectRequest{Modules: []string{"gitlab.example.com/g/m@v1.0.0"}})
	if err != nil || creds["gitlab.example.com"].Username != "envuser" {
		t.Fatalf("env creds = %v, %v", creds, err)
	}
	if _, ok := creds["github.com"]; ok {
		t.Fatal("ARTIGATE_UPSTREAM_AUTH (git/apt/rpm/apk) must not apply to Go collects")
	}

	// A named host is authoritative and the request login wins over the env.
	creds, err = goCollectCredentials(GoCollectRequest{
		Modules: []string{"gitlab.example.com/g/m"},
		Auth:    &HostCollectAuth{Host: "GitLab.example.com", Username: "u", Password: "p"},
	})
	if err != nil || creds["gitlab.example.com"] != (registryCredential{Username: "u", Password: "p"}) {
		t.Fatalf("request creds = %v, %v", creds, err)
	}

	// An unnamed host is inferred when every module shares one host-like prefix.
	creds, err = goCollectCredentials(GoCollectRequest{
		Modules: []string{"gitlab.example.com/g/a", "gitlab.example.com/g/b@v2.0.0"},
		Auth:    &HostCollectAuth{Username: "u", Password: "p"},
	})
	if err != nil || creds["gitlab.example.com"].Username != "u" {
		t.Fatalf("inferred-host creds = %v, %v", creds, err)
	}

	// Ambiguous (multi-host), non-host-like ("std"-style single element), and
	// go.mod-mode requests all require an explicit host.
	for _, req := range []GoCollectRequest{
		{Modules: []string{"gitlab.example.com/g/a", "github.com/x/y"}, Auth: &HostCollectAuth{Username: "u", Password: "p"}},
		{Modules: []string{"internalmod"}, Auth: &HostCollectAuth{Username: "u", Password: "p"}},
		{GoMod: "module x\n", Auth: &HostCollectAuth{Username: "u", Password: "p"}},
	} {
		if _, err := goCollectCredentials(req); err == nil || !strings.Contains(err.Error(), "auth.host") {
			t.Errorf("req %+v should require auth.host, got %v", req, err)
		}
	}

	// Missing password is rejected.
	if _, err := goCollectCredentials(GoCollectRequest{
		Modules: []string{"gitlab.example.com/g/m"}, Auth: &HostCollectAuth{Host: "gitlab.example.com", Username: "u"},
	}); err == nil {
		t.Error("a login without a password should fail")
	}

	// A malformed env value fails the collect, naming the variable — while a
	// malformed ARTIGATE_UPSTREAM_AUTH is irrelevant here and must not.
	t.Setenv(goAuthEnv, "garbage")
	if _, err := goCollectCredentials(GoCollectRequest{Modules: []string{"x"}}); err == nil || !strings.Contains(err.Error(), goAuthEnv) {
		t.Errorf("malformed env value should fail naming %s, got %v", goAuthEnv, err)
	}
	t.Setenv(goAuthEnv, "")
	t.Setenv(upstreamAuthEnv, "garbage")
	if creds, err := goCollectCredentials(GoCollectRequest{Modules: []string{"x"}}); err != nil || len(creds) != 0 {
		t.Errorf("a malformed %s must not affect a Go collect, got %v, %v", upstreamAuthEnv, creds, err)
	}
}

func TestBuildGoAuthEnv(t *testing.T) {
	root := t.TempDir()

	// No credentials: a no-op state and cleanup, no scratch dir created.
	st, cleanup, err := buildGoAuthEnv(root, nil)
	if err != nil || st != nil {
		t.Fatalf("empty creds = %v, %v", st, err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Join(root, "gocollect")); !os.IsNotExist(err) {
		t.Error("empty creds should not create the gocollect dir")
	}

	creds := map[string]registryCredential{
		"gitlab.example.com": {Username: "bot", Password: "s3cr3t"},
		"git.other.com":      {Username: "u2", Password: "p2"},
	}
	st, cleanup, err = buildGoAuthEnv(root, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	env := map[string]string{}
	for _, e := range st.env {
		k, v, _ := strings.Cut(e, "=")
		env[k] = v
	}
	// A NETRC file is set, 0600, and lists both hosts with their logins.
	netrcPath := env["NETRC"]
	if netrcPath == "" || env["GOAUTH"] != "netrc" {
		t.Fatalf("NETRC/GOAUTH env = %q / %q", netrcPath, env["GOAUTH"])
	}
	info, err := os.Stat(netrcPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("netrc stat = %v, mode %v", err, info.Mode().Perm())
	}
	body, _ := os.ReadFile(netrcPath)
	for _, want := range []string{
		"machine git.other.com login u2 password p2",
		"machine gitlab.example.com login bot password s3cr3t",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("netrc missing %q; got:\n%s", want, body)
		}
	}
	// One git credential helper per host (hosts sorted deterministically), with
	// the secrets carried in dedicated vars rather than inline in the snippet.
	if env["GIT_CONFIG_COUNT"] != "2" {
		t.Errorf("GIT_CONFIG_COUNT = %q, want 2", env["GIT_CONFIG_COUNT"])
	}
	if env["GIT_CONFIG_KEY_0"] != "credential.https://git.other.com.helper" ||
		env["GIT_CONFIG_KEY_1"] != "credential.https://gitlab.example.com.helper" {
		t.Errorf("git config keys = %q / %q", env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_KEY_1"])
	}
	if env["ARTIGATE_GO_CRED_1_USER"] != "bot" || env["ARTIGATE_GO_CRED_1_PASS"] != "s3cr3t" {
		t.Errorf("cred vars = %q / %q", env["ARTIGATE_GO_CRED_1_USER"], env["ARTIGATE_GO_CRED_1_PASS"])
	}
	if strings.Contains(env["GIT_CONFIG_VALUE_1"], "s3cr3t") {
		t.Errorf("the helper snippet must not inline the secret: %q", env["GIT_CONFIG_VALUE_1"])
	}
	// Both port-less hosts become GOPRIVATE patterns.
	if len(st.hostPatterns) != 2 {
		t.Errorf("host patterns = %v", st.hostPatterns)
	}

	// Cleanup removes the scratch dir (and the secret with it).
	cleanup()
	if _, err := os.Stat(filepath.Dir(netrcPath)); !os.IsNotExist(err) {
		t.Error("cleanup should remove the netrc scratch dir")
	}
}

func TestBuildGoAuthEnvRejectsWhitespaceLogin(t *testing.T) {
	_, _, err := buildGoAuthEnv(t.TempDir(), map[string]registryCredential{
		"gitlab.example.com": {Username: "bot", Password: "has space"},
	})
	if err == nil || !strings.Contains(err.Error(), "whitespace") || strings.Contains(err.Error(), "has space") {
		t.Fatalf("whitespace login error = %v", err)
	}
}

func TestGoEnvMergesCredentialedHosts(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	ls.cfg.GOPRIVATE = "corp.example/*"

	// Without a credentialed collect, goEnv reflects only the configured value.
	base := envMap(ls.goEnv(context.Background()))
	if base["GOPRIVATE"] != "corp.example/*" {
		t.Fatalf("baseline GOPRIVATE = %q", base["GOPRIVATE"])
	}

	st, cleanup, err := buildGoAuthEnv(ls.cfg.Root, map[string]registryCredential{"gitlab.example.com": {Username: "u", Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := envMap(ls.goEnv(withGoAuth(context.Background(), st)))
	// The credentialed host joins the configured GOPRIVATE, and GONOSUMDB /
	// GONOPROXY — which default to GOPRIVATE while unset — keep that coverage:
	// they must NOT collapse to only the auth host, or corp.example/* modules
	// would leak to the public proxy/sumdb during the collect.
	if got["GOPRIVATE"] != "corp.example/*,gitlab.example.com" {
		t.Errorf("merged GOPRIVATE = %q", got["GOPRIVATE"])
	}
	if got["GONOSUMDB"] != "corp.example/*,gitlab.example.com" || got["GONOPROXY"] != "corp.example/*,gitlab.example.com" {
		t.Errorf("GONOSUMDB/GONOPROXY = %q / %q, want corp.example/* preserved", got["GONOSUMDB"], got["GONOPROXY"])
	}
	if got["NETRC"] == "" || got["GIT_CONFIG_COUNT"] != "1" {
		t.Errorf("auth env not merged: NETRC=%q GIT_CONFIG_COUNT=%q", got["NETRC"], got["GIT_CONFIG_COUNT"])
	}
}

// TestGoNoVarValue pins the GONOSUMDB/GONOPROXY defaulting rule directly: both
// variables default to GOPRIVATE while unset, so a credentialed collect must
// preserve that base rather than replace it with only the auth hosts.
func TestGoNoVarValue(t *testing.T) {
	hosts := []string{"gitlab.example.com"}
	for _, tt := range []struct {
		name                string
		configured, private string
		hosts               []string
		want                string
	}{
		// No credentialed collect: the configured value is exported verbatim
		// (empty when unset, so the subprocess applies its own GOPRIVATE default).
		{"no-auth unset", "", "corp.example/*", nil, ""},
		{"no-auth set", "foo/*", "corp.example/*", nil, "foo/*"},
		// Credentialed: unset falls back to GOPRIVATE before appending hosts;
		// an explicit value is preserved alongside them.
		{"auth unset falls back to GOPRIVATE", "", "corp.example/*", hosts, "corp.example/*,gitlab.example.com"},
		{"auth keeps explicit value", "foo/*", "corp.example/*", hosts, "foo/*,gitlab.example.com"},
		{"auth no GOPRIVATE either", "", "", hosts, "gitlab.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := goNoVarValue(tt.configured, tt.private, tt.hosts); got != tt.want {
				t.Errorf("goNoVarValue(%q,%q,%v) = %q, want %q", tt.configured, tt.private, tt.hosts, got, tt.want)
			}
		})
	}
}

// TestGoAuthGitCredentialRoundTrip proves the generated GIT_CONFIG_* helper
// actually answers a real `git credential fill` for the host.
func TestGoAuthGitCredentialRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	st, cleanup, err := buildGoAuthEnv(t.TempDir(), map[string]registryCredential{
		"gitlab.example.com": {Username: "bot", Password: "s3cr3t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	cmd := exec.Command("git", "credential", "fill")
	// A clean HOME so the user's real credential config can't answer instead.
	cmd.Env = append([]string{"HOME=" + t.TempDir(), "GIT_TERMINAL_PROMPT=0", "PATH=" + os.Getenv("PATH")}, st.env...)
	cmd.Stdin = strings.NewReader("protocol=https\nhost=gitlab.example.com\n\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git credential fill: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "username=bot") || !strings.Contains(string(out), "password=s3cr3t") {
		t.Fatalf("git did not use the injected helper:\n%s", out)
	}
}

// authAssertingGoScript is a fake `go` that materializes modules like
// fakeGoScript but first fails unless the credential environment reached it:
// a NETRC file naming the host, GOAUTH=netrc, one git credential helper, and
// GOPRIVATE covering the host.
const authAssertingGoScript = `#!/usr/bin/env bash
set -eu
[ -n "${NETRC:-}" ] || { echo "NETRC not set" >&2; exit 3; }
grep -q "machine gitlab.example.com " "$NETRC" || { echo "netrc missing host" >&2; exit 3; }
[ "${GOAUTH:-}" = "netrc" ] || { echo "GOAUTH=$GOAUTH" >&2; exit 3; }
[ "${GIT_CONFIG_COUNT:-0}" = "1" ] || { echo "GIT_CONFIG_COUNT=${GIT_CONFIG_COUNT:-}" >&2; exit 3; }
case "${GOPRIVATE:-}" in *gitlab.example.com*) ;; *) echo "GOPRIVATE=${GOPRIVATE:-}" >&2; exit 3;; esac
dldir="${GOMODCACHE}/cache/download"
last=""; for a in "$@"; do last="$a"; done
case "$*" in
  *"download"*)
    mod="${last%@*}"; ver="${last##*@}"
    d="${dldir}/${mod}/@v"; mkdir -p "$d"
    printf '{"Version":"%s","Time":"2020-01-01T00:00:00Z"}' "$ver" > "${d}/${ver}.info"
    printf 'module %s\n' "$mod" > "${d}/${ver}.mod"
    printf 'fake-zip-bytes' > "${d}/${ver}.zip"
    printf '{"Path":"%s","Version":"%s","Info":"%s","GoMod":"%s","Zip":"%s"}\n' \
      "$mod" "$ver" "${d}/${ver}.info" "${d}/${ver}.mod" "${d}/${ver}.zip"
    ;;
esac
`

// TestCollectGoPrivateModules drives a full CollectGo whose fake go binary
// refuses to run unless the injected credential environment is present, both
// via a request login and via ARTIGATE_UPSTREAM_AUTH alone (the scheduled
// path). It also confirms the per-collect secret is cleaned up.
func TestCollectGoPrivateModules(t *testing.T) {
	ls, _ := newFakeLowServerWithGo(t, writeFakeGoWith(t, authAssertingGoScript))
	ctx := context.Background()
	mod := "gitlab.example.com/group/lib@v1.0.0"

	// An anonymous collect fails: the fake go aborts (no NETRC).
	if _, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{mod}}); err == nil {
		t.Fatal("anonymous private collect should fail")
	}

	// A per-collect login makes the fetch succeed.
	res, err := ls.CollectGo(ctx, GoCollectRequest{
		Modules: []string{mod},
		Auth:    &HostCollectAuth{Host: "gitlab.example.com", Username: "bot", Password: "s3cr3t"},
	})
	if err != nil || res.ExportedModules != 1 {
		t.Fatalf("authenticated collect = %+v, %v", res, err)
	}

	// Standing ARTIGATE_GO_AUTH credentials work without request auth.
	t.Setenv(goAuthEnv, "gitlab.example.com=bot:s3cr3t")
	if _, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{mod}, Force: true}); err != nil {
		t.Fatalf("env-authenticated collect: %v", err)
	}

	// The mirror streams' ARTIGATE_UPSTREAM_AUTH must not stand in for it: the
	// same entry there leaves the collect anonymous (the fake go aborts).
	t.Setenv(goAuthEnv, "")
	t.Setenv(upstreamAuthEnv, "gitlab.example.com=bot:s3cr3t")
	if _, err := ls.CollectGo(ctx, GoCollectRequest{Modules: []string{mod}, Force: true}); err == nil {
		t.Fatal("ARTIGATE_UPSTREAM_AUTH alone must not authenticate a Go collect")
	}

	// No credential is left behind under the low root or export dir.
	assertNoSecretOnDisk(t, ls.cfg.Root, "s3cr3t")
	assertNoSecretOnDisk(t, ls.cfg.ExportDir, "s3cr3t")
	// The per-collect scratch dirs are gone.
	if entries, _ := os.ReadDir(filepath.Join(ls.cfg.Root, "gocollect")); len(entries) != 0 {
		t.Errorf("gocollect scratch not cleaned: %v", entries)
	}
}

// TestNewLowServerScrubsStaleGoAuthScratch proves a netrc stranded by a crash
// (the per-collect cleanup never got to run) does not survive a restart:
// NewLowServer removes the gocollect scratch dir before serving.
func TestNewLowServerScrubsStaleGoAuthScratch(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "gocollect", "auth-stale")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "netrc"), []byte("machine gitlab.example.com login bot password s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, priv := newTestKeys(t)
	ls, err := NewLowServer(LowConfig{
		Root:            root,
		ExportDir:       filepath.Join(root, "out"),
		UpstreamGOPROXY: "off",
		GOSUMDB:         "off",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ls.Close() })

	if _, err := os.Stat(filepath.Join(root, "gocollect")); !os.IsNotExist(err) {
		t.Error("stale gocollect scratch should be scrubbed at startup")
	}
	assertNoSecretOnDisk(t, root, "s3cr3t")
}

// assertNoSecretOnDisk walks dir and fails if any file contains secret.
func assertNoSecretOnDisk(t *testing.T, dir, secret string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(b), secret) {
			t.Errorf("secret left on disk in %s", path)
		}
		return nil
	})
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		m[k] = v // last wins, matching child-process semantics
	}
	return m
}
