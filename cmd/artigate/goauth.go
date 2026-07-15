package main

// Per-collect credential injection for the Go stream. Unlike the URL-fetching
// streams, Go module fetching is delegated to the go toolchain and the git
// processes it spawns, so a login cannot ride an Authorization header set by
// ArtiGate. Instead a credentialed collect gets a private environment: a 0600
// netrc file for the toolchain's own HTTPS requests (NETRC/GOAUTH) and one
// host-scoped inline git credential helper per login (GIT_CONFIG_* entries,
// git >= 2.31), plus GOPRIVATE/GONOSUMDB/GONOPROXY augmented with the
// credentialed hosts so they skip the public proxy and checksum database
// without extra flags. The environment exists only for the collect and is
// removed when it ends.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// goAuthKey carries a credentialed collect's subprocess environment on the
// context, so the single goEnv chokepoint picks it up without threading new
// parameters through the resolution helpers.
type goAuthKey struct{}

// goAuthState is the per-collect credential environment: extra env entries
// for the go/git subprocesses, and the host patterns merged into
// GOPRIVATE/GONOSUMDB/GONOPROXY and the sumdb capture's skip patterns.
type goAuthState struct {
	env          []string
	hostPatterns []string
}

func withGoAuth(ctx context.Context, st *goAuthState) context.Context {
	return context.WithValue(ctx, goAuthKey{}, st)
}

// goAuthHostPatterns returns the collect's credentialed-host patterns, nil
// outside a credentialed collect.
func goAuthHostPatterns(ctx context.Context) []string {
	if st, ok := ctx.Value(goAuthKey{}).(*goAuthState); ok {
		return st.hostPatterns
	}
	return nil
}

// goAuthEnvEntries returns the collect's extra subprocess env, nil outside a
// credentialed collect.
func goAuthEnvEntries(ctx context.Context) []string {
	if st, ok := ctx.Value(goAuthKey{}).(*goAuthState); ok {
		return st.env
	}
	return nil
}

// goCollectCredentials resolves the collect's per-host logins: standing
// ARTIGATE_UPSTREAM_AUTH entries overlaid with the request's own auth (the
// request wins for its host). Unlike the mirror streams a Go collect has no
// upstream URL — the module graph spans the public proxy and any private VCS
// hosts — so the request login's host comes from auth.host, or is inferred
// when every requested module names the same host.
func goCollectCredentials(req GoCollectRequest) (map[string]registryCredential, error) {
	creds, err := parseUpstreamAuthEnv(os.Getenv(upstreamAuthEnv))
	if err != nil {
		return nil, err
	}
	if req.Auth == nil {
		return creds, nil
	}
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return nil, errors.New("auth needs both username and password")
	}
	host, err := goRequestAuthHost(req)
	if err != nil {
		return nil, err
	}
	creds[host] = registryCredential{Username: req.Auth.Username, Password: req.Auth.Password}
	return creds, nil
}

// goRequestAuthHost decides which host the request login is for: the named
// auth.host (authoritative — a module graph legitimately reaches hosts beyond
// the request list, so there is nothing to typo-guard against), or the single
// host every requested module names. A go.mod collect always needs auth.host —
// there is no module list to infer from.
func goRequestAuthHost(req GoCollectRequest) (string, error) {
	if req.Auth.Host != "" {
		return normalizeUpstreamHost(req.Auth.Host), nil
	}
	hosts := map[string]bool{}
	for _, spec := range req.Modules {
		mod, _, _ := strings.Cut(strings.TrimSpace(spec), "@")
		first, _, _ := strings.Cut(mod, "/")
		if strings.Contains(first, ".") {
			hosts[normalizeUpstreamHost(first)] = true
		}
	}
	if len(hosts) == 1 {
		for h := range hosts {
			return h, nil
		}
	}
	return "", errors.New("a Go module login needs auth.host — the module graph can span several hosts, so name the one the login is for")
}

// buildGoAuthEnv materializes the credential environment for one collect: a
// private 0600 netrc under <root>/gocollect for the toolchain's own HTTPS
// requests, one host-scoped inline git credential helper per login (the
// secrets ride their own env vars, immune to shell quoting), and the host
// patterns for GOPRIVATE and friends. The cleanup removes the netrc; call it
// when the collect ends. No credentials yield a nil state and no-op cleanup.
func buildGoAuthEnv(root string, creds map[string]registryCredential) (*goAuthState, func(), error) {
	if len(creds) == 0 {
		return nil, func() {}, nil
	}
	hosts := make([]string, 0, len(creds))
	for h := range creds {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if err := checkNetrcSafe(creds, hosts); err != nil {
		return nil, func() {}, err
	}

	base := filepath.Join(root, "gocollect")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, func() {}, err
	}
	dir, err := os.MkdirTemp(base, "auth-")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	st := &goAuthState{}
	var netrc strings.Builder
	for i, host := range hosts {
		cred := creds[host]
		fmt.Fprintf(&netrc, "machine %s login %s password %s\n", host, cred.Username, cred.Password)
		st.env = append(st.env, gitCredentialHelperEnv(i, host, cred)...)
		if !strings.Contains(host, ":") {
			// Module paths never carry a port, so only port-less hosts can be
			// GOPRIVATE patterns.
			st.hostPatterns = append(st.hostPatterns, host)
		}
	}
	netrcPath := filepath.Join(dir, "netrc")
	if err := os.WriteFile(netrcPath, []byte(netrc.String()), 0o600); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	// GOAUTH=netrc is set explicitly so an inherited GOAUTH cannot disable the
	// injected file; older toolchains ignore GOAUTH and still honor NETRC.
	st.env = append(st.env,
		"NETRC="+netrcPath,
		"GOAUTH=netrc",
		fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(hosts)),
	)
	return st, cleanup, nil
}

// gitCredentialHelperEnv renders one host's inline git credential helper as
// GIT_CONFIG_* command-line configuration (read by git >= 2.31). The login
// itself rides two dedicated env vars the snippet expands at run time, so no
// shell quoting can mangle or leak it; the helper answers only "get".
func gitCredentialHelperEnv(i int, host string, cred registryCredential) []string {
	return []string{
		fmt.Sprintf("GIT_CONFIG_KEY_%d=credential.https://%s.helper", i, host),
		fmt.Sprintf(`GIT_CONFIG_VALUE_%d=!f() { if [ "$1" = get ]; then printf 'username=%%s\npassword=%%s\n' "$ARTIGATE_GO_CRED_%d_USER" "$ARTIGATE_GO_CRED_%d_PASS"; fi; }; f`, i, i, i),
		fmt.Sprintf("ARTIGATE_GO_CRED_%d_USER=%s", i, cred.Username),
		fmt.Sprintf("ARTIGATE_GO_CRED_%d_PASS=%s", i, cred.Password),
	}
}

// checkNetrcSafe rejects logins the netrc token format cannot express —
// whitespace would split them into other fields. The error names only the
// host, never the login.
func checkNetrcSafe(creds map[string]registryCredential, hosts []string) error {
	for _, host := range hosts {
		cred := creds[host]
		if strings.ContainsAny(cred.Username+cred.Password, " \t\r\n") {
			return fmt.Errorf("the login for %s contains whitespace, which the go toolchain's netrc format cannot express", host)
		}
	}
	return nil
}

// mergePatterns joins a configured comma-separated pattern list with the
// collect's credentialed hosts.
func mergePatterns(configured string, hosts []string) string {
	parts := make([]string, 0, len(hosts)+1)
	if configured != "" {
		parts = append(parts, configured)
	}
	parts = append(parts, hosts...)
	return strings.Join(parts, ",")
}
