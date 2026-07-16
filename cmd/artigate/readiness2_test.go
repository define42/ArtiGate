package main

// Tests for the second production-readiness wave: login timing decoy and
// lockout, pip URL/path rejection, and stale UDP temp reaping.

import (
	"path/filepath"
	"testing"
	"time"
)

// --- Login timing decoy ----------------------------------------------------

func TestCredentialDecoyIsWellFormed(t *testing.T) {
	// The decoy must be a valid argon2id hash so an unknown-user check spends the
	// same work as a known one; verifying its own preimage proves it parses and
	// runs rather than being rejected early as malformed.
	if !verifyArgon2("artigate-decoy-not-a-real-credential", decoyArgon2Hash) {
		t.Error("decoy hash must be a well-formed argon2id hash")
	}
	if credentialOK(map[string]string{}, "nobody", "pw") {
		t.Error("unknown user must never authenticate")
	}
}

// --- Login lockout ---------------------------------------------------------

func TestLoginLockout(t *testing.T) {
	am := &authManager{
		users:    map[string]string{"alice": decoyArgon2Hash},
		failures: map[string]loginFailure{},
	}
	now := time.Now()

	// An unknown username is never tracked, so it can never lock (and cannot be
	// used to grow the table).
	for i := 0; i < loginFailureThreshold+2; i++ {
		am.noteLoginResult("bob", false)
	}
	if am.loginLocked("bob", now) {
		t.Error("unknown username must not be lockable")
	}
	if len(am.failures) != 0 {
		t.Errorf("unknown usernames must not be recorded, have %d", len(am.failures))
	}

	// A known account locks only at the threshold.
	for i := 0; i < loginFailureThreshold-1; i++ {
		am.noteLoginResult("alice", false)
	}
	if am.loginLocked("alice", now) {
		t.Fatal("must not lock before the threshold")
	}
	am.noteLoginResult("alice", false) // threshold reached
	if !am.loginLocked("alice", now) {
		t.Fatal("must lock at the threshold")
	}
	// The lock clears once its window elapses.
	if am.loginLocked("alice", now.Add(loginLockoutWindow+time.Second)) {
		t.Error("lock must expire after the window")
	}

	// A success clears accumulated failures.
	am.noteLoginResult("alice", false)
	am.noteLoginResult("alice", true)
	if _, tracked := am.failures["alice"]; tracked {
		t.Error("a successful login must clear the failure record")
	}
}

// --- pip requirement validation --------------------------------------------

func TestValidatePipArgRejectsURLsAndPaths(t *testing.T) {
	good := []struct{ kind, val string }{
		{"requirement", "requests"},
		{"requirement", "requests==2.31.0"},
		{"requirement", "requests>=2,<3"},
		{"requirement", "requests[socks]"},
		{"platform", "manylinux2014_x86_64"},
		{"python-version", "3.11"},
	}
	for _, c := range good {
		if err := validatePipArg(c.kind, c.val); err != nil {
			t.Errorf("%s %q should be valid: %v", c.kind, c.val, err)
		}
	}

	bad := []struct{ kind, val string }{
		{"requirement", "https://evil.example/x-1.0-py3-none-any.whl"},
		{"requirement", "requests @ https://evil.example/x.whl"},
		{"requirement", "./local-wheel.whl"},
		{"requirement", "/abs/path.whl"},
		{"requirement", "a/b"},
		{"platform", "file:///etc/passwd"},
	}
	for _, c := range bad {
		if err := validatePipArg(c.kind, c.val); err == nil {
			t.Errorf("%s %q must be rejected", c.kind, c.val)
		}
	}
}

// --- Stale transport temp reaping -------------------------------------------

func TestReapStaleTransportTemps(t *testing.T) {
	dir := t.TempDir()
	staleTemp := filepath.Join(dir, "go-bundle-000001.tar.gz.udp-abc")
	freshTemp := filepath.Join(dir, "go-bundle-000002.tar.gz.udp-xyz")
	bundle := filepath.Join(dir, "go-bundle-000003.tar.gz")
	staleUpload := filepath.Join(dir, "go-bundle-000004.tar.gz.upload-123")
	freshUpload := filepath.Join(dir, "go-bundle-000005.tar.gz.upload-456")
	writeAged(t, staleTemp, 72*time.Hour)
	writeAged(t, freshTemp, 0)
	writeAged(t, bundle, 72*time.Hour)
	writeAged(t, staleUpload, 72*time.Hour)
	writeAged(t, freshUpload, 0)

	n, err := reapStaleTransportTemps(dir, time.Now().Add(-incompleteLandingRetention))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("reaped %d, want 2", n)
	}
	if fileExists(staleTemp) {
		t.Error("stale UDP temp should be reaped")
	}
	if !fileExists(freshTemp) {
		t.Error("fresh UDP temp must be kept")
	}
	if !fileExists(bundle) {
		t.Error("a normal bundle file must not be touched by the temp reaper")
	}
	// An orphaned HTTP ingest upload temp would otherwise pin the unverified
	// storage quota forever: it counts against the quota but carried no known
	// bundle suffix, so no other reaper matched it.
	if fileExists(staleUpload) {
		t.Error("stale HTTP upload temp should be reaped")
	}
	if !fileExists(freshUpload) {
		t.Error("fresh HTTP upload temp must be kept")
	}
}
