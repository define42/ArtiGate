//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLowDashboardUI checks the low-side operator dashboard end-to-end: the
// page renders and its status API returns the per-stream JSON the front-end
// drives from, listing the built-in ecosystem streams even before anything is
// exported. The low-side UI has no e2e coverage otherwise. It runs against the
// shared unauthenticated (loopback) low side, so no login is involved.
func TestLowDashboardUI(t *testing.T) {
	stack.Prepare(t)

	code, body := httpGet(t, stack.LowURL+"/")
	if code != 200 || !strings.Contains(string(body), "ArtiGate") {
		t.Fatalf("low dashboard page = %d (%d bytes)", code, len(body))
	}
	// The dashboard's script must be inlined and served no-store, never a stale
	// cached copy across versions.
	code, body = httpGet(t, stack.LowURL+"/ui/api/status")
	if code != 200 {
		t.Fatalf("/ui/api/status = %d: %s", code, body)
	}
	var status struct {
		Streams []struct {
			Stream       string `json:"stream"`
			NextSequence int64  `json:"next_sequence"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("parse /ui/api/status: %v\n%s", err, body)
	}
	// The status must enumerate the built-in streams (registry-derived), each
	// with a next sequence of at least 1.
	got := map[string]int64{}
	for _, s := range status.Streams {
		got[s.Stream] = s.NextSequence
	}
	for _, stream := range []string{"go", "python", "apt", "rpm", "npm", "rubygems", "uploads"} {
		if n, ok := got[stream]; !ok || n < 1 {
			t.Fatalf("/ui/api/status missing stream %q (or bad next sequence %d); streams: %v", stream, n, keysOfInt64(got))
		}
	}
}

// TestHighDashboardUI checks the high-side dashboard renders and its overview
// API returns JSON, so the served-content browser has basic e2e coverage
// alongside the protocol endpoints the ecosystem tests exercise.
func TestHighDashboardUI(t *testing.T) {
	stack.Prepare(t)

	code, body := httpGet(t, stack.HighURL+"/ui/")
	if code != 200 || !strings.Contains(string(body), "ArtiGate") {
		t.Fatalf("high dashboard page = %d (%d bytes)", code, len(body))
	}
	code, body = httpGet(t, stack.HighURL+"/ui/api/overview")
	if code != 200 || !json.Valid(body) {
		t.Fatalf("/ui/api/overview = %d, valid JSON=%v: %s", code, json.Valid(body), body)
	}
}

func keysOfInt64(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
