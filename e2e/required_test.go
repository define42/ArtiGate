//go:build e2e

package e2e

import (
	"fmt"
	"testing"
)

type unavailableReporter interface {
	Helper()
	Fatalf(string, ...any)
	Skipf(string, ...any)
}

// requiredUnavailable keeps local runs convenient without letting an upstream
// outage or missing client silently remove a required CI flow from coverage.
func requiredUnavailable(t unavailableReporter, format string, args ...any) {
	t.Helper()
	if requireAll() {
		t.Fatalf(format, args...)
		return
	}
	t.Skipf(format, args...)
}

type unavailableRecorder struct {
	failed  bool
	skipped bool
	message string
}

func (*unavailableRecorder) Helper() {}

func (r *unavailableRecorder) Fatalf(format string, args ...any) {
	r.failed = true
	r.message = fmt.Sprintf(format, args...)
}

func (r *unavailableRecorder) Skipf(format string, args ...any) {
	r.skipped = true
	r.message = fmt.Sprintf(format, args...)
}

func TestRequiredUnavailablePolicy(t *testing.T) {
	for _, mode := range []string{"local", "required"} {
		t.Run(mode, func(t *testing.T) {
			value := "0"
			if mode == "required" {
				value = "1"
			}
			t.Setenv("ARTIGATE_E2E_REQUIRE_ALL", value)
			var recorder unavailableRecorder
			requiredUnavailable(&recorder, "upstream unavailable: HTTP %d", 503)
			if recorder.failed != (mode == "required") || recorder.skipped != (mode == "local") {
				t.Fatalf("mode=%s: failure=%t skip=%t", mode, recorder.failed, recorder.skipped)
			}
			if recorder.message != "upstream unavailable: HTTP 503" {
				t.Fatalf("failure reason lost: %q", recorder.message)
			}
		})
	}
}
