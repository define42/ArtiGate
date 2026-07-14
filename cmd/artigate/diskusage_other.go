//go:build !linux

package main

// diskUsage is Linux-only (it uses statfs); elsewhere it reports "unsupported"
// so /metrics simply omits the disk-space samples. ArtiGate's production target
// is Linux; this stub keeps `go build`/tests green on other platforms.
func diskUsage(string) (free, total int64, ok bool) {
	return 0, 0, false
}
