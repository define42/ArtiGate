//go:build e2e && race

package e2e

import "time"

const (
	raceEnabled = true
	// Full OSV archives contain hundreds of thousands of JSON advisories.
	// Race instrumentation slows their ZIP extraction and parsing enough to
	// exceed the normal three-minute import deadline on an otherwise healthy server.
	importTimeout = 10 * time.Minute
)
