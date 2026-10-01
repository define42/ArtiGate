//go:build e2e && !race

package e2e

import "time"

const (
	raceEnabled   = false
	importTimeout = 3 * time.Minute
)
