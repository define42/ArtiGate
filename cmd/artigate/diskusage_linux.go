//go:build linux

package main

import "syscall"

// diskUsage reports the free and total bytes of the filesystem backing path,
// used by /metrics to surface how much headroom the low-side export spool and
// the high-side landing/repository have left. ok is false when the path cannot
// be stat'd (it does not exist yet, or the platform does not support it), in
// which case the caller omits the sample rather than reporting a misleading
// zero.
func diskUsage(path string) (free, total int64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		return 0, 0, false
	}
	// Bavail/Blocks are unsigned; guard the narrowing so an implausible value
	// cannot wrap to a negative gauge.
	free = clampUint64ToInt64(st.Bavail) * bsize
	total = clampUint64ToInt64(st.Blocks) * bsize
	return free, total, true
}

// clampUint64ToInt64 narrows a uint64 to int64, saturating at the max rather
// than wrapping to a negative number.
func clampUint64ToInt64(v uint64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if v > uint64(maxInt64) {
		return maxInt64
	}
	return int64(v)
}
