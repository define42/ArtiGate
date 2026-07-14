package main

// Collect dry runs: POST /admin/<stream>/collect?dry_run=1 answers "N
// artifacts, ~X GB, Y new" without exporting anything, so an operator can see
// what a collect would commit to a rate-limited one-way link before pulling
// the trigger. A dry run runs exactly like a real collect — resolution,
// upstream metadata fetches, dedup marking against the exported index, split
// planning — but stops at the export threshold: no bundle is written, no
// sequence number is consumed, nothing is recorded as forwarded, and nothing
// is handed to the diode transport. The flag rides on the context (like the
// progress sinks) so the one choke point every ecosystem already goes through
// — exportIfNew — can answer with an estimate instead of exporting. The
// collectors that know each file's SHA-256 and size from upstream metadata
// (apt, rpm, containers, hf — the gigabyte-scale streams) also skip the
// downloads themselves, making their dry runs metadata-cheap; tool-driven
// ecosystems (go, python, npm, ...) still fetch into their local caches and
// staging, because their sizes are unknowable before the fetch.

import (
	"context"
	"fmt"
	"net/http"
)

// dryRunKey marks a context whose collect must stop short of exporting. The
// unexported empty struct type makes it a collision-free key.
type dryRunKey struct{}

// withDryRunCollect returns a context marked as a dry-run collect.
func withDryRunCollect(ctx context.Context) context.Context {
	return context.WithValue(ctx, dryRunKey{}, true)
}

// isDryRunCollect reports whether this collect is a dry run.
func isDryRunCollect(ctx context.Context) bool {
	on, _ := ctx.Value(dryRunKey{}).(bool)
	return on
}

// wantsDryRunCollect reports whether the client asked for a size estimate
// instead of an export (?dry_run=1 on the collect endpoint).
func wantsDryRunCollect(r *http.Request) bool {
	return r.URL.Query().Get("dry_run") == "1"
}

// skipDownloadForDryRun reports whether a dry-run collect can account for a
// file from upstream metadata alone: a declared SHA-256 and size are all a
// manifest entry — and thus the estimate — needs. Callers consult it after
// their prior-content check, so the skipped file still counts as new content.
func skipDownloadForDryRun(ctx context.Context, sha256 string, size int64) bool {
	return sha256 != "" && size > 0 && isDryRunCollect(ctx)
}

// CollectEstimate is a dry-run collect's size report: what a real collect
// would send across the diode, and what it would skip as already forwarded.
type CollectEstimate struct {
	// TotalFiles/TotalBytes cover every file the collect resolved, new and
	// already-forwarded alike.
	TotalFiles int   `json:"total_files"`
	TotalBytes int64 `json:"total_bytes"`
	// NewFiles/NewBytes cover the files whose content has not been forwarded
	// on this stream yet — what a real collect would pack and send.
	NewFiles int   `json:"new_files"`
	NewBytes int64 `json:"new_bytes"`
	// EstimatedArchiveBytes bounds from above the total size of the signed
	// archive(s) a real collect would stage for the diode, using the same
	// conservative packed-size model that drives bundle splitting.
	EstimatedArchiveBytes int64 `json:"estimated_archive_bytes,omitempty"`
	// Bundles is how many sequenced bundles the new content would ship as.
	Bundles int `json:"bundles,omitempty"`
}

// dryRunExportResult is exportIfNew's dry-run tail. The files arrive resolved
// and dedup-marked exactly as for a real export; instead of allocating a
// sequence and writing bundles, it plans the split and reports what would
// happen. Only the split plan can fail — with the same error a real collect
// would hit, which is precisely what a dry run is for.
func (s *LowServer) dryRunExportResult(ctx context.Context, stream string, files []ManifestFile) (ExportResult, error) {
	est := &CollectEstimate{TotalFiles: len(files)}
	for _, f := range files {
		est.TotalBytes += f.Size
		if !f.Prior {
			est.NewFiles++
			est.NewBytes += f.Size
		}
	}
	res := ExportResult{Stream: stream, DryRun: true, Estimate: est, PriorFiles: est.TotalFiles - est.NewFiles}
	if est.NewFiles == 0 {
		res.Skipped = true
		res.Message = fmt.Sprintf("dry run: all %d file(s) (%s) already forwarded; a collect would skip", est.TotalFiles, formatBytes(est.TotalBytes))
		emitProgress(ctx, "Dry run: nothing new — every resolved file has already been forwarded on this stream.")
		return res, nil
	}
	chunks, err := splitDeliveredFiles(files, s.bundleSplitBudget())
	if err != nil {
		return ExportResult{}, s.decorateSplitError(err)
	}
	est.Bundles = len(chunks)
	est.EstimatedArchiveBytes = estimateArchiveBytes(files, chunks)
	res.Message = dryRunMessage(est)
	emitProgress(ctx, "Dry run: %d file(s) resolved, %s total; %s", est.TotalFiles, formatBytes(est.TotalBytes), res.Message)
	return res, nil
}

// estimateArchiveBytes totals the conservative packed-size model over the
// planned bundles: an upper bound on the archives a real collect would stage.
func estimateArchiveBytes(files []ManifestFile, chunks [][]int) int64 {
	var total int64
	for _, chunk := range chunks {
		total += bundlePackBaseOverheadBytes
		for _, fi := range chunk {
			total += estimatedPackedBytes(files[fi].Size)
		}
	}
	return total
}

// dryRunMessage renders the operator-facing one-line summary of an estimate.
func dryRunMessage(est *CollectEstimate) string {
	msg := fmt.Sprintf("dry run: %d new file(s), %s of new content would cross the diode in %d bundle(s) (≤ %s archived)",
		est.NewFiles, formatBytes(est.NewBytes), est.Bundles, formatBytes(est.EstimatedArchiveBytes))
	if prior := est.TotalFiles - est.NewFiles; prior > 0 {
		msg += fmt.Sprintf("; %d of %d resolved file(s) already forwarded", prior, est.TotalFiles)
	}
	return msg
}
