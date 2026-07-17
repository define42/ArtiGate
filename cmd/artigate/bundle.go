package main

// The bundle wire format shared by both sides: the signed manifest and its
// entry types, the per-ecosystem stream names, bundle id naming and filename
// parsing ("go-bundle-000042"), discovery and movement of a bundle's artifact
// files on disk, and the operator-facing sequence-range syntax ("42,45-47")
// used by missing-bundle reports and re-export requests.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	manifestType  = "go-module-bundle"
	completeExt   = ".complete"
	stateFileMode = 0o600
)

// manifestFormatCurrent is the bundle wire-format version this binary stamps
// into every manifest it exports ("format") and the newest it can import. The
// high side refuses newer formats with an explicit upgrade error instead of
// letting json.Unmarshal silently drop fields it does not know, and manifests
// without the field (format 0, written before it existed) stay importable.
// Bump it only when a manifest change would make an older high side import a
// bundle incorrectly; purely informational additions need no bump, and a
// brand-new ecosystem section needs none either — old high sides already
// reject its unknown stream by name.
//
// One invariant every future format must keep: the manifest stays a JSON
// object whose top-level "format" member is this plain JSON number. Old high
// sides probe exactly that member from the signed bytes before decoding
// anything else (checkManifestWireFormat), so it is the one part of the wire
// format that can never change shape.
const manifestFormatCurrent = 1

// Bundle streams. Each ecosystem is its own independently-sequenced stream, so a
// lost or out-of-order bundle in one stream never blocks the others. The "go"
// stream keeps the pre-multi-stream numbering for backward compatibility.
const (
	streamGo         = "go"
	streamPython     = "python"
	streamMaven      = "maven"
	streamApt        = "apt"
	streamRpm        = "rpm"
	streamContainers = "containers"
	streamNpm        = "npm"
	streamHF         = "hf"
	streamCrates     = "crates"
	streamTerraform  = "terraform"
	streamHelm       = "helm"
	streamNuget      = "nuget"
	streamApk        = "apk"
	streamConda      = "conda"
	streamRubyGems   = "rubygems"
	streamComposer   = "composer"
	streamVSX        = "vsx"
	streamGalaxy     = "galaxy"
	streamCRAN       = "cran"
	streamSnap       = "snap"
	streamGit        = "git"
	streamOsv        = "osv"
	streamUploads    = "uploads"
)

// knownStreams is the set of built-in ecosystem streams in registry order,
// shown in the low-side status even before anything has been exported.
func knownStreams() []string {
	ecos := ecosystems()
	streams := make([]string, 0, len(ecos))
	for _, e := range ecos {
		streams = append(streams, e.stream)
	}
	return streams
}

const manifestSignaturePHPrefix = "ed25519ph:"

type BundleManifest struct {
	Type string `json:"type"`
	// Format is the bundle wire-format version (manifestFormatCurrent at
	// export time; 0 in manifests written before the field existed). The
	// high side checks it before anything else and refuses formats newer
	// than it understands.
	Format           int       `json:"format,omitempty"`
	Stream           string    `json:"stream,omitempty"`
	Sequence         int64     `json:"sequence"`
	PreviousSequence int64     `json:"previous_sequence"`
	Created          time.Time `json:"created"`
	Generator        string    `json:"generator"`
	// GeneratorVersion records the producing binary's version so operators
	// can tell which low-side release built a bundle; it is informational
	// and never checked.
	GeneratorVersion string             `json:"generator_version,omitempty"`
	BundleID         string             `json:"bundle_id"`
	Ecosystems       []string           `json:"ecosystems,omitempty"`
	Modules          []ManifestMod      `json:"modules,omitempty"`
	Python           *PythonManifest    `json:"python,omitempty"`
	Maven            *MavenManifest     `json:"maven,omitempty"`
	Apt              *AptManifest       `json:"apt,omitempty"`
	Rpm              *RpmManifest       `json:"rpm,omitempty"`
	Containers       *ContainerManifest `json:"containers,omitempty"`
	Npm              *NpmManifest       `json:"npm,omitempty"`
	HuggingFace      *HFManifest        `json:"huggingface,omitempty"`
	Crates           *CratesManifest    `json:"crates,omitempty"`
	Terraform        *TerraformManifest `json:"terraform,omitempty"`
	Helm             *HelmManifest      `json:"helm,omitempty"`
	Nuget            *NugetManifest     `json:"nuget,omitempty"`
	Apk              *ApkManifest       `json:"apk,omitempty"`
	Conda            *CondaManifest     `json:"conda,omitempty"`
	RubyGems         *RubyGemsManifest  `json:"rubygems,omitempty"`
	Composer         *ComposerManifest  `json:"composer,omitempty"`
	VSX              *VSXManifest       `json:"vsx,omitempty"`
	Galaxy           *GalaxyManifest    `json:"galaxy,omitempty"`
	CRAN             *CRANManifest      `json:"cran,omitempty"`
	Snap             *SnapManifest      `json:"snap,omitempty"`
	Git              *GitManifest       `json:"git,omitempty"`
	Osv              *OsvManifest       `json:"osv,omitempty"`
	Uploads          *UploadsManifest   `json:"uploads,omitempty"`
	Part             *BundlePartInfo    `json:"part,omitempty"`
	Files            []ManifestFile     `json:"files"`
}

// BundlePartInfo marks a bundle that carries one slice of a collect whose
// content exceeds the single-archive transport limit (diodeMaxArchiveBytes).
// Content parts deliver files only; the split's final bundle carries the
// ecosystem metadata and lists every earlier part's files as prior, so by the
// time it imports — imports are strictly sequential per stream — all the
// content it references is already in the repository, and clients see the new
// content exactly once, complete.
type BundlePartInfo struct {
	// Index is this bundle's 1-based position among the collect's bundles.
	Index int `json:"index"`
	// Count is how many bundles the collect produced in total.
	Count int `json:"count"`
}

type ManifestMod struct {
	Module  string                  `json:"module"`
	Version string                  `json:"version"`
	Files   map[string]ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Prior marks a file whose content an earlier bundle on this stream
	// already delivered: it is listed (so module/repo references stay
	// complete) but not packed into this bundle's archive. The high side
	// verifies it against the accumulated repository instead of extracting it.
	Prior bool `json:"prior,omitempty"`
}

type ModuleInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// marshalManifest renders the canonical manifest JSON that gets signed,
// stamping the bundle wire-format version and the producing binary's version
// first. Every bundle producer marshals through here (m is a copy, so the
// caller's value is untouched), which is what guarantees no exported bundle
// can miss the stamp.
func marshalManifest(m BundleManifest) ([]byte, error) {
	m.Format = manifestFormatCurrent
	m.GeneratorVersion = versionString()
	return json.MarshalIndent(m, "", "  ")
}

// SequenceRange is inclusive. It is used for operator-facing missing bundle
// reports and low-side re-export requests such as "42,45-47".
type SequenceRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

func (r SequenceRange) String() string {
	if r.Start == r.End {
		return strconv.FormatInt(r.Start, 10)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

// bundleManifestNameRE captures the stream name and sequence from a manifest
// filename like "go-bundle-000042.manifest.json" or "apt-bundle-000001...". The
// digits match six-or-more so numbering stays zero-padded to six for
// readability without capping at 999999 (%06d is a minimum width).
var bundleManifestNameRE = regexp.MustCompile(`^([a-z0-9]+)-bundle-([0-9]{6,})\.manifest\.json$`)

// bundleIDFor renders the on-disk id for a stream's sequence, e.g.
// "go-bundle-000042" or "apt-bundle-000001". Each ecosystem has its own stream,
// so a lost or stalled bundle in one stream never blocks the others.
func bundleIDFor(stream string, seq int64) string {
	return fmt.Sprintf("%s-bundle-%06d", stream, seq)
}

// parseBundleName extracts the stream and sequence from a manifest filename.
func parseBundleName(name string) (stream string, seq int64, ok bool) {
	m := bundleManifestNameRE.FindStringSubmatch(name)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return m[1], n, true
}

// bundleIDForSequence is a convenience for the "go" stream (its ids match the
// pre-multi-stream scheme, easing migration).
func bundleIDForSequence(seq int64) string { return bundleIDFor(streamGo, seq) }

func bundleCompleteInDir(dir, bundleID string) bool {
	for _, suffix := range []string{".tar.gz", ".manifest.json", ".manifest.json.sig"} {
		if !fileExists(filepath.Join(dir, bundleID+suffix)) {
			return false
		}
	}
	return true
}

func bundleArtifactsExistInDir(dir, bundleID string) bool {
	for _, suffix := range bundleSuffixes() {
		if fileExists(filepath.Join(dir, bundleID+suffix)) {
			return true
		}
	}
	return false
}

// bundleSizeInDir returns the total size in bytes of the bundle's files present
// in dir (archive + manifest + signature); missing files simply contribute 0.
func bundleSizeInDir(dir, bundleID string) int64 {
	var total int64
	for _, suffix := range bundleSuffixes() {
		if fi, err := os.Stat(filepath.Join(dir, bundleID+suffix)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// findBundleStreams groups the manifest files in dir by stream, returning each
// stream's sorted sequence numbers.
func findBundleStreams(dir string) (map[string][]int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]int64{}, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]map[int64]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if stream, seq, ok := parseBundleName(e.Name()); ok {
			if seen[stream] == nil {
				seen[stream] = map[int64]bool{}
			}
			seen[stream][seq] = true
		}
	}
	out := make(map[string][]int64, len(seen))
	for stream, set := range seen {
		seqs := make([]int64, 0, len(set))
		for seq := range set {
			seqs = append(seqs, seq)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		out[stream] = seqs
	}
	return out, nil
}

func filterCompleteSequences(dir, stream string, seqs []int64) []int64 {
	out := make([]int64, 0, len(seqs))
	for _, seq := range seqs {
		if bundleCompleteInDir(dir, bundleIDFor(stream, seq)) {
			out = append(out, seq)
		}
	}
	return out
}

func moveBundleFiles(srcDir, dstDir, bundleID string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, suffix := range bundleSuffixes() {
		src := filepath.Join(srcDir, bundleID+suffix)
		if !fileExists(src) {
			continue
		}
		if err := moveFile(src, filepath.Join(dstDir, bundleID+suffix), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// moveFile moves src to dst. It uses rename when possible, and falls back to
// copy+remove when they are on different filesystems. That happens in
// containerized deployments where the landing directory and the repository root
// are separate mounts/volumes, in which case rename returns EXDEV
// ("invalid cross-device link").
func moveFile(src, dst string, mode os.FileMode) error {
	_ = os.Remove(dst)
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyFileAtomic(src, dst, mode); err != nil {
		return err
	}
	return os.Remove(src)
}

func moveImportedFilesFromDir(srcDir, importedDir, bundleID string) error {
	return moveBundleFiles(srcDir, importedDir, bundleID)
}

func parseSequenceSpec(spec string) ([]SequenceRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("empty sequence range")
	}
	var ranges []SequenceRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r, err := parseSequenceRangePart(part)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	if len(ranges) == 0 {
		return nil, errors.New("empty sequence range")
	}
	return mergeSequenceRanges(ranges), nil
}

// parseSequenceRangePart parses a single "N" or "N-M" token into an inclusive,
// positive, non-descending range.
func parseSequenceRangePart(part string) (SequenceRange, error) {
	r, err := parseRangeBounds(part)
	if err != nil {
		return SequenceRange{}, err
	}
	if r.Start <= 0 || r.End <= 0 || r.End < r.Start {
		return SequenceRange{}, fmt.Errorf("invalid sequence range %q", part)
	}
	return r, nil
}

func parseRangeBounds(part string) (SequenceRange, error) {
	if !strings.Contains(part, "-") {
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return SequenceRange{}, fmt.Errorf("invalid sequence %q", part)
		}
		return SequenceRange{Start: n, End: n}, nil
	}
	parts := strings.SplitN(part, "-", 2)
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return SequenceRange{}, fmt.Errorf("invalid range start %q", parts[0])
	}
	end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return SequenceRange{}, fmt.Errorf("invalid range end %q", parts[1])
	}
	return SequenceRange{Start: start, End: end}, nil
}

func mergeSequenceRanges(in []SequenceRange) []SequenceRange {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start == in[j].Start {
			return in[i].End < in[j].End
		}
		return in[i].Start < in[j].Start
	})
	out := []SequenceRange{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End+1 {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func expandSequenceRanges(ranges []SequenceRange, limit int) []int64 {
	var out []int64
	for _, r := range ranges {
		for n := r.Start; n <= r.End; n++ {
			if limit > 0 && len(out) >= limit {
				return out
			}
			out = append(out, n)
		}
	}
	return out
}

func rangesToStrings(ranges []SequenceRange) []string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, r.String())
	}
	return out
}

func missingRanges(start, end int64, present map[int64]bool) []SequenceRange {
	if end < start {
		return nil
	}
	seen := make([]int64, 0, len(present))
	for seq, ok := range present {
		if ok && seq >= start && seq <= end {
			seen = append(seen, seq)
		}
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })

	var out []SequenceRange
	cursor := start
	for _, seq := range seen {
		if seq < cursor {
			continue
		}
		if seq > cursor {
			out = append(out, SequenceRange{Start: cursor, End: seq - 1})
		}
		if seq == math.MaxInt64 {
			return out
		}
		cursor = seq + 1
	}
	if cursor <= end {
		out = append(out, SequenceRange{Start: cursor, End: end})
	}
	return out
}
