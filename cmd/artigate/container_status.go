package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

const (
	containerDiscoveryComplete   = "complete"
	containerDiscoveryIncomplete = "incomplete"
	containerDiscoveryUnknown    = "unknown"
	containerDiscoveryMaxIssues  = 16
)

// ContainerDiscoveryStatus reports collection coverage, never signature trust.
// Issues deliberately contain no upstream strings, URLs, or credentials.
type ContainerDiscoveryStatus struct {
	State         string                    `json:"state"`
	CheckedAt     string                    `json:"checked_at,omitempty"`
	LastSuccessAt string                    `json:"last_success_at,omitempty"`
	Artifacts     int                       `json:"artifacts"`
	Subjects      int                       `json:"subjects"`
	Issues        []ContainerDiscoveryIssue `json:"issues,omitempty"`
	IssuesDropped int                       `json:"issues_dropped,omitempty"`
	// A dry run reports unknown to callers while retaining its projected
	// coverage for the export dedup estimate. It is never serialized.
	estimatedState string
}

type ContainerDiscoveryIssue struct {
	Code    string `json:"code"`
	Subject string `json:"subject,omitempty"`
}

type ContainerDiscoveryRecord struct {
	Registry   string                    `json:"registry"`
	Repository string                    `json:"repository"`
	Digest     string                    `json:"digest"`
	Tags       []string                  `json:"tags"`
	Discovery  *ContainerDiscoveryStatus `json:"discovery"`
	// ReferenceTracking distinguishes observations made before reference
	// provenance was recorded. Pins stay active when tags subsequently move.
	Pinned            bool   `json:"pinned,omitempty"`
	ReferenceTracking bool   `json:"reference_tracking,omitempty"`
	Lifecycle         string `json:"lifecycle,omitempty"`
	Freshness         string `json:"freshness,omitempty"`
	AgeSeconds        *int64 `json:"age_seconds,omitempty"`
}

type containerDiscoverySnapshot struct {
	Version int                                 `json:"version"`
	Records map[string]ContainerDiscoveryRecord `json:"records"`
}

type containerDiscoveryContextKey struct{}

type containerDiscoveryTracker struct {
	status   ContainerDiscoveryStatus
	subjects map[string]bool
}

func withContainerDiscovery(ctx context.Context) (context.Context, *containerDiscoveryTracker) {
	tracker := &containerDiscoveryTracker{status: ContainerDiscoveryStatus{State: containerDiscoveryComplete}, subjects: make(map[string]bool)}
	return context.WithValue(ctx, containerDiscoveryContextKey{}, tracker), tracker
}

func noteContainerDiscoveryIssue(ctx context.Context, code, subject string) {
	tracker, _ := ctx.Value(containerDiscoveryContextKey{}).(*containerDiscoveryTracker)
	if tracker == nil {
		return
	}
	tracker.status.State = containerDiscoveryIncomplete
	if code == "discovery_limit" || !containerDigestRE.MatchString(subject) {
		subject = ""
	}
	issue := ContainerDiscoveryIssue{Code: code, Subject: subject}
	if slices.Contains(tracker.status.Issues, issue) {
		return
	}
	if len(tracker.status.Issues) < containerDiscoveryMaxIssues {
		tracker.status.Issues = append(tracker.status.Issues, issue)
	} else {
		tracker.status.IssuesDropped++
	}
}

func noteContainerDiscoverySubject(ctx context.Context, subject string) {
	tracker, _ := ctx.Value(containerDiscoveryContextKey{}).(*containerDiscoveryTracker)
	if tracker != nil {
		tracker.subjects[subject] = true
	}
}

func (tracker *containerDiscoveryTracker) finish(ctx context.Context, image ContainerImage) *ContainerDiscoveryStatus {
	if ctx.Err() != nil {
		noteContainerDiscoveryIssue(ctx, "cancelled", "")
	}
	status := tracker.status
	status.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	status.Subjects = len(tracker.subjects)
	for _, artifact := range image.Artifacts {
		if artifact.Digest != image.Digest && artifact.Digest != containerImageServedDigest(image) {
			status.Artifacts++
		}
	}
	if isDryRunCollect(ctx) {
		status.estimatedState = status.State
		status.State = containerDiscoveryUnknown
	} else if status.State == containerDiscoveryComplete {
		status.LastSuccessAt = status.CheckedAt
	}
	sort.Slice(status.Issues, func(i, j int) bool {
		if status.Issues[i].Code != status.Issues[j].Code {
			return status.Issues[i].Code < status.Issues[j].Code
		}
		return status.Issues[i].Subject < status.Issues[j].Subject
	})
	return &status
}

type containerArtifactFetchError struct{ cause error }

func (err *containerArtifactFetchError) Error() string { return err.cause.Error() }
func (err *containerArtifactFetchError) Unwrap() error { return err.cause }

type containerArtifactLimitError struct{}

func (*containerArtifactLimitError) Error() string { return "artifact graph exceeds traversal limits" }

func containerArtifactIssueCode(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	var limit *containerArtifactLimitError
	if errors.As(err, &limit) {
		return "discovery_limit"
	}
	var fetch *containerArtifactFetchError
	if errors.As(err, &fetch) {
		return "artifact_fetch"
	}
	return "artifact_invalid"
}

func containerImageDiscovery(image ContainerImage) ContainerDiscoveryStatus {
	if image.Discovery == nil {
		return ContainerDiscoveryStatus{State: containerDiscoveryUnknown}
	}
	return *image.Discovery
}

func validContainerDiscoveryCode(code string) bool {
	switch code {
	case "referrers_api", "referrers_fallback", "legacy_fetch", "artifact_fetch", "artifact_invalid", "discovery_limit", "cancelled":
		return true
	default:
		return false
	}
}

func validateContainerDiscovery(status *ContainerDiscoveryStatus) error {
	if status == nil {
		return nil
	}
	if status.State != containerDiscoveryComplete && status.State != containerDiscoveryIncomplete && status.State != containerDiscoveryUnknown {
		return errors.New("invalid container discovery state")
	}
	if err := validateContainerDiscoveryLimits(status); err != nil {
		return err
	}
	if err := validateContainerDiscoveryTimes(status); err != nil {
		return err
	}
	if status.State == containerDiscoveryComplete && (len(status.Issues) != 0 || status.IssuesDropped != 0 || status.LastSuccessAt == "") {
		return errors.New("inconsistent complete container discovery status")
	}
	for _, issue := range status.Issues {
		if !validContainerDiscoveryCode(issue.Code) || (issue.Subject != "" && !containerDigestRE.MatchString(issue.Subject)) {
			return errors.New("invalid container discovery issue")
		}
	}
	return nil
}

func validateContainerDiscoveryLimits(status *ContainerDiscoveryStatus) error {
	if status.Artifacts < 0 || status.Artifacts > containerMaxImageArtifacts || status.Subjects < 0 || status.Subjects > containerMaxImageArtifacts+2 ||
		len(status.Issues) > containerDiscoveryMaxIssues || status.IssuesDropped < 0 || status.IssuesDropped > 100000 {
		return errors.New("container discovery status exceeds limits")
	}
	return nil
}

func validateContainerDiscoveryTimes(status *ContainerDiscoveryStatus) error {
	if status.CheckedAt == "" && status.State != containerDiscoveryUnknown {
		return errors.New("container discovery status has no check time")
	}
	var checked time.Time
	for i, value := range []string{status.CheckedAt, status.LastSuccessAt} {
		if value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || len(value) > 35 {
			return errors.New("invalid container discovery timestamp")
		}
		if i == 0 {
			checked = parsed
		} else if checked.IsZero() || parsed.After(checked) {
			return errors.New("container discovery success is after check time")
		}
	}
	return nil
}

func (s *LowServer) containerDiscoveryPath() string {
	return filepath.Join(s.cfg.Root, "containers", "discovery.json")
}

func (s *LowServer) loadContainerDiscovery() (containerDiscoverySnapshot, error) {
	snapshot := containerDiscoverySnapshot{Version: 1, Records: make(map[string]ContainerDiscoveryRecord)}
	body, err := os.ReadFile(s.containerDiscoveryPath())
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return snapshot, err
	}
	if snapshot.Version != 1 || snapshot.Records == nil {
		return snapshot, errors.New("invalid container discovery snapshot")
	}
	for key, record := range snapshot.Records {
		if err := validateContainerDiscovery(record.Discovery); err != nil {
			return snapshot, err
		}
		// Lifecycle and freshness are computed for a query, never trusted as
		// durable state from an older writer.
		record.Lifecycle, record.Freshness, record.AgeSeconds = "", "", nil
		snapshot.Records[key] = record
	}
	return snapshot, nil
}

// updateContainerDiscovery runs under the containers stream lock. Readers use
// atomic snapshots and never block on a registry request. Old digest records
// remain available; moving a tag removes only its old tag association.
func (s *LowServer) updateContainerDiscovery(ctx context.Context, repos []ContainerRepo) ([]ContainerDiscoveryRecord, error) {
	snapshot, err := s.loadContainerDiscovery()
	if err != nil {
		return nil, fmt.Errorf("read container discovery status: %w", err)
	}
	var keys []string
	for _, repo := range repos {
		for i := range repo.Images {
			key := updateContainerDiscoveryImage(snapshot.Records, repo.Registry, repo.Repository, &repo.Images[i])
			keys = append(keys, key)
		}
	}
	if !isDryRunCollect(ctx) {
		if err := writeJSONAtomic(s.containerDiscoveryPath(), snapshot, 0o600); err != nil {
			return nil, fmt.Errorf("persist container discovery status: %w", err)
		}
	}
	// A later reference may move a tag off an earlier digest in this batch.
	// Resolve returned records only after every tag association is final.
	records := make([]ContainerDiscoveryRecord, 0, len(keys))
	asOf := time.Now().UTC()
	for _, key := range keys {
		records = append(records, enrichContainerDiscoveryRecord(snapshot.Records[key], asOf, containerDiscoveryDefaultStaleAfter))
	}
	return records, nil
}

func updateContainerDiscoveryImage(records map[string]ContainerDiscoveryRecord, registry, repository string, image *ContainerImage) string {
	key := registry + "/" + repository + "@" + containerImageServedDigest(*image)
	previous := records[key]
	if image.Discovery != nil && image.Discovery.State != containerDiscoveryComplete && previous.Discovery != nil {
		image.Discovery.LastSuccessAt = previous.Discovery.LastSuccessAt
	}
	record := ContainerDiscoveryRecord{
		Registry: registry, Repository: repository, Digest: containerImageServedDigest(*image),
		Tags: slices.Clone(previous.Tags), Discovery: image.Discovery,
		Pinned: previous.Pinned || image.Tag == "", ReferenceTracking: true,
	}
	if record.Tags == nil {
		record.Tags = []string{}
	}
	moveContainerDiscoveryTag(records, &record, image.Tag)
	records[key] = record
	return key
}

func moveContainerDiscoveryTag(records map[string]ContainerDiscoveryRecord, next *ContainerDiscoveryRecord, tag string) {
	if tag == "" {
		return
	}
	for key, record := range records {
		if record.Registry == next.Registry && record.Repository == next.Repository && record.Digest != next.Digest {
			if slices.Contains(record.Tags, tag) {
				record.ReferenceTracking = true
			}
			record.Tags = slices.DeleteFunc(record.Tags, func(old string) bool { return old == tag })
			records[key] = record
		}
	}
	if !slices.Contains(next.Tags, tag) {
		next.Tags = append(next.Tags, tag)
		slices.Sort(next.Tags)
	}
}

func (s *LowServer) containerDiscoveryRecords() ([]ContainerDiscoveryRecord, error) {
	snapshot, err := s.loadContainerDiscovery()
	if err != nil {
		return nil, err
	}
	return sortedContainerDiscoveryRecords(snapshot, time.Now().UTC(), containerDiscoveryDefaultStaleAfter), nil
}
