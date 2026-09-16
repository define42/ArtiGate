package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	containerDiscoveryDefaultStaleAfter = 24 * time.Hour
	containerDiscoveryDefaultPageSize   = 100
	containerDiscoveryMaxPageSize       = 250
	containerDiscoveryMaxResponseBytes  = 1 << 20
	containerDiscoveryMaxCursorBytes    = 4096
)

type containerDiscoveryQuery struct {
	Repository string
	State      string
	Lifecycle  string
	Freshness  string
	StaleAfter time.Duration
	Limit      int
	Cursor     string `json:"-"`
}

type containerDiscoveryPage struct {
	Records           []ContainerDiscoveryRecord `json:"records"`
	Total             int                        `json:"total"`
	NextCursor        string                     `json:"next_cursor"`
	AsOf              string                     `json:"as_of"`
	StaleAfterSeconds int64                      `json:"stale_after_seconds"`
}

// Revision fixes the sorted dataset, while Query fixes the selected rows. An
// offset is therefore stable without placing repository names in the cursor.
type containerDiscoveryCursor struct {
	Version  int    `json:"v"`
	Revision string `json:"revision"`
	Query    string `json:"query"`
	Offset   int    `json:"offset"`
	AsOf     string `json:"as_of"`
}

type containerDiscoveryQueryError struct {
	status  int
	message string
}

func (err *containerDiscoveryQueryError) Error() string { return err.message }

func enrichContainerDiscoveryRecord(record ContainerDiscoveryRecord, asOf time.Time, staleAfter time.Duration) ContainerDiscoveryRecord {
	record.Lifecycle = "unknown"
	if len(record.Tags) > 0 || record.Pinned {
		record.Lifecycle = "active"
	} else if record.ReferenceTracking {
		record.Lifecycle = "historical"
	}
	record.Freshness, record.AgeSeconds = "unknown", nil
	if record.Discovery == nil {
		return record
	}
	checked, err := time.Parse(time.RFC3339Nano, record.Discovery.CheckedAt)
	if err != nil || checked.After(asOf) {
		return record
	}
	age := asOf.Unix() - checked.Unix()
	if asOf.Nanosecond() < checked.Nanosecond() {
		age--
	}
	record.AgeSeconds = &age
	record.Freshness = "fresh"
	if !checked.Add(staleAfter).After(asOf) {
		record.Freshness = "stale"
	}
	return record
}

func sortedContainerDiscoveryRecords(snapshot containerDiscoverySnapshot, asOf time.Time, staleAfter time.Duration) []ContainerDiscoveryRecord {
	keys := make([]string, 0, len(snapshot.Records))
	for key := range snapshot.Records {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	records := make([]ContainerDiscoveryRecord, 0, len(keys))
	for _, key := range keys {
		records = append(records, enrichContainerDiscoveryRecord(snapshot.Records[key], asOf, staleAfter))
	}
	return records
}

func parseContainerDiscoveryQuery(raw string) (containerDiscoveryQuery, error) {
	query := containerDiscoveryQuery{Limit: containerDiscoveryDefaultPageSize, StaleAfter: containerDiscoveryDefaultStaleAfter}
	if len(raw) > 8192 {
		return query, errors.New("container discovery query is too large")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return query, errors.New("invalid container discovery query")
	}
	for key, value := range values {
		if len(value) != 1 {
			return query, errors.New("duplicate container discovery query parameter")
		}
		if err := setContainerDiscoveryQuery(&query, key, value[0]); err != nil {
			return query, err
		}
	}
	return query, nil
}

func setContainerDiscoveryQuery(query *containerDiscoveryQuery, key, value string) error {
	switch key {
	case "repository":
		query.Repository = value
		return validateContainerDiscoveryRepository(value)
	case "state":
		return setContainerDiscoveryFilter(&query.State, value, "complete", "incomplete", "unknown")
	case "lifecycle":
		return setContainerDiscoveryFilter(&query.Lifecycle, value, "active", "historical", "unknown")
	case "freshness":
		return setContainerDiscoveryFilter(&query.Freshness, value, "fresh", "stale", "unknown")
	case "limit":
		limit, err := parseContainerDiscoveryLimit(value)
		query.Limit = limit
		return err
	case "stale_after":
		duration, err := parseContainerDiscoveryStaleAfter(value)
		query.StaleAfter = duration
		return err
	case "cursor":
		if len(value) > containerDiscoveryMaxCursorBytes {
			return errors.New("container discovery cursor is too large")
		}
		query.Cursor = value
	default:
		return errors.New("unknown container discovery query parameter")
	}
	return nil
}

func validateContainerDiscoveryRepository(value string) error {
	if value == "" {
		return nil
	}
	registry, repository, _ := strings.Cut(value, "/")
	if len(value) > 1024 || !containerRegistryRE.MatchString(registry) || validateContainerRepository(repository) != nil {
		return errors.New("invalid repository filter; use registry/repository")
	}
	return nil
}

func parseContainerDiscoveryLimit(value string) (int, error) {
	limit, err := strconv.ParseUint(value, 10, 16)
	if err != nil || limit < 1 || limit > containerDiscoveryMaxPageSize {
		return 0, errors.New("invalid container discovery page limit; use 1..250")
	}
	return int(limit), nil
}

func parseContainerDiscoveryStaleAfter(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < time.Second || duration > 365*24*time.Hour || duration%time.Second != 0 {
		return 0, errors.New("invalid stale_after; use a whole-second duration from 1s to 8760h")
	}
	return duration, nil
}

func setContainerDiscoveryFilter(target *string, value string, allowed ...string) error {
	if value == "" || value == "all" {
		*target = ""
		return nil
	}
	if !slices.Contains(allowed, value) {
		return errors.New("invalid container discovery filter")
	}
	*target = value
	return nil
}

func containerDiscoveryQueryMatches(query containerDiscoveryQuery, record ContainerDiscoveryRecord) bool {
	state := containerDiscoveryUnknown
	if record.Discovery != nil {
		state = record.Discovery.State
	}
	return (query.Repository == "" || query.Repository == record.Registry+"/"+record.Repository) &&
		(query.State == "" || query.State == state) &&
		(query.Lifecycle == "" || query.Lifecycle == record.Lifecycle) &&
		(query.Freshness == "" || query.Freshness == record.Freshness)
}

func containerDiscoveryFingerprint(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func newContainerDiscoveryCursor(snapshot containerDiscoverySnapshot, query containerDiscoveryQuery, asOf time.Time) (containerDiscoveryCursor, error) {
	cursor := containerDiscoveryCursor{Version: 1, AsOf: asOf.UTC().Format(time.RFC3339Nano)}
	var err error
	cursor.Revision, err = containerDiscoveryFingerprint(snapshot)
	if err != nil {
		return cursor, err
	}
	cursor.Query, err = containerDiscoveryFingerprint(query)
	return cursor, err
}

func decodeContainerDiscoveryCursor(encoded string, expected containerDiscoveryCursor) (containerDiscoveryCursor, error) {
	var cursor containerDiscoveryCursor
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(encoded) > containerDiscoveryMaxCursorBytes {
		return cursor, errors.New("invalid container discovery cursor")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return cursor, errors.New("invalid container discovery cursor")
	}
	_, err = time.Parse(time.RFC3339Nano, cursor.AsOf)
	if err != nil || len(cursor.AsOf) > 35 || cursor.Version != 1 || cursor.Offset < 1 || cursor.Query != expected.Query {
		return cursor, errors.New("container discovery cursor does not match query")
	}
	if digest, err := hex.DecodeString(cursor.Revision); err != nil || len(digest) != sha256.Size {
		return cursor, errors.New("invalid container discovery cursor revision")
	}
	if cursor.Revision != expected.Revision {
		return cursor, &containerDiscoveryQueryError{status: http.StatusConflict, message: "container discovery snapshot changed; restart pagination"}
	}
	return cursor, nil
}

func encodeContainerDiscoveryCursor(cursor containerDiscoveryCursor) string {
	body, _ := json.Marshal(cursor) // This fixed scalar struct is always encodable.
	return base64.RawURLEncoding.EncodeToString(body)
}

func queryContainerDiscovery(snapshot containerDiscoverySnapshot, query containerDiscoveryQuery, now time.Time) ([]byte, error) {
	cursor, err := newContainerDiscoveryCursor(snapshot, query, now)
	if err != nil {
		return nil, err
	}
	if query.Cursor != "" {
		cursor, err = decodeContainerDiscoveryCursor(query.Cursor, cursor)
		if err != nil {
			return nil, err
		}
	}
	asOf, _ := time.Parse(time.RFC3339Nano, cursor.AsOf)
	records := sortedContainerDiscoveryRecords(snapshot, asOf, query.StaleAfter)
	records = slices.DeleteFunc(records, func(record ContainerDiscoveryRecord) bool { return !containerDiscoveryQueryMatches(query, record) })
	if cursor.Offset > len(records) {
		return nil, errors.New("invalid container discovery cursor offset")
	}
	return encodeContainerDiscoveryPage(records, query, cursor)
}

func encodeContainerDiscoveryPage(records []ContainerDiscoveryRecord, query containerDiscoveryQuery, cursor containerDiscoveryCursor) ([]byte, error) {
	page := containerDiscoveryPage{
		Records: make([]ContainerDiscoveryRecord, 0), Total: len(records),
		AsOf: cursor.AsOf, StaleAfterSeconds: int64(query.StaleAfter / time.Second),
	}
	// Reserve enough space for all fixed metadata and a bounded cursor. Measure
	// encoded rows, since tag aliases can make a single record much larger.
	remaining := containerDiscoveryMaxResponseBytes - containerDiscoveryMaxCursorBytes
	end := min(len(records), cursor.Offset+query.Limit)
	for _, record := range records[cursor.Offset:end] {
		body, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if len(body)+1 > remaining {
			break
		}
		remaining -= len(body) + 1
		page.Records = append(page.Records, record)
	}
	if len(page.Records) == 0 && cursor.Offset < len(records) {
		return nil, &containerDiscoveryQueryError{status: http.StatusInternalServerError, message: "container discovery record exceeds response limit"}
	}
	cursor.Offset += len(page.Records)
	if cursor.Offset < len(records) {
		page.NextCursor = encodeContainerDiscoveryCursor(cursor)
	}
	return json.Marshal(page)
}

func (s *LowServer) handleContainerDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query, err := parseContainerDiscoveryQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	snapshot, err := s.loadContainerDiscovery()
	if err != nil {
		http.Error(w, "container discovery status unavailable", http.StatusInternalServerError)
		return
	}
	body, err := queryContainerDiscovery(snapshot, query, time.Now().UTC())
	if err != nil {
		status := http.StatusBadRequest
		var queryErr *containerDiscoveryQueryError
		if errors.As(err, &queryErr) {
			status = queryErr.status
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
