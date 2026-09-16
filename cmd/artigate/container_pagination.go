package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const containerRegistryPageSize = 1000

type containerPagination struct {
	Limit        int
	Last         string
	ArtifactType string
}

func parseContainerPagination(rawQuery string, referrers bool) (containerPagination, error) {
	page := containerPagination{Limit: containerRegistryPageSize}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return page, fmt.Errorf("invalid pagination query encoding")
	}
	for _, key := range []string{"n", "last", "artifactType"} {
		if len(query[key]) > 1 {
			return page, fmt.Errorf("pagination parameter %s must occur once", key)
		}
	}
	if values, present := query["n"]; present {
		limit, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			return page, fmt.Errorf("pagination n must be a nonnegative integer")
		}
		page.Limit = int(min(limit, containerRegistryPageSize))
	}
	page.Last = query.Get("last")
	validCursor := containerTagRE.MatchString
	if referrers {
		validCursor = containerDigestRE.MatchString
		page.ArtifactType = query.Get("artifactType")
	}
	if page.Last != "" && !validCursor(page.Last) {
		return page, fmt.Errorf("invalid pagination last reference")
	}
	return page, nil
}

// containerRepositoryTags includes every mutable registry reference, including
// legacy cosign tags. Image and artifact references share one tag namespace.
func containerRepositoryTags(repo ContainerRepo) []string {
	seen := make(map[string]bool)
	for _, image := range repo.Images {
		if image.Tag != "" {
			seen[image.Tag] = true
		}
	}
	if repo.artifactIndex != nil {
		for tag, digest := range repo.artifactIndex.Tags {
			if _, exists := repo.artifactIndex.Artifacts[digest]; exists && tag != "" {
				seen[tag] = true
			}
		}
	}
	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return compareContainerTags(tags[i], tags[j]) < 0 })
	return tags
}

// OCI tag ordering is case-insensitive. A bytewise tie-breaker gives distinct
// tags that differ only by case a stable continuation order.
func compareContainerTags(a, b string) int {
	if order := strings.Compare(strings.ToLower(a), strings.ToLower(b)); order != 0 {
		return order
	}
	return strings.Compare(a, b)
}

func paginateContainerTags(tags []string, page containerPagination) ([]string, string) {
	if page.Limit == 0 {
		return []string{}, ""
	}
	start := sort.Search(len(tags), func(i int) bool { return compareContainerTags(tags[i], page.Last) > 0 })
	end := min(start+page.Limit, len(tags))
	last := ""
	if end < len(tags) {
		last = tags[end-1]
	}
	return tags[start:end], last
}

// paginateContainerReferrers measures encoded descriptors before appending
// them, so large annotations cannot make a page exceed the discovery limit.
// A descriptor that cannot fit by itself fails explicitly instead of silently
// dropping metadata or returning an oversized response.
func paginateContainerReferrers(descriptors []ociDescriptor, page containerPagination) ([]byte, string, error) {
	const prefix = `{"schemaVersion":2,"mediaType":"` + mtOCIIndex + `","manifests":[`
	body := []byte(prefix)
	start := sort.Search(len(descriptors), func(i int) bool { return descriptors[i].Digest > page.Last })
	end := min(start+page.Limit, len(descriptors))
	position := start
	for ; position < end; position++ {
		encoded, err := json.Marshal(descriptors[position])
		if err != nil {
			return nil, "", err
		}
		separator := 0
		if position > start {
			separator = 1
		}
		if len(body)+separator+len(encoded)+2 > maxServedManifestBytes {
			if position == start {
				return nil, "", fmt.Errorf("referrer descriptor exceeds the %d-byte response limit", maxServedManifestBytes)
			}
			break
		}
		if separator != 0 {
			body = append(body, ',')
		}
		body = append(body, encoded...)
	}
	body = append(body, ']', '}')
	last := ""
	if page.Limit != 0 && position < len(descriptors) {
		last = descriptors[position-1].Digest
	}
	return body, last, nil
}

func writeContainerPage(w http.ResponseWriter, r *http.Request, page containerPagination, last, mediaType string, body []byte) {
	if last != "" {
		query := url.Values{"n": {strconv.Itoa(page.Limit)}, "last": {last}}
		if page.ArtifactType != "" {
			query.Set("artifactType", page.ArtifactType)
		}
		next := url.URL{Path: r.URL.Path, RawQuery: query.Encode()}
		w.Header().Set("Link", "<"+next.String()+`>; rel="next"`)
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
