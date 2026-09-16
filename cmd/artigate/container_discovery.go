package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	containerMaxReferrerPages       = 100
	containerMaxReferrerDescriptors = 4096
	containerReferrerAttempts       = 3
	containerReferrerMaxRetryDelay  = 2 * time.Second
)

// fetchReferrers preserves any successfully discovered pages when discovery is
// incomplete. Only an initial API 404 selects the OCI fallback tag; an outage
// or authorization failure must not be mistaken for an unsupported API.
func (c *containerClient) fetchReferrers(ctx context.Context, ref imageRef, subject string) []ociDescriptor {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	descs, supported, err := c.fetchReferrersAPI(ctx, ref, subject)
	if !supported && err == nil {
		descs, err = c.fetchReferrersFallbackTag(ctx, ref, subject)
	}
	if err != nil {
		emitProgress(ctx, "    ⚠ referrers for %s: discovery incomplete (%d found): %v", shortDigest(subject), len(descs), err)
		log.Printf("containers: %s referrers for %s: discovery incomplete (%d found): %v", ref, subject, len(descs), err)
	}
	return descs
}

func (c *containerClient) fetchReferrersAPI(ctx context.Context, ref imageRef, subject string) ([]ociDescriptor, bool, error) {
	endpoint, err := url.Parse(c.ls.containerAPIBase(ref.Registry) + "/v2/" + ref.Repository + "/referrers/" + subject)
	if err != nil {
		return nil, true, fmt.Errorf("invalid registry discovery endpoint")
	}
	next := endpoint
	visited := make(map[string]bool)
	pages := containerReferrerPages{seen: make(map[string]bool)}
	for page := 0; page < containerMaxReferrerPages; page++ {
		key := next.String()
		if visited[key] {
			return pages.descriptors, true, fmt.Errorf("referrers pagination loop")
		}
		visited[key] = true
		descs, links, supported, err := c.fetchContainerReferrerPage(ctx, ref, subject, next, page == 0)
		if err != nil {
			return pages.descriptors, true, fmt.Errorf("referrers page %d: %w", page+1, err)
		}
		if !supported {
			return nil, false, nil
		}
		next, err = nextContainerReferrerPage(endpoint, next, links)
		if appendErr := pages.append(descs, next != nil); appendErr != nil {
			return pages.descriptors, true, appendErr
		}
		if err != nil {
			return pages.descriptors, true, err
		}
		if next == nil {
			return pages.descriptors, true, nil
		}
	}
	return pages.descriptors, true, fmt.Errorf("referrers exceed %d pages", containerMaxReferrerPages)
}

type containerReferrerPages struct {
	descriptors []ociDescriptor
	seen        map[string]bool
	observed    int
}

func (p *containerReferrerPages) append(descs []ociDescriptor, more bool) error {
	remaining := containerMaxReferrerDescriptors - p.observed
	limited := len(descs) > remaining
	if limited {
		descs = descs[:remaining]
	}
	p.observed += len(descs)
	for _, desc := range descs {
		if !p.seen[desc.Digest] {
			p.descriptors = append(p.descriptors, desc)
			p.seen[desc.Digest] = true
		}
	}
	if limited || (p.observed == containerMaxReferrerDescriptors && more) {
		return fmt.Errorf("referrers exceed %d descriptors", containerMaxReferrerDescriptors)
	}
	return nil
}

func (c *containerClient) fetchContainerReferrerPage(ctx context.Context, ref imageRef, subject string, page *url.URL, first bool) ([]ociDescriptor, []string, bool, error) {
	resource := "referrers/" + subject
	if page.RawQuery != "" {
		resource += "?" + page.RawQuery
	}
	resp, err := c.getDiscoveryResponse(ctx, ref, resource, mtOCIIndex)
	if err != nil {
		return nil, nil, true, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		if first {
			return nil, nil, false, nil
		}
		return nil, nil, true, fmt.Errorf("HTTP 404")
	}
	descs, err := readContainerReferrerIndex(resp, false)
	return descs, resp.Header.Values("Link"), true, err
}

func (c *containerClient) fetchReferrersFallbackTag(ctx context.Context, ref imageRef, subject string) ([]ociDescriptor, error) {
	resource := "manifests/" + cosignArtifactTag(subject, "")
	resp, err := c.getDiscoveryResponse(ctx, ref, resource, containerManifestAccept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, nil
	}
	descs, err := readContainerReferrerIndex(resp, true)
	if err != nil {
		return nil, fmt.Errorf("referrers fallback tag: %w", err)
	}
	if len(descs) > containerMaxReferrerDescriptors {
		return descs[:containerMaxReferrerDescriptors], fmt.Errorf("referrers fallback tag exceeds %d descriptors", containerMaxReferrerDescriptors)
	}
	return descs, nil
}

// readContainerReferrerIndex closes every response, including failures, and
// detects overflow instead of parsing a silently truncated document.
func readContainerReferrerIndex(resp *http.Response, fallback bool) ([]ociDescriptor, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxServedManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxServedManifestBytes {
		return nil, fmt.Errorf("referrers index exceeds %d bytes", maxServedManifestBytes)
	}
	var index struct {
		SchemaVersion int              `json:"schemaVersion"`
		MediaType     string           `json:"mediaType"`
		Manifests     *[]ociDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("invalid referrers index: %w", err)
	}
	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if fallback && !isContainerIndexType(contentType) {
		contentType = index.MediaType
	}
	if (!fallback && contentType != mtOCIIndex) || (fallback && !isContainerIndexType(contentType)) {
		return nil, fmt.Errorf("unexpected referrers media type %q", contentType)
	}
	if index.SchemaVersion != 2 || index.Manifests == nil || (index.MediaType != "" && !isContainerIndexType(index.MediaType)) {
		return nil, fmt.Errorf("invalid referrers index shape")
	}
	return validateContainerReferrerDescriptors(*index.Manifests)
}

func validateContainerReferrerDescriptors(descriptors []ociDescriptor) ([]ociDescriptor, error) {
	for _, desc := range descriptors {
		if !containerDigestRE.MatchString(desc.Digest) || desc.MediaType == "" || desc.Size < 0 {
			return nil, fmt.Errorf("invalid or unsupported referrer descriptor")
		}
	}
	return descriptors, nil
}

// nextContainerReferrerPage accepts pagination only for this exact subject
// endpoint. The next request always uses the configured registry/repository;
// only a validated link's query is carried forward.
func nextContainerReferrerPage(endpoint, current *url.URL, headers []string) (*url.URL, error) {
	parts, err := containerLinkParts(headers)
	if err != nil {
		return nil, err
	}
	var next *url.URL
	for _, part := range parts {
		candidate, err := containerReferrerNextLink(endpoint, current, part)
		if err != nil {
			return nil, err
		}
		if candidate == nil {
			continue
		}
		if next != nil && next.String() != candidate.String() {
			return nil, fmt.Errorf("ambiguous referrers pagination links")
		}
		next = candidate
	}
	return next, nil
}

func containerLinkParts(headers []string) ([]string, error) {
	var all []string
	for _, header := range headers {
		parts, err := splitContainerLinks(header)
		if err != nil {
			return nil, err
		}
		all = append(all, parts...)
	}
	return all, nil
}

func containerReferrerNextLink(endpoint, current *url.URL, part string) (*url.URL, error) {
	end := strings.IndexByte(part, '>')
	if !strings.HasPrefix(part, "<") || end < 2 {
		return nil, fmt.Errorf("malformed referrers pagination Link")
	}
	_, params, err := mime.ParseMediaType("application/link" + strings.TrimSpace(part[end+1:]))
	if err != nil {
		return nil, fmt.Errorf("malformed referrers pagination parameters")
	}
	isNext := false
	for _, relation := range strings.Fields(params["rel"]) {
		isNext = isNext || strings.EqualFold(relation, "next")
	}
	if !isNext {
		return nil, nil
	}
	link, err := url.Parse(part[1:end])
	if err != nil {
		return nil, fmt.Errorf("invalid referrers pagination URL")
	}
	candidate := current.ResolveReference(link)
	if !sameContainerDiscoveryEndpoint(endpoint, candidate) {
		return nil, fmt.Errorf("referrers pagination leaves the registry, repository, or subject")
	}
	return candidate, nil
}

func splitContainerLinks(header string) ([]string, error) {
	var parts []string
	start := 0
	var scanner containerLinkScanner
	for i, ch := range header {
		if scanner.separator(ch) {
			parts = append(parts, strings.TrimSpace(header[start:i]))
			start = i + 1
		}
	}
	if scanner.quoted || scanner.angled || scanner.escaped {
		return nil, fmt.Errorf("malformed referrers pagination Link")
	}
	if tail := strings.TrimSpace(header[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts, nil
}

type containerLinkScanner struct {
	quoted, angled, escaped bool
}

func (s *containerLinkScanner) separator(ch rune) bool {
	if s.escaped {
		s.escaped = false
		return false
	}
	if s.quoted {
		switch ch {
		case '\\':
			s.escaped = true
		case '"':
			s.quoted = false
		}
		return false
	}
	switch ch {
	case '"':
		s.quoted = !s.angled
	case '<':
		s.angled = true
	case '>':
		s.angled = false
	case ',':
		return !s.angled
	}
	return false
}

func sameContainerDiscoveryEndpoint(expected, actual *url.URL) bool {
	return strings.EqualFold(expected.Scheme, actual.Scheme) && strings.EqualFold(expected.Host, actual.Host) &&
		expected.EscapedPath() == actual.EscapedPath() && actual.User == nil && actual.Fragment == ""
}

// getDiscoveryResponse keeps discovery credentials within one endpoint, even
// across redirects, without restricting the CDN redirects used for blob pulls.
func (c *containerClient) getDiscoveryResponse(ctx context.Context, ref imageRef, resource, accept string) (*http.Response, error) {
	endpoint, err := url.Parse(c.ls.containerAPIBase(ref.Registry) + "/v2/" + ref.Repository + "/" + resource)
	if err != nil {
		return nil, fmt.Errorf("invalid registry discovery endpoint")
	}
	client := *http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !sameContainerDiscoveryEndpoint(endpoint, req.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.authorizedDiscoveryRequest(ctx, &client, ref, endpoint, accept)
		if err != nil {
			return nil, err
		}
		delay, retry := containerDiscoveryRetryDelay(resp, attempt)
		if !retry || attempt+1 == containerReferrerAttempts {
			return resp, nil
		}
		_ = resp.Body.Close()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *containerClient) authorizedDiscoveryRequest(ctx context.Context, client *http.Client, ref imageRef, endpoint *url.URL, accept string) (*http.Response, error) {
	key := ref.Registry + "/" + ref.Repository
	resp, err := doContainerDiscoveryRequest(ctx, client, endpoint, accept, c.auths[key])
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("Www-Authenticate")
	_ = resp.Body.Close()
	authorization, err := c.authorizeChallenge(ctx, challenge, ref)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Token errors can contain credential-bearing realm URLs. The normal
		// image request supplies login guidance; discovery reports its failure
		// without copying those URLs into progress or durable server logs.
		return nil, fmt.Errorf("registry discovery authentication failed; check credentials and token endpoint")
	}
	c.auths[key] = authorization
	return doContainerDiscoveryRequest(ctx, client, endpoint, accept, authorization)
}

func doContainerDiscoveryRequest(ctx context.Context, client *http.Client, endpoint *url.URL, accept, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("invalid registry discovery request")
	}
	req.Header.Set("Accept", accept)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)
	if err == nil {
		return resp, nil
	}
	var requestErr *url.Error
	if errors.As(err, &requestErr) {
		// Pagination queries may carry signed cursors or access tokens.
		return nil, fmt.Errorf("registry discovery request failed: %w", requestErr.Err)
	}
	return nil, fmt.Errorf("registry discovery request failed")
}

func containerDiscoveryRetryDelay(resp *http.Response, attempt int) (time.Duration, bool) {
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
	default:
		return 0, false
	}
	delay := time.Duration(1<<attempt) * 100 * time.Millisecond
	if after := resp.Header.Get("Retry-After"); after != "" {
		if seconds, err := strconv.ParseInt(after, 10, 32); err == nil && seconds >= 0 {
			delay = time.Duration(seconds) * time.Second
		} else if when, err := http.ParseTime(after); err == nil {
			delay = max(time.Until(when), 0)
		}
	}
	// Do not violate a longer Retry-After by retrying prematurely. Report the
	// incomplete discovery so a later collection can retry instead.
	return delay, delay <= containerReferrerMaxRetryDelay
}
