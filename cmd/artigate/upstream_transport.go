package main

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// upstreamRedirectPolicy keeps credentials within the request's original
// origin. Once a chain leaves that origin, later redirects cannot restore them.
type upstreamRedirectPolicy struct {
	origin        *url.URL
	crossedOrigin bool
	previousCheck func(*http.Request, []*http.Request) error
}

func (p *upstreamRedirectPolicy) check(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("upstream request exceeded redirect limit")
	}
	if p.previousCheck != nil {
		if err := p.previousCheck(req, via); err != nil {
			return err
		}
	}
	previous := via[len(via)-1].URL
	if strings.EqualFold(previous.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return errors.New("upstream redirect would downgrade HTTPS")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return errors.New("upstream redirect has an unsupported scheme")
	}
	// net/http copies the initial headers again on each redirect, so remember
	// the boundary crossing for the lifetime of this request chain.
	p.crossedOrigin = p.crossedOrigin || !sameUpstreamOrigin(p.origin, req.URL)
	// Signed blob URLs can contain credentials in their query. Do not copy
	// the previous request's URL into a redirected request's Referer header.
	req.Header.Del("Referer")
	if p.crossedOrigin {
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Cookie2")
		req.URL.User = nil
	}
	return nil
}

func sameUpstreamOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		upstreamOriginPort(a) == upstreamOriginPort(b)
}

func upstreamOriginPort(u *url.URL) int {
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil {
			return -1
		}
		return number
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// doUpstreamRequest retains the default client's transport and timeouts while
// enforcing an origin-aware redirect policy. The boolean reports whether
// the whole chain stayed at the original origin and can issue a login challenge.
func doUpstreamRequest(req *http.Request) (*http.Response, bool, error) {
	client := *http.DefaultClient
	policy := upstreamRedirectPolicy{origin: req.URL, previousCheck: client.CheckRedirect}
	client.CheckRedirect = policy.check
	// Upstream authentication is explicit; a cookie jar could add credentials
	// after CheckRedirect has removed them.
	client.Jar = nil
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	return resp, !policy.crossedOrigin, nil
}
