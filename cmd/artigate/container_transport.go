package main

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// containerRedirectPolicy keeps credentials within the request's original
// origin. Once a chain leaves that origin, later redirects cannot restore them.
type containerRedirectPolicy struct {
	origin        *url.URL
	crossedOrigin bool
	previousCheck func(*http.Request, []*http.Request) error
}

func (p *containerRedirectPolicy) check(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("registry request exceeded redirect limit")
	}
	if p.previousCheck != nil {
		if err := p.previousCheck(req, via); err != nil {
			return err
		}
	}
	previous := via[len(via)-1].URL
	if strings.EqualFold(previous.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return errors.New("registry redirect would downgrade HTTPS")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return errors.New("registry redirect has an unsupported scheme")
	}
	p.crossedOrigin = p.crossedOrigin || !sameContainerOrigin(p.origin, req.URL)
	// Signed blob URLs can contain credentials in their query. Do not copy
	// the previous request's URL into a redirected request's Referer header.
	req.Header.Del("Referer")
	if p.crossedOrigin {
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
		req.URL.User = nil
	}
	return nil
}

func sameContainerOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		containerOriginPort(a) == containerOriginPort(b)
}

func containerOriginPort(u *url.URL) int {
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

// doContainerRequest retains the default client's transport and timeouts while
// enforcing a registry-specific redirect policy. The boolean reports whether
// the whole chain stayed at the original origin and can issue a login challenge.
func doContainerRequest(req *http.Request) (*http.Response, bool, error) {
	client := *http.DefaultClient
	policy := containerRedirectPolicy{origin: req.URL, previousCheck: client.CheckRedirect}
	client.CheckRedirect = policy.check
	// Registry authentication is explicit; do not use ambient client cookies.
	client.Jar = nil
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, &containerAuthError{message: "registry request failed", cause: err}
	}
	return resp, !policy.crossedOrigin, nil
}
