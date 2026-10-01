package main

import "net/http"

// doContainerRequest applies the shared upstream redirect policy while keeping
// signed registry URLs out of error messages. The boolean reports whether the
// whole chain stayed at the original origin and can issue a login challenge.
func doContainerRequest(req *http.Request) (*http.Response, bool, error) {
	resp, sameOrigin, err := doUpstreamRequest(req)
	if err != nil {
		return nil, false, &containerAuthError{message: "registry request failed", cause: err}
	}
	return resp, sameOrigin, nil
}
