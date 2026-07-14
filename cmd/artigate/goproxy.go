package main

// GOPROXY protocol plumbing: parsing proxy request URLs
// ("/<module>/@v/<version>.<ext>", "/@v/list", "/@latest") and the bang
// case-encoding the proxy protocol uses for module paths and versions on disk
// and in URLs ("!m" encodes "M").

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

type proxyKind int

const (
	proxyUnknown proxyKind = iota
	proxyList
	proxyLatest
	proxyVersionFile
)

type ProxyRequest struct {
	Kind           proxyKind
	ModuleEscaped  string
	Module         string
	VersionEscaped string
	Version        string
	Ext            string
	RelativePath   string
}

func parseProxyRequest(urlPath string) (ProxyRequest, error) {
	rel := strings.TrimPrefix(urlPath, "/")
	rel = path.Clean("/" + rel)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "." || rel == "" {
		return ProxyRequest{}, errors.New("empty path")
	}
	if err := validateRelPath(rel); err != nil {
		return ProxyRequest{}, err
	}

	if strings.HasSuffix(rel, "/@latest") {
		modEsc := strings.TrimSuffix(rel, "/@latest")
		mod, err := unescapeModulePath(modEsc)
		if err != nil {
			return ProxyRequest{}, err
		}
		return ProxyRequest{Kind: proxyLatest, ModuleEscaped: modEsc, Module: mod, RelativePath: rel}, nil
	}

	idx := strings.LastIndex(rel, "/@v/")
	if idx < 0 {
		return ProxyRequest{}, errors.New("not a GOPROXY path")
	}
	modEsc := rel[:idx]
	suffix := rel[idx+len("/@v/"):]
	mod, err := unescapeModulePath(modEsc)
	if err != nil {
		return ProxyRequest{}, err
	}
	if suffix == "list" {
		return ProxyRequest{Kind: proxyList, ModuleEscaped: modEsc, Module: mod, RelativePath: rel}, nil
	}
	for _, ext := range []string{".info", ".mod", ".zip", ".ziphash"} {
		if strings.HasSuffix(suffix, ext) {
			verEsc := strings.TrimSuffix(suffix, ext)
			ver, err := unescapeVersion(verEsc)
			if err != nil {
				return ProxyRequest{}, err
			}
			return ProxyRequest{Kind: proxyVersionFile, ModuleEscaped: modEsc, Module: mod, VersionEscaped: verEsc, Version: ver, Ext: ext, RelativePath: rel}, nil
		}
	}
	return ProxyRequest{}, errors.New("unknown GOPROXY path")
}

func unescapeModulePath(s string) (string, error) { return unescapeBang(s) }
func unescapeVersion(s string) (string, error)    { return unescapeBang(s) }

func unescapeBang(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '!' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", errors.New("invalid escaped path: trailing bang")
		}
		n := s[i+1]
		if n < 'a' || n > 'z' {
			return "", fmt.Errorf("invalid escaped path: !%c", n)
		}
		b.WriteByte(n - ('a' - 'A'))
		i++
	}
	return b.String(), nil
}

func escapePathApprox(s string) string    { return escapeBang(s) }
func escapeVersionApprox(s string) string { return escapeBang(s) }

func escapeBang(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
