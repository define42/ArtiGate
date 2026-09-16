package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newDiscoveryClient(t *testing.T, handler http.HandlerFunc) (*containerClient, imageRef) {
	t.Helper()
	up := httptest.NewServer(handler)
	t.Cleanup(up.Close)
	ls := &LowServer{containerRegistryBases: map[string]string{"registry.test": up.URL}}
	c := ls.newContainerClient()
	c.auths["registry.test/org/app"] = "Bearer discovery-test"
	return c, imageRef{Registry: "registry.test", Repository: "org/app", Tag: "latest"}
}

func discoveryDescriptor(label string) ociDescriptor {
	return ociDescriptor{MediaType: mtOCIManifest, Digest: containerSHA([]byte(label)), Size: 123}
}

func discoveryWriteIndex(w http.ResponseWriter, descriptors ...ociDescriptor) {
	if descriptors == nil {
		descriptors = []ociDescriptor{}
	}
	w.Header().Set("Content-Type", mtOCIIndex)
	_ = json.NewEncoder(w).Encode(ociReferrersIndex{SchemaVersion: 2, MediaType: mtOCIIndex, Manifests: descriptors})
}

func discoveryFetch(t *testing.T, c *containerClient, ref imageRef) ([]ociDescriptor, []string) {
	t.Helper()
	var progress []string
	ctx := withProgress(t.Context(), func(line string) { progress = append(progress, line) })
	return c.fetchReferrers(ctx, ref, containerSHA([]byte("discovery-subject"))), progress
}

func TestContainerReferrerDiscoveryPagination(t *testing.T) {
	for _, mode := range []string{"query", "absolute", "root-relative", "multiple-links"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			first, second := discoveryDescriptor("first"), discoveryDescriptor("second")
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer discovery-test" {
					t.Error("pagination lost scoped authentication")
				}
				if r.URL.Query().Get("page") == "2" {
					discoveryWriteIndex(w, first, second)
					return
				}
				next := "?page=2"
				switch mode {
				case "absolute":
					next = "http://" + r.Host + r.URL.Path + next
				case "root-relative":
					next = r.URL.Path + next
				}
				link := "<" + next + `>; rel="next"; title="page, two"`
				if mode == "multiple-links" {
					link = `<?page=0>; rel="prev", ` + link
				}
				w.Header().Set("Link", link)
				discoveryWriteIndex(w, first)
			})
			got, warnings := discoveryFetch(t, c, ref)
			if calls.Load() != 2 || len(got) != 2 || got[0].Digest != first.Digest || got[1].Digest != second.Digest || len(warnings) != 0 {
				t.Fatalf("pagination: calls=%d descriptors=%+v warnings=%v", calls.Load(), got, warnings)
			}
		})
	}
}

func TestContainerReferrerDiscoveryFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		mediaType string
		wantCalls int32
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, wantCalls: 1},
		{name: "forbidden", status: http.StatusForbidden, wantCalls: 1},
		{name: "method not allowed", status: http.StatusMethodNotAllowed, wantCalls: 1},
		{name: "rate limited", status: http.StatusTooManyRequests, wantCalls: containerReferrerAttempts},
		{name: "unavailable", status: http.StatusServiceUnavailable, wantCalls: containerReferrerAttempts},
		{name: "malformed JSON", status: http.StatusOK, body: "{", mediaType: mtOCIIndex, wantCalls: 1},
		{name: "missing descriptors", status: http.StatusOK, body: `{"schemaVersion":2}`, mediaType: mtOCIIndex, wantCalls: 1},
		{name: "invalid descriptor", status: http.StatusOK, body: `{"schemaVersion":2,"manifests":[{"digest":"broken"}]}`, mediaType: mtOCIIndex, wantCalls: 1},
		{name: "unexpected content type", status: http.StatusOK, body: `{"schemaVersion":2,"manifests":[]}`, mediaType: "text/html", wantCalls: 1},
		{name: "oversized body", status: http.StatusOK, body: strings.Repeat(" ", maxServedManifestBytes+1), mediaType: mtOCIIndex, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls, fallbacks atomic.Int32
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/manifests/") {
					fallbacks.Add(1)
					discoveryWriteIndex(w, discoveryDescriptor("unexpected fallback"))
					return
				}
				calls.Add(1)
				w.Header().Set("Content-Type", tc.mediaType)
				w.Header().Set("Retry-After", "0")
				if tc.status == http.StatusUnauthorized {
					w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			got, warnings := discoveryFetch(t, c, ref)
			if len(got) != 0 || calls.Load() != tc.wantCalls || fallbacks.Load() != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "discovery incomplete") {
				t.Fatalf("calls=%d fallbacks=%d descriptors=%+v warnings=%v", calls.Load(), fallbacks.Load(), got, warnings)
			}
		})
	}
}

func TestContainerReferrerDiscoveryRetainsPartialPages(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var fallbacks atomic.Int32
			first := discoveryDescriptor("retained page")
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/manifests/") {
					fallbacks.Add(1)
				}
				if r.URL.RawQuery == "page=2" {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					return
				}
				w.Header().Set("Link", `<?page=2>; rel="next"`)
				discoveryWriteIndex(w, first)
			})
			got, warnings := discoveryFetch(t, c, ref)
			if len(got) != 1 || got[0].Digest != first.Digest || fallbacks.Load() != 0 || len(warnings) != 1 {
				t.Fatalf("descriptors=%+v fallbacks=%d warnings=%v", got, fallbacks.Load(), warnings)
			}
		})
	}
}

func TestContainerReferrerDiscoveryFallback(t *testing.T) {
	for _, mode := range []string{"present", "absent", "malformed", "wrong media type", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var calls, fallbacks atomic.Int32
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/referrers/") {
					calls.Add(1)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				fallbacks.Add(1)
				switch mode {
				case "absent":
					w.WriteHeader(http.StatusNotFound)
				case "malformed":
					w.Header().Set("Content-Type", mtOCIIndex)
					_, _ = w.Write([]byte("{"))
				case "wrong media type":
					w.Header().Set("Content-Type", mtOCIManifest)
					_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"` + mtOCIManifest + `","manifests":[]}`))
				case "oversized":
					w.Header().Set("Content-Type", mtOCIIndex)
					_, _ = w.Write([]byte(strings.Repeat(" ", maxServedManifestBytes+1)))
				default:
					discoveryWriteIndex(w, discoveryDescriptor("fallback"))
				}
			})
			got, warnings := discoveryFetch(t, c, ref)
			wantDescriptors, wantWarnings := 0, 0
			if mode == "present" {
				wantDescriptors = 1
			} else if mode != "absent" {
				wantWarnings = 1
			}
			if calls.Load() != 1 || fallbacks.Load() != 1 || len(got) != wantDescriptors || len(warnings) != wantWarnings {
				t.Fatalf("api=%d fallback=%d descriptors=%+v warnings=%v", calls.Load(), fallbacks.Load(), got, warnings)
			}
		})
	}
}

func TestContainerReferrerDiscoveryRetries(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) < containerReferrerAttempts {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					return
				}
				discoveryWriteIndex(w, discoveryDescriptor("recovered"))
			})
			got, warnings := discoveryFetch(t, c, ref)
			if calls.Load() != containerReferrerAttempts || len(got) != 1 || len(warnings) != 0 {
				t.Fatalf("retry result: calls=%d descriptors=%+v warnings=%v", calls.Load(), got, warnings)
			}
		})
	}
	t.Run("long retry-after is not violated", func(t *testing.T) {
		var calls atomic.Int32
		c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
		})
		_, warnings := discoveryFetch(t, c, ref)
		if calls.Load() != 1 || len(warnings) != 1 {
			t.Fatalf("long retry-after: calls=%d warnings=%v", calls.Load(), warnings)
		}
	})
	t.Run("cancellation interrupts retry delay", func(t *testing.T) {
		first := make(chan struct{}, 1)
		var calls atomic.Int32
		c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusServiceUnavailable)
			first <- struct{}{}
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.fetchReferrers(ctx, ref, containerSHA([]byte("discovery-subject")))
		}()
		<-first
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("discovery ignored cancellation during retry delay")
		}
		if calls.Load() != 1 {
			t.Errorf("retried after cancellation: %d requests", calls.Load())
		}
	})
}

func TestContainerReferrerDiscoveryPaginationLimits(t *testing.T) {
	for _, mode := range []string{"loop", "page limit", "descriptor limit", "malformed link", "other repository", "other subject", "userinfo"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				link := "?page=" + strconv.Itoa(int(n))
				switch mode {
				case "loop":
					link = "?page=1"
				case "malformed link":
					w.Header().Set("Link", "broken")
					discoveryWriteIndex(w, discoveryDescriptor("kept"))
					return
				case "other repository":
					link = strings.Replace(r.URL.Path, "/org/app/", "/private/other/", 1)
				case "other subject":
					link = "/v2/org/app/referrers/" + containerSHA([]byte("another subject"))
				case "userinfo":
					link = "http://user:password@" + r.Host + r.URL.Path + "?page=2"
				case "descriptor limit":
					descriptors := make([]ociDescriptor, containerMaxReferrerDescriptors+1)
					for i := range descriptors {
						descriptors[i] = discoveryDescriptor(strconv.Itoa(i))
					}
					discoveryWriteIndex(w, descriptors...)
					return
				}
				w.Header().Set("Link", "<"+link+`>; rel="next"`)
				discoveryWriteIndex(w, discoveryDescriptor("kept"))
			})
			got, warnings := discoveryFetch(t, c, ref)
			wantCalls, wantDescriptors := int32(1), 1
			switch mode {
			case "loop":
				wantCalls = 2
			case "page limit":
				wantCalls = containerMaxReferrerPages
			case "descriptor limit":
				wantDescriptors = containerMaxReferrerDescriptors
			}
			if calls.Load() != wantCalls || len(got) != wantDescriptors || len(warnings) != 1 {
				t.Fatalf("bounded discovery: calls=%d descriptors=%d warnings=%v", calls.Load(), len(got), warnings)
			}
		})
	}
}

func TestContainerReferrerDiscoveryRejectsOffOrigin(t *testing.T) {
	for _, mode := range []string{"pagination", "redirect", "same-origin other-repository redirect", "fallback redirect"} {
		t.Run(mode, func(t *testing.T) {
			var unauthorizedCalls atomic.Int32
			outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				unauthorizedCalls.Add(1)
				discoveryWriteIndex(w)
			}))
			t.Cleanup(outside.Close)
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/private/") {
					unauthorizedCalls.Add(1)
					discoveryWriteIndex(w)
					return
				}
				if mode == "pagination" {
					w.Header().Set("Link", "<"+outside.URL+r.URL.Path+`?page=2>; rel="next"`)
					discoveryWriteIndex(w, discoveryDescriptor("kept"))
					return
				}
				if mode == "fallback redirect" && strings.Contains(r.URL.Path, "/referrers/") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				target := outside.URL + r.URL.Path
				if mode == "same-origin other-repository redirect" {
					target = strings.Replace(r.URL.Path, "/org/app/", "/private/other/", 1)
				}
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			})
			_, warnings := discoveryFetch(t, c, ref)
			if unauthorizedCalls.Load() != 0 || len(warnings) != 1 {
				t.Fatalf("out-of-scope requests=%d warnings=%v", unauthorizedCalls.Load(), warnings)
			}
		})
	}
}

func TestContainerReferrerDiscoveryEmptyIsComplete(t *testing.T) {
	var paths []string
	c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		discoveryWriteIndex(w)
	})
	got, warnings := discoveryFetch(t, c, ref)
	if len(got) != 0 || len(warnings) != 0 || len(paths) != 1 || !slices.Contains(paths, fmt.Sprintf("/v2/org/app/referrers/%s", containerSHA([]byte("discovery-subject")))) {
		t.Fatalf("empty discovery: descriptors=%+v warnings=%v paths=%v", got, warnings, paths)
	}
}

func TestContainerReferrerDiscoveryRefreshesAuthentication(t *testing.T) {
	var calls atomic.Int32
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("discovery-user:discovery-password"))
	c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != authorization {
			w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		discoveryWriteIndex(w)
	})
	c.creds = map[string]registryCredential{"registry.test": {Username: "discovery-user", Password: "discovery-password"}}
	for range 2 {
		_, warnings := discoveryFetch(t, c, ref)
		if len(warnings) != 0 {
			t.Fatalf("authenticated discovery failed: %v", warnings)
		}
	}
	if calls.Load() != 3 {
		t.Errorf("authentication was not refreshed and cached: %d requests", calls.Load())
	}
}

func TestContainerReferrerDiscoveryRedactsSensitiveErrors(t *testing.T) {
	for _, mode := range []string{"token endpoint failure", "pagination transport failure", "malformed redirect"} {
		t.Run(mode, func(t *testing.T) {
			const secret = "sensitive-query-token"
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(tokenServer.Close)
			c, ref := newDiscoveryClient(t, func(w http.ResponseWriter, r *http.Request) {
				if mode == "malformed redirect" {
					w.Header().Set("Location", "http://auth.test/%zz?access_token="+secret)
					w.WriteHeader(http.StatusFound)
					return
				}
				if mode == "token endpoint failure" {
					w.Header().Set("Www-Authenticate", `Bearer realm="`+tokenServer.URL+`?access_token=`+secret+`",service="registry.test"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.URL.RawQuery == "access_token="+secret {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				w.Header().Set("Link", "<?access_token="+secret+`>; rel="next"`)
				discoveryWriteIndex(w, discoveryDescriptor("retained"))
			})
			c.creds = map[string]registryCredential{"registry.test": {Username: "private-user", Password: "private-password"}}
			_, warnings := discoveryFetch(t, c, ref)
			if len(warnings) != 1 || strings.Contains(warnings[0], secret) || strings.Contains(warnings[0], "private-password") || strings.Contains(warnings[0], tokenServer.URL) {
				t.Fatalf("discovery warning exposed sensitive URL or login: %v", warnings)
			}
		})
	}
}
