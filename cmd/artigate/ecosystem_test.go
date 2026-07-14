package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestEcosystemRegistryWiring enforces, for every registered ecosystem, the
// wiring the registry cannot generate itself: the hooks each dispatch site
// needs, both dashboards' labels/pages, and e2e coverage. Adding an ecosystem
// is meant to be two code sites (its own file with a constructor, plus the
// ecosystems() list); this test turns everything still hand-maintained — the
// UI maps in ui_low.go and ui/app.ts, the nav buttons, the e2e suite — into
// a build failure with a precise message instead of a silent runtime gap.
func TestEcosystemRegistryWiring(t *testing.T) {
	streamRE := regexp.MustCompile(`^[a-z0-9]+$`)
	seen := map[string]bool{}
	for _, e := range ecosystems() {
		if !streamRE.MatchString(e.stream) {
			t.Errorf("stream %q must be lowercase alphanumeric (bundle filenames depend on it)", e.stream)
			continue
		}
		if seen[e.stream] {
			t.Errorf("stream %q registered twice", e.stream)
		}
		seen[e.stream] = true
		t.Run(e.stream, func(t *testing.T) {
			checkEcosystemHooks(t, e)
			checkEcosystemLowUI(t, e)
			checkEcosystemHighUI(t, e)
			checkEcosystemE2E(t, e)
		})
	}
}

// checkEcosystemHooks asserts the descriptor carries every hook the dispatch
// sites dereference without nil checks.
func checkEcosystemHooks(t *testing.T, e ecosystem) {
	t.Helper()
	if e.label == "" || e.title == "" {
		t.Error("label and title must be set (both dashboards render them)")
	}
	for name, missing := range map[string]bool{
		"collect (POST /admin/<stream>/collect)": e.collect == nil,
		"manifestContent (high-side validation)": e.manifestContent == nil,
		"validateContent (high-side validation)": e.validateContent == nil,
		"serve (high-side URL space)":            e.serve == nil,
		"scanTree (dashboard tree)":              e.scanTree == nil,
		"detail (dashboard detail panel)":        e.detail == nil,
		"contentDesc (bundle rejection message)": e.contentDesc == "",
	} {
		if missing {
			t.Errorf("missing %s", name)
		}
	}
	// Exactly one of watchCollect (schedulable) and noSchedule (the refusal
	// message) must be set: the watch endpoints dispatch on that distinction.
	if (e.watchCollect == nil) == (e.noSchedule == "") {
		t.Error("set exactly one of watchCollect and noSchedule (watch dispatch)")
	}
}

// checkEcosystemLowUI asserts the low-side dashboard exposes the ecosystem: a
// nav button, its page section, the collect endpoint, its streamLabel entry,
// and — for schedulable streams — its VIEW_STREAM entry (which drives the
// per-page schedule list).
func checkEcosystemLowUI(t *testing.T, e ecosystem) {
	t.Helper()
	wants := []string{
		`data-view="` + e.stream + `"`,
		`id="view-` + e.stream + `"`,
		"/admin/" + e.stream + "/collect",
		e.stream + ":'" + e.label + "'",
	}
	if e.watchCollect != nil {
		wants = append(wants, e.stream+":'"+e.stream+"'")
	}
	for _, want := range wants {
		if !strings.Contains(lowUIHTML, want) {
			t.Errorf("low-side dashboard (ui_low.go) missing %s", want)
		}
	}
}

// checkEcosystemHighUI asserts the high-side dashboard exposes the ecosystem:
// a nav button in index.html, and its STREAM_LABELS + View/VIEW_TITLES
// entries in the TypeScript source and the embedded compiled app.js (tsc ties
// the View union to VIEW_TITLES, so the title entry implies the view exists).
func checkEcosystemHighUI(t *testing.T, e ecosystem) {
	t.Helper()
	if !strings.Contains(uiIndexHTML, `data-view="`+e.stream+`"`) {
		t.Errorf("high-side dashboard (ui/index.html) missing the %s nav button", e.stream)
	}
	appTS, err := os.ReadFile("ui/app.ts")
	if err != nil {
		t.Fatalf("read ui/app.ts: %v", err)
	}
	for _, want := range []string{
		e.stream + `: "` + e.label + `"`,
		e.stream + `: "` + e.title + `"`,
	} {
		if !strings.Contains(string(appTS), want) {
			t.Errorf("high-side dashboard (ui/app.ts) missing %s", want)
		}
		if !strings.Contains(uiAppJS, want) {
			t.Errorf("embedded ui/app.js missing %s — run `make ui` after editing app.ts", want)
		}
	}
}

// checkEcosystemE2E asserts the opt-in end-to-end suite covers the ecosystem
// with a test file of its own (e2e/<stream>_test.go).
func checkEcosystemE2E(t *testing.T, e ecosystem) {
	t.Helper()
	if _, err := os.Stat("../../e2e/" + e.stream + "_test.go"); err != nil {
		t.Errorf("e2e suite missing e2e/%s_test.go: %v", e.stream, err)
	}
}

// TestEcosystemRegistryDispatch pins the registry-derived dispatch behavior
// the old hand-maintained sites provided: every stream is a known stream with
// a collect route, and the high-side serve chain still orders hf before
// containers (mirrored AI models answer /v2/ paths for their own repos and
// fall through to the container mirror for the rest).
func TestEcosystemRegistryDispatch(t *testing.T) {
	streams := knownStreams()
	byStream := map[string]int{}
	for i, s := range streams {
		byStream[s] = i
	}
	if len(byStream) != len(streams) {
		t.Fatalf("knownStreams has duplicates: %v", streams)
	}
	hf, okHF := byStream[streamHF]
	containers, okC := byStream[streamContainers]
	if !okHF || !okC || hf > containers {
		t.Fatalf("registry must order hf before containers (serve order is load-bearing), got %v", streams)
	}
	for _, stream := range streams {
		if !isKnownStream(stream) {
			t.Errorf("stream %s not known", stream)
		}
	}
	if isKnownStream("bogus") {
		t.Error("bogus stream reported known")
	}
}

// TestEcosystemCollectRoutes pins the registry-derived collect route table:
// every registered stream's endpoint is present, named by its stream
// (collectStreamFromPath depends on that), and nothing else is routed.
func TestEcosystemCollectRoutes(t *testing.T) {
	ls, _ := newFakeLowServer(t)
	handlers := ls.collectHandlers()
	for _, e := range ecosystems() {
		route := "/admin/" + e.stream + "/collect"
		if handlers[route] == nil {
			t.Errorf("collect route %s not registered", route)
		}
		if got := collectStreamFromPath(route); got != e.stream {
			t.Errorf("collectStreamFromPath(%s) = %q, want %q", route, got, e.stream)
		}
	}
	if len(handlers) != len(ecosystems()) {
		t.Errorf("%d collect routes for %d ecosystems", len(handlers), len(ecosystems()))
	}
}

// TestNoManifestContentError pins the rejection message shape: it must name
// every registered ecosystem's content so operators can tell what a valid
// bundle could have carried.
func TestNoManifestContentError(t *testing.T) {
	msg := noManifestContentError().Error()
	for _, e := range ecosystems() {
		if !strings.Contains(msg, e.contentDesc) {
			t.Errorf("rejection message missing %q: %s", e.contentDesc, msg)
		}
	}
	if !strings.Contains(msg, "content-part marker") {
		t.Errorf("rejection message missing the content-part marker: %s", msg)
	}
}

// TestJoinWithAnd covers the prose list renderer used by /ui/api/repos.
func TestJoinWithAnd(t *testing.T) {
	for want, items := range map[string][]string{
		"":               nil,
		"a":              {"a"},
		"a and b":        {"a", "b"},
		"a, b, and c":    {"a", "b", "c"},
		"a, b, c, and d": {"a", "b", "c", "d"},
	} {
		if got := joinWithAnd(items); got != want {
			t.Errorf("joinWithAnd(%v) = %q, want %q", items, got, want)
		}
	}
}

func TestEcosystemForUnknown(t *testing.T) {
	if _, ok := ecosystemFor("bogus"); ok {
		t.Error("ecosystemFor(bogus) reported a registered ecosystem")
	}
	e, ok := ecosystemFor(streamGo)
	if !ok || e.stream != streamGo {
		t.Errorf("ecosystemFor(go) = %+v, %v", e, ok)
	}
	if len(ecosystems()) != len(knownStreams()) {
		t.Error("ecosystems and knownStreams disagree")
	}
}
