package main

// The ecosystem registry. Adding an ecosystem used to be shotgun surgery
// across every dispatch site (knownStreams, the collect-handler map, the
// watch dispatch, manifest validation, the publish sequence, the high-side
// serve chain, flags, and the dashboard trees/details/repos) with nothing
// tying them together — a forgotten entry was a silent runtime bug. All of
// those sites now derive from the single list in ecosystems(), so a new
// ecosystem is two code sites: implement the hooks in its own file (as a
// fooEcosystem() constructor next to python.go, npm.go, ...) and append that
// constructor here. TestEcosystemRegistryWiring then enforces the pieces no
// registry can generate — the dashboard forms, labels, and e2e coverage —
// failing with a precise message instead of shipping a half-wired ecosystem.

import (
	"context"
	"flag"
	"net/http"
)

// ecosystem describes one mirrored package ecosystem end to end: its stream
// identity, the low-side hooks that fetch and export it, the high-side hooks
// that verify, install, and serve it, and its dashboard wiring. Hooks take
// the server as a parameter (method expressions fit directly) so descriptors
// stay plain values with no construction order to worry about.
type ecosystem struct {
	// stream names the bundle stream and doubles as the collect route segment
	// (/admin/<stream>/collect) and both dashboards' view key.
	stream string
	// label is the short human name both dashboards show ("Go", "APT", ...).
	label string
	// title is the high-side dashboard's page title ("Go modules", ...).
	title string

	// collect answers POST /admin/<stream>/collect on the low side.
	collect func(*LowServer, context.Context, *http.Request) (ExportResult, error)
	// watchCollect runs a stored watch spec; nil marks a stream that cannot
	// be scheduled, with noSchedule giving the operator-facing reason.
	watchCollect func(*LowServer, context.Context, []byte) (ExportResult, error)
	noSchedule   string
	// flags declares the ecosystem's low-side tool/upstream overrides; nil
	// when it has none.
	flags func(*flag.FlagSet, *LowConfig)

	// manifestContent reports whether a manifest carries this ecosystem's
	// content; validateContent (called only when it does) checks that content
	// against the manifest's verified file set. contentDesc names the content
	// in the "manifest contains no ..." rejection.
	manifestContent func(BundleManifest) bool
	validateContent func(BundleManifest, map[string]bool) error
	contentDesc     string
	// publish regenerates the served repository metadata from the artifacts
	// actually installed — never from transferred indexes. It must no-op on a
	// manifest without this ecosystem's content (every import pass calls every
	// publish hook). nil when the installed files are already the served layout.
	publish func(*HighServer, BundleManifest) error
	// serve handles the ecosystem's high-side URL space, reporting whether it
	// wrote a response.
	serve func(*HighServer, http.ResponseWriter, *http.Request) bool

	// scanTree walks the ecosystem's repository once for the dashboard tree;
	// detail describes one selected leaf. repoList, when set, backs the
	// per-repository "Set me up" guide (/ui/api/repos).
	scanTree func(*HighServer) (uiTree, error)
	detail   func(*HighServer, string) (UIDetail, error)
	repoList func(*HighServer) ([]UIRepo, error)
}

// ecosystems is the registry: the one list every ecosystem dispatch site
// derives from. The order is the high-side URL-claim order and is
// load-bearing in one place — hf must precede containers, because mirrored
// AI models answer the container-registry protocol (/v2/...) for their own
// repositories and fall through to the container mirror for everything else.
// Elsewhere the order only sets display order (low-side status, job lists).
func ecosystems() []ecosystem {
	return []ecosystem{
		goEcosystem(),
		pythonEcosystem(),
		mavenEcosystem(),
		aptEcosystem(),
		rpmEcosystem(),
		hfEcosystem(),
		containersEcosystem(),
		npmEcosystem(),
		cratesEcosystem(),
		terraformEcosystem(),
		helmEcosystem(),
		nugetEcosystem(),
		apkEcosystem(),
		uploadsEcosystem(),
	}
}

// ecosystemFor returns the registered ecosystem for a stream name.
func ecosystemFor(stream string) (ecosystem, bool) {
	for _, e := range ecosystems() {
		if e.stream == stream {
			return e, true
		}
	}
	return ecosystem{}, false
}

// watchAdapter adapts a typed collector into the registry's watch hook: the
// stored spec decodes into the collector's request type and runs.
func watchAdapter[T any](collect func(*LowServer, context.Context, T) (ExportResult, error)) func(*LowServer, context.Context, []byte) (ExportResult, error) {
	return func(s *LowServer, ctx context.Context, spec []byte) (ExportResult, error) {
		return decodeAndCollect(ctx, spec, func(ctx context.Context, req T) (ExportResult, error) {
			return collect(s, ctx, req)
		})
	}
}

// segmentTreeScan and flatTreeScan adapt a UIModule lister into the registry's
// scanTree hook, picking the tree shape the ecosystem's names call for (see
// uiTree in ui.go).
func segmentTreeScan(list func(*HighServer) ([]UIModule, error)) func(*HighServer) (uiTree, error) {
	return func(s *HighServer) (uiTree, error) {
		mods, err := list(s)
		return segmentTree(mods), err
	}
}

func flatTreeScan(list func(*HighServer) ([]UIModule, error)) func(*HighServer) (uiTree, error) {
	return func(s *HighServer) (uiTree, error) {
		pkgs, err := list(s)
		return flatTree(pkgs), err
	}
}

// goEcosystem describes the Go module stream. Go is the original ecosystem
// and its machinery is the shared core (lowside.go, highside.go, ui.go), so
// its descriptor lives here rather than in an ecosystem file of its own. Its
// module records sit at the manifest root (not under a per-ecosystem field)
// and its verified files are installed by the importer itself, so it has no
// publish hook.
func goEcosystem() ecosystem {
	return ecosystem{
		stream:          streamGo,
		label:           "Go",
		title:           "Go modules",
		collect:         (*LowServer).HandleGoCollect,
		watchCollect:    watchAdapter((*LowServer).CollectGo),
		manifestContent: func(m BundleManifest) bool { return len(m.Modules) > 0 },
		validateContent: func(m BundleManifest, seen map[string]bool) error {
			return validateManifestModules(m.Modules, seen)
		},
		contentDesc: "modules",
		serve:       (*HighServer).serveGo,
		scanTree:    segmentTreeScan((*HighServer).listGoModules),
		detail:      (*HighServer).goDetail,
	}
}
