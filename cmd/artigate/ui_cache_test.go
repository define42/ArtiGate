package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type treeCacheTestResult struct {
	tree uiTree
	err  error
}

func treeCacheTestReceive(t *testing.T, results <-chan treeCacheTestResult) treeCacheTestResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("cache operation blocked behind a repository scan")
		return treeCacheTestResult{}
	}
}

func treeCacheTestSnapshot(name string) uiTree {
	return flatTree{{Module: name, Versions: []string{"1.0.0"}}}
}

func treeCacheTestName(t *testing.T, result treeCacheTestResult, want string) {
	t.Helper()
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.tree == nil {
		t.Fatal("cache returned a nil tree")
	}
	if nodes := result.tree.children(""); len(nodes) != 1 || nodes[0].Label != want {
		t.Fatalf("tree roots = %+v, want one root named %q", nodes, want)
	}
}

func TestTreeCacheScanDoesNotBlockInvalidationOrOtherEcosystems(t *testing.T) {
	t.Parallel()
	var cache treeCache
	var npmScans int
	scanNPM := func() (uiTree, error) {
		npmScans++
		return treeCacheTestSnapshot("npm-package"), nil
	}
	if _, err := cache.get(t.Context(), streamNpm, scanNPM); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var goScans atomic.Int32
	goResults := make(chan treeCacheTestResult, 1)
	go func() {
		tree, err := cache.get(t.Context(), streamGo, func() (uiTree, error) {
			if goScans.Add(1) == 1 {
				close(started)
				<-release
				return treeCacheTestSnapshot("before-import"), nil
			}
			return treeCacheTestSnapshot("after-import"), nil
		})
		goResults <- treeCacheTestResult{tree, err}
	}()
	<-started

	otherResults := make(chan treeCacheTestResult, 1)
	go func() {
		tree, err := cache.get(t.Context(), streamNpm, scanNPM)
		otherResults <- treeCacheTestResult{tree, err}
	}()
	treeCacheTestName(t, treeCacheTestReceive(t, otherResults), "npm-package")

	// Import completion must be able to invalidate the same ecosystem while
	// its previous generation is still being scanned.
	go func() {
		cache.invalidate(streamGo)
		otherResults <- treeCacheTestResult{}
	}()
	treeCacheTestReceive(t, otherResults)

	go func() {
		tree, err := cache.get(t.Context(), streamUploads, func() (uiTree, error) {
			return treeCacheTestSnapshot("uploaded-file"), nil
		})
		otherResults <- treeCacheTestResult{tree, err}
	}()
	treeCacheTestName(t, treeCacheTestReceive(t, otherResults), "uploaded-file")
	go func() {
		tree, err := cache.get(t.Context(), streamNpm, scanNPM)
		otherResults <- treeCacheTestResult{tree, err}
	}()
	treeCacheTestName(t, treeCacheTestReceive(t, otherResults), "npm-package")
	if npmScans != 1 {
		t.Fatalf("unrelated cached ecosystem scanned %d times, want 1", npmScans)
	}

	unblock()
	treeCacheTestName(t, treeCacheTestReceive(t, goResults), "after-import")
	tree, err := cache.get(t.Context(), streamGo, func() (uiTree, error) {
		goScans.Add(1)
		return treeCacheTestSnapshot("unexpected-rescan"), nil
	})
	treeCacheTestName(t, treeCacheTestResult{tree, err}, "after-import")
	if scans := goScans.Load(); scans != 2 {
		t.Fatalf("invalidated scan ran %d times, want original plus one retry", scans)
	}
}

func TestTreeCacheDeduplicatesConcurrentScans(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var cache treeCache
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		var scans atomic.Int32
		const readers = 12
		results := make(chan treeCacheTestResult, readers)
		for range readers {
			go func() {
				tree, err := cache.get(t.Context(), streamGo, func() (uiTree, error) {
					scans.Add(1)
					<-release
					return treeCacheTestSnapshot("shared"), nil
				})
				results <- treeCacheTestResult{tree, err}
			}()
		}
		synctest.Wait()
		if got := scans.Load(); got != 1 {
			t.Fatalf("concurrent requests started %d scans, want 1", got)
		}
		unblock()
		for range readers {
			treeCacheTestName(t, <-results, "shared")
		}
		if got := scans.Load(); got != 1 {
			t.Fatalf("concurrent requests completed %d scans, want 1", got)
		}
	})
}

func TestTreeCacheExpirationIsPerEcosystemAndRequestDriven(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var cache treeCache
		var goScans, npmScans int
		scanGo := func() (uiTree, error) {
			goScans++
			return treeCacheTestSnapshot("go-module"), nil
		}
		scanNPM := func() (uiTree, error) {
			npmScans++
			return treeCacheTestSnapshot("npm-package"), nil
		}
		get := func(stream string, scan func() (uiTree, error)) {
			t.Helper()
			if _, err := cache.get(t.Context(), stream, scan); err != nil {
				t.Fatal(err)
			}
		}
		get(streamGo, scanGo)
		time.Sleep(treeCacheTTL / 2)
		get(streamNpm, scanNPM)
		time.Sleep(treeCacheTTL/2 + time.Nanosecond)
		get(streamGo, scanGo)
		get(streamNpm, scanNPM)
		if goScans != 2 || npmScans != 1 {
			t.Fatalf("scans after Go expiration: Go=%d npm=%d, want 2 and 1", goScans, npmScans)
		}
		time.Sleep(2 * treeCacheTTL)
		if goScans != 2 || npmScans != 1 {
			t.Fatalf("idle cache triggered scans: Go=%d npm=%d", goScans, npmScans)
		}
		get(streamNpm, scanNPM)
		if goScans != 2 || npmScans != 2 {
			t.Fatalf("npm refresh rescanned other ecosystems: Go=%d npm=%d", goScans, npmScans)
		}
	})
}

func TestTreeCacheScanErrorCanBeRetried(t *testing.T) {
	t.Parallel()
	var cache treeCache
	wantErr := errors.New("repository temporarily unreadable")
	var scans int
	scan := func() (uiTree, error) {
		scans++
		if scans == 1 {
			return nil, wantErr
		}
		return treeCacheTestSnapshot("recovered"), nil
	}
	if _, err := cache.get(t.Context(), streamGo, scan); !errors.Is(err, wantErr) {
		t.Fatalf("failed scan error = %v, want %v", err, wantErr)
	}
	for range 2 {
		tree, err := cache.get(t.Context(), streamGo, scan)
		treeCacheTestName(t, treeCacheTestResult{tree, err}, "recovered")
	}
	if scans != 2 {
		t.Fatalf("scan called %d times, want failed attempt plus one recovery", scans)
	}
}

func TestTreeCacheWaiterCancellation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var cache treeCache
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		first := make(chan treeCacheTestResult, 1)
		go func() {
			tree, err := cache.get(t.Context(), streamGo, func() (uiTree, error) {
				<-release
				return treeCacheTestSnapshot("ready"), nil
			})
			first <- treeCacheTestResult{tree, err}
		}()
		synctest.Wait()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		waiter := make(chan treeCacheTestResult, 1)
		var waiterScans atomic.Int32
		go func() {
			tree, err := cache.get(ctx, streamGo, func() (uiTree, error) {
				waiterScans.Add(1)
				return treeCacheTestSnapshot("unexpected"), nil
			})
			waiter <- treeCacheTestResult{tree, err}
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case result := <-waiter:
			if !errors.Is(result.err, context.Canceled) {
				t.Fatalf("canceled waiter error = %v, want context.Canceled", result.err)
			}
		default:
			t.Fatal("canceled waiter still waits for the repository scan")
		}
		if got := waiterScans.Load(); got != 0 {
			t.Fatalf("waiting request started %d redundant scans", got)
		}
		unblock()
		treeCacheTestName(t, <-first, "ready")
	})
}

func TestTreeCacheCancellationStopsGenerationRetries(t *testing.T) {
	t.Parallel()
	var cache treeCache
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var scans int
	_, err := cache.get(ctx, streamGo, func() (uiTree, error) {
		scans++
		cache.invalidate(streamGo)
		cancel()
		return treeCacheTestSnapshot("stale"), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled generation retry error = %v, want context.Canceled", err)
	}
	if scans != 1 {
		t.Fatalf("canceled request started %d scans, want 1", scans)
	}
	tree, err := cache.get(t.Context(), streamGo, func() (uiTree, error) {
		return treeCacheTestSnapshot("fresh"), nil
	})
	treeCacheTestName(t, treeCacheTestResult{tree, err}, "fresh")
}
