package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPythonIndexImportPersistsVerifiedMetadata(t *testing.T) {
	for _, name := range []string{"project records", "content part"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pub, priv := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			stage := t.TempDir()
			dest := filepath.Join(stage, "python", "packages")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			const filename = "demo-1.0-py3-none-any.whl"
			writeWheelZip(t, filepath.Join(dest, filename), map[string]string{
				"demo-1.0.dist-info/METADATA": wheelMetadata(">=3.9"),
			})
			files, projects, _, err := collectPythonDist(dest)
			if err != nil {
				t.Fatal(err)
			}
			manifest := BundleManifest{
				Type: manifestType, Format: manifestFormatCurrent, Stream: streamPython,
				Sequence: 1, BundleID: bundleIDFor(streamPython, 1),
				Created: time.Unix(0, 0).UTC(), Generator: "test", Ecosystems: []string{"python"},
				Files: files, Python: &PythonManifest{Projects: projects},
			}
			if name == "content part" {
				manifest.Python = nil
				manifest.Part = &BundlePartInfo{Index: 1, Count: 2}
			} else {
				// Project records are descriptive claims; only the verified file
				// digest and metadata extracted from its bytes can seed the index.
				p := &manifest.Python.Projects[0]
				p.Name, p.NormalizedName, p.Version = "forged", "forged", "99"
				p.Files[0].Filename = "forged-99-py3-none-any.whl"
				p.Files[0].SHA256 = strings.Repeat("a", 64)
				p.Files[0].RequiresPython = ">=99"
			}
			signAndWriteBundle(t, hs.cfg.Landing, priv, manifest, stage)
			if result := mustImportNext(t, hs); !result.Imported {
				t.Fatalf("bundle was not imported: %+v", result)
			}

			// Check the on-disk snapshot before any project request can fill it.
			data, err := os.ReadFile(hs.pythonIndexPath())
			if err != nil {
				t.Fatal(err)
			}
			var saved struct {
				Projects map[string][]struct {
					Filename       string `json:"filename"`
					SHA256         string `json:"sha256"`
					RequiresPython string `json:"requires_python"`
				} `json:"projects"`
			}
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			entries := saved.Projects["demo"]
			if len(saved.Projects) != 1 || len(entries) != 1 || entries[0].Filename != filename ||
				entries[0].SHA256 != files[0].SHA256 || entries[0].RequiresPython != ">=3.9" {
				t.Fatalf("import did not persist verified artifact metadata: %s", data)
			}

			// Preserve the cache's size/mtime identity while replacing all bytes.
			// Hashing or opening this wheel after restart would produce different
			// results, proving both the digest and extracted metadata are reused.
			installed := filepath.Join(hs.pythonDir(), filename)
			fi, err := os.Stat(installed)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, installed, make([]byte, fi.Size()))
			if err := os.Chtimes(installed, fi.ModTime(), fi.ModTime()); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewHighServer(hs.cfg, pub)
			if err != nil {
				t.Fatal(err)
			}
			got, err := restarted.pyProjectFiles("demo")
			if err != nil || len(got) != 1 || got[0].sha256 != files[0].SHA256 || got[0].requiresPython != ">=3.9" {
				t.Fatalf("first lookup after restart = %+v, %v", got, err)
			}
			if got, err := restarted.pyProjectFiles("forged"); err != nil || len(got) != 0 {
				t.Fatalf("forged project was indexed: %+v, %v", got, err)
			}
		})
	}
}

func TestPythonIndexRecovery(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "missing"},
		{name: "corrupt", data: "{broken"},
		{name: "obsolete", data: `{"format":0,"projects":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, priv := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			writeSignedPythonBundle(t, hs.cfg.Landing, priv, 1, 0, map[string]string{
				"demo-1.0-py3-none-any.whl":  "wheel bytes",
				"other-2.0-py3-none-any.whl": "other wheel bytes",
			})
			mustImportNext(t, hs)
			if tc.data == "" {
				if err := os.Remove(hs.pythonIndexPath()); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, hs.pythonIndexPath(), []byte(tc.data))
			}
			restarted, err := NewHighServer(hs.cfg, pub)
			if err != nil {
				t.Fatal(err)
			}
			for _, project := range []string{"demo", "other", "absent"} {
				got, err := restarted.pyProjectFiles(project)
				if err != nil {
					t.Fatal(err)
				}
				if project == "absent" {
					if len(got) != 0 {
						t.Fatalf("absent project = %+v", got)
					}
					continue
				}
				if len(got) != 1 {
					t.Fatalf("recovered %s = %+v", project, got)
				}
				want, err := sha256File(filepath.Join(hs.pythonDir(), got[0].filename))
				if err != nil || got[0].sha256 != want {
					t.Fatalf("recovered digest %q, want %q: %v", got[0].sha256, want, err)
				}
			}
		})
	}
}

func TestPythonIndexPriorDigestMustBeVerified(t *testing.T) {
	for _, name := range []string{"cached", "legacy inventory"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pub, _ := newTestKeys(t)
			hs := newTestHighServer(t, pub)
			stage := t.TempDir()
			f := stageTestFile(t, stage, "python/packages/demo-1.0-py3-none-any.whl", "verified bytes")
			if err := hs.installVerifiedFiles(stage, []ManifestFile{f}, nil); err != nil {
				t.Fatal(err)
			}
			if name == "legacy inventory" {
				if err := os.Remove(hs.pythonIndexPath()); err != nil {
					t.Fatal(err)
				}
				var err error
				hs, err = NewHighServer(hs.cfg, pub)
				if err != nil {
					t.Fatal(err)
				}
			}
			want := f.SHA256
			f.Prior, f.SHA256 = true, strings.Repeat("a", 64)
			if err := hs.installVerifiedFiles(stage, []ManifestFile{f}, nil); err != nil {
				t.Fatal(err)
			}
			got, err := hs.pyProjectFiles("demo")
			if err != nil || len(got) != 1 || got[0].sha256 != want {
				t.Fatalf("prior-file digest = %+v, %v; want verified %s", got, err, want)
			}
		})
	}
}

func TestPythonIndexPersistenceFailureLeavesImportRetryable(t *testing.T) {
	t.Parallel()
	pub, priv := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	if _, err := hs.pyProjectFiles("absent"); err != nil {
		t.Fatal(err)
	}
	// Block the final atomic rename after installation has completed.
	if err := os.Remove(hs.pythonIndexPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(hs.pythonIndexPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	const filename = "demo-1.0-py3-none-any.whl"
	writeSignedPythonBundle(t, hs.cfg.Landing, priv, 1, 0, map[string]string{filename: "verified bytes"})
	for range 2 {
		if _, err := hs.ImportNext(); err == nil || !strings.Contains(err.Error(), "persist Python index") {
			t.Fatalf("blocked index write: %v", err)
		}
		if got := hs.state.Imported[streamGo]; got != 0 {
			t.Fatalf("sequence advanced despite failed index persistence: %d", got)
		}
	}
	if !fileExists(filepath.Join(hs.pythonDir(), filename)) {
		t.Fatal("expected wheel installed before index write failed")
	}
	if !bundleCompleteInDir(hs.cfg.Landing, bundleIDForSequence(1)) {
		t.Fatal("failed import must remain available for retry")
	}
	if err := os.Remove(hs.pythonIndexPath()); err != nil {
		t.Fatal(err)
	}
	if got, err := hs.pyProjectFiles("demo"); err != nil || len(got) != 1 {
		t.Fatalf("installed file not recovered after persistence failure: %+v, %v", got, err)
	}
	if result := mustImportNext(t, hs); !result.Imported {
		t.Fatalf("repaired index did not allow retry: %+v", result)
	}
}

func TestPythonIndexPartialInstallationIsDiscovered(t *testing.T) {
	t.Parallel()
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	stage := t.TempDir()
	good := stageTestFile(t, stage, "python/packages/demo-1.0-py3-none-any.whl", "verified bytes")
	missing := ManifestFile{Path: "python/packages/absent-1.0-py3-none-any.whl", SHA256: strings.Repeat("a", 64), Size: 1}
	if err := hs.installVerifiedFiles(stage, []ManifestFile{good, missing}, nil); err == nil {
		t.Fatal("expected failure for missing staged file")
	}
	if got, err := hs.pyProjectFiles("demo"); err != nil || len(got) != 1 || got[0].sha256 != good.SHA256 {
		t.Fatalf("partially installed file not discovered: %+v, %v", got, err)
	}
	if got, err := hs.pyProjectFiles("absent"); err != nil || len(got) != 0 {
		t.Fatalf("uninstalled file was indexed: %+v, %v", got, err)
	}
}

func TestPythonIndexAppendsSortedFilesAndProvenance(t *testing.T) {
	t.Parallel()
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	stage := t.TempDir()
	for _, filename := range []string{"demo-3.0-py3-none-any.whl", "demo-1.0.tar.gz", "demo-2.0-py3-none-any.whl"} {
		f := stageTestFile(t, stage, "python/packages/"+filename, filename)
		if err := hs.installVerifiedFiles(stage, []ManifestFile{f}, nil); err != nil {
			t.Fatal(err)
		}
	}
	const wheel = "demo-2.0-py3-none-any.whl"
	provenance := stageTestFile(t, stage, "python/packages/"+wheel+".provenance", "{}")
	if err := hs.installVerifiedFiles(stage, []ManifestFile{provenance}, nil); err != nil {
		t.Fatal(err)
	}
	provenance.Prior = true
	if err := hs.installVerifiedFiles(stage, []ManifestFile{provenance}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := hs.pyProjectFiles("demo")
	if err != nil || len(got) != 3 {
		t.Fatalf("appended files = %+v, %v", got, err)
	}
	names := make([]string, 0, len(got))
	for _, f := range got {
		names = append(names, f.filename)
		if f.provenance != (f.filename == wheel) {
			t.Errorf("provenance for %s = %v", f.filename, f.provenance)
		}
	}
	if !slices.IsSorted(names) {
		t.Errorf("appended files are not sorted: %v", names)
	}
}

func TestPythonIndexDetectsAddedAndRemovedFiles(t *testing.T) {
	t.Parallel()
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	stage := t.TempDir()
	f := stageTestFile(t, stage, "python/packages/old-1.0-py3-none-any.whl", "old")
	if err := hs.installVerifiedFiles(stage, []ManifestFile{f}, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(hs.pythonDir(), "old-1.0-py3-none-any.whl")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hs.pythonDir(), "new-2.0.tar.gz"), []byte("new"))
	writeFile(t, filepath.Join(hs.pythonDir(), "invalid.whl"), []byte("ignored"))
	if err := os.Mkdir(filepath.Join(hs.pythonDir(), "directory-1.0-py3-none-any.whl"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"old", "directory", "absent"} {
		if got, err := hs.pyProjectFiles(project); err != nil || len(got) != 0 {
			t.Fatalf("%s should be absent: %+v, %v", project, got, err)
		}
	}
	got, err := hs.pyProjectFiles("new")
	if err != nil || len(got) != 1 || got[0].filename != "new-2.0.tar.gz" {
		t.Fatalf("new file not discovered: %+v, %v", got, err)
	}
}

func TestPythonIndexConcurrentReadsAndImports(t *testing.T) {
	t.Parallel()
	pub, _ := newTestKeys(t)
	hs := newTestHighServer(t, pub)
	stage := t.TempDir()
	var files []ManifestFile
	for i := range 12 {
		filename := fmt.Sprintf("python/packages/demo-%02d-py3-none-any.whl", i)
		files = append(files, stageTestFile(t, stage, filename, filename))
	}
	if err := hs.installVerifiedFiles(stage, files[:1], nil); err != nil {
		t.Fatal(err)
	}
	const readers = 8
	start := make(chan struct{})
	failures := make(chan error, readers)
	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			<-start
			for range 30 {
				got, err := hs.pyProjectFiles("demo")
				if err != nil {
					failures <- err
					return
				}
				if len(got) == 0 {
					failures <- fmt.Errorf("concurrent lookup returned %d files", len(got))
					return
				}
				last := ""
				for _, f := range got {
					if f.filename <= last || f.sha256 == "" {
						failures <- fmt.Errorf("incomplete or unordered result: %+v", got)
						return
					}
					last = f.filename
				}
				absent, err := hs.pyProjectFiles("absent")
				if err != nil {
					failures <- err
					return
				}
				if len(absent) != 0 {
					failures <- fmt.Errorf("missing project returned %+v", absent)
					return
				}
			}
		})
	}
	close(start)
	for _, f := range files[1:] {
		if err := hs.installVerifiedFiles(stage, []ManifestFile{f}, nil); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if got, err := hs.pyProjectFiles("demo"); err != nil || len(got) != len(files) {
		t.Fatalf("final lookup returned %d files, want %d: %v", len(got), len(files), err)
	}
}
