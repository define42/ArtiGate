package buildin

import (
	"io/fs"
	"strings"
	"testing"
)

// TestSourcesCatalogMatchesEmbeddedFiles pins the catalog/file pairing both
// ways: every catalog entry must load a real embedded file, and every embedded
// file must be offered by the catalog (an orphaned file would silently never
// reach the UI).
func TestSourcesCatalogMatchesEmbeddedFiles(t *testing.T) {
	src, err := Sources()
	if err != nil {
		t.Fatalf("Sources: %v", err)
	}
	cataloged := checkEntries(t, src)
	err = fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !cataloged[path] {
			t.Errorf("embedded file %s is missing from the catalog", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded files: %v", err)
	}
}

// checkEntries validates each stream's entries and returns the set of files
// the catalog references.
func checkEntries(t *testing.T, src map[string][]Entry) map[string]bool {
	t.Helper()
	if len(src["apt"]) == 0 || len(src["rpm"]) == 0 || len(src["apk"]) == 0 {
		t.Errorf("want built-in sources for apt, rpm and apk, got streams %v", mapKeys(src))
	}
	cataloged := map[string]bool{}
	labels := map[string]bool{}
	for stream, entries := range src {
		for _, e := range entries {
			if e.Label == "" || labels[stream+"\x00"+e.Label] {
				t.Errorf("stream %s: empty or duplicate label %q", stream, e.Label)
			}
			labels[stream+"\x00"+e.Label] = true
			if !strings.HasPrefix(e.File, stream+"/") {
				t.Errorf("stream %s: entry %s is filed under the wrong directory", stream, e.File)
			}
			if cataloged[e.File] {
				t.Errorf("file %s is cataloged twice", e.File)
			}
			cataloged[e.File] = true
			if strings.TrimSpace(e.Content) == "" {
				t.Errorf("built-in %s has no content", e.File)
			}
		}
	}
	return cataloged
}

func mapKeys(src map[string][]Entry) []string {
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	return keys
}
