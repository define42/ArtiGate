package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// pyProjectIndex is derived local state, never a transferred index. Imports
// update it before committing their sequence. A single snapshot keeps membership,
// verified digests and extracted metadata consistent across restarts. Writing the
// snapshot costs O(inventory) per import; normal project lookups only stat their
// selected files and the package directory, including for missing projects.
//
// mu permits concurrent warm lookups. Initialization, recovery and cold metadata
// reads take the exclusive lock so concurrent clients do not repeat that work.
type pyProjectIndex struct {
	mu          sync.RWMutex
	initialized bool
	dirty       bool
	state       pyIndexState
}

type pyIndexState struct {
	Format    int                        `json:"format"`
	Directory pyFileStamp                `json:"directory"`
	Projects  map[string][]pyIndexedFile `json:"projects"`
}

// Size and modification time retain the existing digest cache's invalidation
// policy. Mode also notices permission changes without opening unchanged wheels.
type pyFileStamp struct {
	Size    int64       `json:"size"`
	ModTime time.Time   `json:"mod_time"`
	Mode    os.FileMode `json:"mode"`
}

type pyIndexedFile struct {
	Filename       string      `json:"filename"`
	Version        string      `json:"version"`
	Stamp          pyFileStamp `json:"stamp"`
	SHA256         string      `json:"sha256,omitempty"`
	RequiresPython string      `json:"requires_python,omitempty"`
}

func pythonFileStamp(abs string) (pyFileStamp, error) {
	fi, err := os.Stat(abs)
	if err != nil {
		return pyFileStamp{}, err
	}
	return pyFileStamp{Size: fi.Size(), ModTime: fi.ModTime(), Mode: fi.Mode()}, nil
}

func (a pyFileStamp) equal(b pyFileStamp) bool {
	return a.Size == b.Size && a.ModTime.Equal(b.ModTime) && a.Mode == b.Mode
}

func (s *HighServer) pythonDirectoryStamp() (pyFileStamp, error) {
	stamp, err := pythonFileStamp(s.pythonDir())
	if errors.Is(err, os.ErrNotExist) {
		return pyFileStamp{}, nil
	}
	return stamp, err
}

func (s *HighServer) pythonIndexPath() string {
	return filepath.Join(s.cfg.Root, "python-index.json")
}

// lockPythonIndex returns with the read lock held. Only the first caller after
// a directory change rebuilds membership; a valid saved snapshot needs no scan.
func (s *HighServer) lockPythonIndex() error {
	for {
		s.pyIndex.mu.RLock()
		stamp, err := s.pythonDirectoryStamp()
		if err != nil {
			s.pyIndex.mu.RUnlock()
			return err
		}
		if s.pyIndex.initialized && !s.pyIndex.dirty && s.pyIndex.state.Directory.equal(stamp) {
			return nil
		}
		s.pyIndex.mu.RUnlock()
		s.pyIndex.mu.Lock()
		err = s.ensurePythonIndexLocked()
		s.pyIndex.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (s *HighServer) ensurePythonIndexLocked() error {
	stamp, err := s.pythonDirectoryStamp()
	if err != nil {
		return err
	}
	c := &s.pyIndex
	if !c.initialized {
		if err := s.loadPythonIndexLocked(); err != nil {
			return err
		}
	}
	if c.initialized && c.state.Directory.equal(stamp) {
		if c.dirty {
			return s.savePythonIndexLocked()
		}
		return nil
	}
	if err := s.rebuildPythonIndexLocked(stamp); err != nil {
		return err
	}
	return s.savePythonIndexLocked()
}

func (s *HighServer) loadPythonIndexLocked() error {
	data, err := os.ReadFile(s.pythonIndexPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state pyIndexState
	if json.Unmarshal(data, &state) != nil || !validPythonIndex(state) {
		// Missing, corrupt or obsolete derived state can be rebuilt from the
		// installed artifacts. Never accept partial decoded state.
		return nil
	}
	s.pyIndex.state = state
	s.pyIndex.initialized = true
	return nil
}

func validPythonIndex(state pyIndexState) bool {
	if state.Format != 1 || state.Projects == nil {
		return false
	}
	for project, files := range state.Projects {
		last := ""
		for _, f := range files {
			p, v, ok := parsePythonArtifact(f.Filename)
			if !ok || p != project || v != f.Version || f.Filename <= last ||
				strings.ContainsAny(f.Filename, "/\\") || !validPythonDigest(f.SHA256) {
				return false
			}
			last = f.Filename
		}
	}
	return true
}

func validPythonDigest(sum string) bool {
	if sum == "" {
		return true // A legacy entry whose metadata has not been read yet.
	}
	_, err := hex.DecodeString(sum)
	return len(sum) == 64 && err == nil
}

func parsePythonArtifact(filename string) (project, version string, ok bool) {
	if project, version, ok = parseWheelFilename(filename); ok {
		return project, version, true
	}
	project, version, ok = parseSdistFilename(filename)
	return project, version, ok && version != ""
}

func (s *HighServer) rebuildPythonIndexLocked(stamp pyFileStamp) error {
	entries, err := os.ReadDir(s.pythonDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	old := make(map[string]pyIndexedFile)
	for _, files := range s.pyIndex.state.Projects {
		for _, f := range files {
			old[f.Filename] = f
		}
	}
	projects := make(map[string][]pyIndexedFile)
	for _, entry := range entries {
		project, version, ok := parsePythonArtifact(entry.Name())
		if entry.IsDir() || !ok {
			continue
		}
		f, found := old[entry.Name()]
		if !found {
			f = pyIndexedFile{Filename: entry.Name(), Version: version}
		}
		projects[project] = append(projects[project], f)
	}
	s.pyIndex.state = pyIndexState{Format: 1, Directory: stamp, Projects: projects}
	s.pyIndex.initialized = true
	s.pyIndex.dirty = true
	return nil
}

func (s *HighServer) savePythonIndexLocked() error {
	if err := writeJSONAtomic(s.pythonIndexPath(), s.pyIndex.state, stateFileMode); err != nil {
		return fmt.Errorf("persist Python index: %w", err)
	}
	s.pyIndex.dirty = false
	return nil
}

func pythonPackageFiles(files []ManifestFile, goFiles map[string]bool) []ManifestFile {
	var packages []ManifestFile
	for _, f := range files {
		if !goFiles[f.Path] && path.Dir(f.Path) == "python/packages" {
			packages = append(packages, f)
		}
	}
	return packages
}

// publishPythonIndexLocked runs only after all listed files installed. Content
// parts and delta bundles need indexing too, so use actual manifest file paths,
// not Python project records or transferred Requires-Python attributes.
func (s *HighServer) publishPythonIndexLocked(files []ManifestFile) error {
	for _, f := range files {
		name := path.Base(f.Path)
		project, version, ok := parsePythonArtifact(name)
		if !ok {
			continue
		}
		entries := s.pyIndex.state.Projects[project]
		i := sort.Search(len(entries), func(i int) bool { return entries[i].Filename >= name })
		if i == len(entries) || entries[i].Filename != name {
			entries = append(entries, pyIndexedFile{})
			copy(entries[i+1:], entries[i:])
			entries[i] = pyIndexedFile{Filename: name, Version: version}
			s.pyIndex.state.Projects[project] = entries
		}
		verifiedSum := f.SHA256
		if f.Prior {
			// Immutable prior files are only size-checked by requirePriorFile.
			// Reuse their verified cache or hash the bytes, never seed a digest
			// from an unverified prior-file claim.
			verifiedSum = ""
		}
		if err := s.refreshPythonFileLocked(&entries[i], verifiedSum); err != nil {
			return err
		}
	}
	stamp, err := s.pythonDirectoryStamp()
	if err != nil {
		return err
	}
	s.pyIndex.state.Directory = stamp
	s.pyIndex.dirty = true
	return s.savePythonIndexLocked()
}

func (s *HighServer) refreshPythonFileLocked(f *pyIndexedFile, verifiedSum string) error {
	abs := filepath.Join(s.pythonDir(), f.Filename)
	stamp, err := pythonFileStamp(abs)
	if err != nil {
		return err
	}
	if f.SHA256 != "" && f.Stamp.equal(stamp) && (verifiedSum == "" || verifiedSum == f.SHA256) {
		return nil
	}
	if verifiedSum == "" {
		verifiedSum, err = sha256File(abs)
		if err != nil {
			return err
		}
	}
	f.SHA256 = verifiedSum
	f.RequiresPython = requiresPythonFor(abs)
	f.Stamp = stamp
	s.pyIndex.dirty = true
	return nil
}

// pyProjectFiles reads only one project's sorted entries. Warm requests share
// the read lock; cold requests recheck under the write lock before hashing.
func (s *HighServer) pyProjectFiles(project string) ([]pyProjectFile, error) {
	if err := s.lockPythonIndex(); err != nil {
		return nil, err
	}
	out, stale, err := s.indexedPythonFiles(s.pyIndex.state.Projects[project])
	s.pyIndex.mu.RUnlock()
	if err != nil || !stale {
		return out, err
	}
	s.pyIndex.mu.Lock()
	defer s.pyIndex.mu.Unlock()
	if err := s.ensurePythonIndexLocked(); err != nil {
		return nil, err
	}
	files := s.pyIndex.state.Projects[project]
	for i := range files {
		if err := s.refreshPythonFileLocked(&files[i], ""); err != nil {
			return nil, err
		}
	}
	if s.pyIndex.dirty {
		if err := s.savePythonIndexLocked(); err != nil {
			return nil, err
		}
	}
	out, stale, err = s.indexedPythonFiles(files)
	if stale {
		return nil, fmt.Errorf("Python project %s changed while reading its metadata", project)
	}
	return out, err
}

func (s *HighServer) indexedPythonFiles(files []pyIndexedFile) ([]pyProjectFile, bool, error) {
	var out []pyProjectFile
	if len(files) > 0 {
		out = make([]pyProjectFile, 0, len(files))
	}
	for _, f := range files {
		abs := filepath.Join(s.pythonDir(), f.Filename)
		stamp, err := pythonFileStamp(abs)
		if err != nil {
			return nil, false, err
		}
		if f.SHA256 == "" || !f.Stamp.equal(stamp) {
			return nil, true, nil
		}
		out = append(out, pyProjectFile{
			filename: f.Filename, version: f.Version, sha256: f.SHA256,
			requiresPython: f.RequiresPython, provenance: fileExists(abs + ".provenance"),
		})
	}
	return out, false, nil
}

// pythonFileDigest shares the persisted metadata with the detail panel without
// making a request for one file read every other release of the project.
func (s *HighServer) pythonFileDigest(filename string) (string, error) {
	project, _, ok := parsePythonArtifact(filename)
	if !ok {
		return "", os.ErrNotExist
	}
	if err := s.lockPythonIndex(); err != nil {
		return "", err
	}
	f := s.indexedPythonFile(project, filename)
	stamp, err := pythonFileStamp(filepath.Join(s.pythonDir(), filename))
	if f != nil && err == nil && f.SHA256 != "" && f.Stamp.equal(stamp) {
		sum := f.SHA256
		s.pyIndex.mu.RUnlock()
		return sum, nil
	}
	s.pyIndex.mu.RUnlock()
	s.pyIndex.mu.Lock()
	defer s.pyIndex.mu.Unlock()
	if err := s.ensurePythonIndexLocked(); err != nil {
		return "", err
	}
	f = s.indexedPythonFile(project, filename)
	if f == nil {
		return "", os.ErrNotExist
	}
	if err := s.refreshPythonFileLocked(f, ""); err != nil {
		return "", err
	}
	if s.pyIndex.dirty {
		if err := s.savePythonIndexLocked(); err != nil {
			return "", err
		}
	}
	return f.SHA256, nil
}

// indexedPythonFile requires at least the index's read lock.
func (s *HighServer) indexedPythonFile(project, filename string) *pyIndexedFile {
	files := s.pyIndex.state.Projects[project]
	i := sort.Search(len(files), func(i int) bool { return files[i].Filename >= filename })
	if i == len(files) || files[i].Filename != filename {
		return nil
	}
	return &files[i]
}
