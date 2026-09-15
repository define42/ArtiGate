package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Keep the selected project's releases fixed while growing unrelated inventory.
// Warm the lookup before measurement to exclude digest and index initialization.
func BenchmarkPyProjectFiles(b *testing.B) {
	for _, unrelated := range []int{100, 10_000} {
		b.Run(fmt.Sprintf("unrelated=%d", unrelated), func(b *testing.B) {
			s := benchmarkPythonInventory(b, unrelated)
			for _, project := range []string{"selected", "missing"} {
				b.Run(project, func(b *testing.B) {
					benchmarkCheckPyProject(b, s, project)
					b.ReportAllocs()
					for b.Loop() {
						benchmarkCheckPyProject(b, s, project)
					}
				})
			}
		})
	}
}

func BenchmarkPyProjectFilesParallel(b *testing.B) {
	for _, unrelated := range []int{100, 10_000} {
		b.Run(fmt.Sprintf("unrelated=%d", unrelated), func(b *testing.B) {
			s := benchmarkPythonInventory(b, unrelated)
			for _, project := range []string{"selected", "missing"} {
				b.Run(project, func(b *testing.B) {
					benchmarkCheckPyProject(b, s, project)
					b.ReportAllocs()
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							benchmarkCheckPyProject(b, s, project)
						}
					})
				})
			}
		})
	}
}

func benchmarkCheckPyProject(b *testing.B, s *HighServer, project string) {
	files, err := s.pyProjectFiles(project)
	if err != nil {
		b.Errorf("pyProjectFiles(%q): %v", project, err)
		return
	}
	want := 0
	if project == "selected" {
		want = 3
	}
	if len(files) != want {
		b.Errorf("pyProjectFiles(%q) returned %d files, want %d", project, len(files), want)
	}
}

func benchmarkPythonInventory(b *testing.B, unrelated int) *HighServer {
	b.Helper()
	root := b.TempDir()
	s := &HighServer{cfg: HighConfig{Root: root}, downloadDir: filepath.Join(root, "download")}
	if err := os.MkdirAll(s.pythonDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	var wheel bytes.Buffer
	zw := zip.NewWriter(&wheel)
	metadata, err := zw.Create("fixture-1.0.dist-info/METADATA")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := metadata.Write([]byte("Metadata-Version: 2.1\nRequires-Python: >=3.10\n")); err != nil {
		b.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}
	for i := range unrelated + 3 {
		name := fmt.Sprintf("unrelated%d-1.0-py3-none-any.whl", i)
		if i < 3 {
			name = fmt.Sprintf("selected-1.%d-py3-none-any.whl", i)
		}
		if err := os.WriteFile(filepath.Join(s.pythonDir(), name), wheel.Bytes(), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	return s
}
