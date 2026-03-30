package diff

import (
	"archive/tar"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func TestResolveDBPath_PlainDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	if err := os.WriteFile(dbPath, []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, cleanup, err := resolveDBPath(dbPath)
	if err != nil {
		t.Fatalf("resolveDBPath: %v", err)
	}
	defer cleanup()

	if resolved != dbPath {
		t.Errorf("expected %q, got %q", dbPath, resolved)
	}
}

func TestResolveDBPath_TarGz(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "vulnerability-db_v5.tar.gz")
	createTarGz(t, archivePath, "vulnerability.db", []byte("SQLite format 3"))

	resolved, cleanup, err := resolveDBPath(archivePath)
	if err != nil {
		t.Fatalf("resolveDBPath: %v", err)
	}
	defer cleanup()

	if filepath.Base(resolved) != "vulnerability.db" {
		t.Errorf("expected vulnerability.db, got %q", filepath.Base(resolved))
	}

	content, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(content) != "SQLite format 3" {
		t.Errorf("content mismatch: got %q", content)
	}
}

func TestResolveDBPath_TarZst(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "db.tar.zst")
	createTarZst(t, archivePath, "vulnerability.db", []byte("zstd-content"))

	resolved, cleanup, err := resolveDBPath(archivePath)
	if err != nil {
		t.Fatalf("resolveDBPath: %v", err)
	}
	defer cleanup()

	if filepath.Base(resolved) != "vulnerability.db" {
		t.Errorf("expected vulnerability.db, got %q", filepath.Base(resolved))
	}

	content, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(content) != "zstd-content" {
		t.Errorf("content mismatch: got %q", content)
	}
}

func TestResolveDBPath_TarXz(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "db.tar.xz")
	createTarXz(t, archivePath, "vulnerability.db", []byte("xz-content"))

	resolved, cleanup, err := resolveDBPath(archivePath)
	if err != nil {
		t.Fatalf("resolveDBPath: %v", err)
	}
	defer cleanup()

	if filepath.Base(resolved) != "vulnerability.db" {
		t.Errorf("expected vulnerability.db, got %q", filepath.Base(resolved))
	}

	content, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(content) != "xz-content" {
		t.Errorf("content mismatch: got %q", content)
	}
}

func TestResolveDBPath_NoDB(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "empty.tar.gz")
	createTarGz(t, archivePath, "readme.txt", []byte("not a db"))

	_, cleanup, err := resolveDBPath(archivePath)
	defer cleanup()

	if err == nil {
		t.Fatal("expected error for archive with no .db file")
	}
}

func TestResolveDBPath_NestedPath(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "grype.tar.gz")
	createTarGz(t, archivePath, "vulnerability-db_v5_2026/vulnerability.db", []byte("SQLite"))

	resolved, cleanup, err := resolveDBPath(archivePath)
	if err != nil {
		t.Fatalf("resolveDBPath: %v", err)
	}
	defer cleanup()

	if filepath.Base(resolved) != "vulnerability.db" {
		t.Errorf("expected vulnerability.db, got %q", filepath.Base(resolved))
	}
}

func TestResolveDBPath_ExtractedFilePermissions(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "perms.tar.gz")
	createTarGz(t, archivePath, "vulnerability.db", []byte("SQLite"))

	resolved, cleanup, err := resolveDBPath(archivePath)
	if err != nil {
		t.Fatalf("resolveDBPath: %v", err)
	}
	defer cleanup()

	info, err := os.Stat(resolved)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		t.Errorf("extracted file should not be group/world accessible, got %04o", perm)
	}
}

func TestCompareDBs_WithArchive(t *testing.T) {
	dir := t.TempDir()

	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 5})
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 7})

	dbBContent, err := os.ReadFile(dbB)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "b.tar.gz")
	createTarGz(t, archivePath, "vulnerability.db", dbBContent)

	result, err := CompareDBs(dbA, archivePath)
	if err != nil {
		t.Fatalf("CompareDBs with archive: %v", err)
	}

	if result.TotalA != 5 {
		t.Errorf("TotalA: got %d, want 5", result.TotalA)
	}
	if result.TotalB != 7 {
		t.Errorf("TotalB: got %d, want 7", result.TotalB)
	}
}

func TestCompareDBs_WithZstArchive(t *testing.T) {
	dir := t.TempDir()

	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 3})
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 4})

	dbBContent, err := os.ReadFile(dbB)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "b.tar.zst")
	createTarZst(t, archivePath, "vulnerability.db", dbBContent)

	result, err := CompareDBs(dbA, archivePath)
	if err != nil {
		t.Fatalf("CompareDBs with zst archive: %v", err)
	}

	if result.TotalA != 3 {
		t.Errorf("TotalA: got %d, want 3", result.TotalA)
	}
	if result.TotalB != 4 {
		t.Errorf("TotalB: got %d, want 4", result.TotalB)
	}
}

func TestArchiveExt(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"foo.db", ""},
		{"foo.tar.gz", ".tar.gz"},
		{"foo.TAR.GZ", ".tar.gz"},
		{"foo.tar.zst", ".tar.zst"},
		{"foo.tar.xz", ".tar.xz"},
		{"/path/to/vulnerability-db_v5_2026.tar.gz", ".tar.gz"},
		{"plain", ""},
	}
	for _, tt := range tests {
		got := archiveExt(tt.path)
		if got != tt.want {
			t.Errorf("archiveExt(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestExtractedFileCloseError(t *testing.T) {
	// Verify that extraction returns error if underlying write fails.
	// We test this indirectly: extract to a read-only directory.
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "test.tar.gz")
	createTarGz(t, archivePath, "vulnerability.db", []byte("SQLite"))

	roDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o755) }()

	_, err := extractDB(archivePath, ".tar.gz", roDir)
	if err == nil {
		t.Fatal("expected error when extracting to read-only directory")
	}
}

// --- test helpers ---

func writeTar(t *testing.T, tw *tar.Writer, entryPath string, content []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name: entryPath,
		Size: int64(len(content)),
		Mode: 0o644,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
}

func createTarGz(t *testing.T, archivePath, entryPath string, content []byte) {
	t.Helper()
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	writeTar(t, tw, entryPath, content)
}

func createTarZst(t *testing.T, archivePath, entryPath string, content []byte) {
	t.Helper()
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer func() { _ = tw.Close() }()

	writeTar(t, tw, entryPath, content)
}

func createTarXz(t *testing.T, archivePath, entryPath string, content []byte) {
	t.Helper()
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	xw, err := xz.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = xw.Close() }()

	tw := tar.NewWriter(xw)
	defer func() { _ = tw.Close() }()

	writeTar(t, tw, entryPath, content)
}

// testFilePerms returns the permission bits of a file, stripping type bits.
func testFilePerms(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
