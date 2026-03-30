package diff

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// resolveDBPath returns a path to a SQLite .db file. If the input is an
// archive (.tar.gz, .tar.zst, .tar.xz), it extracts the first .db file
// found to a temp directory and returns that path plus a cleanup function.
// For plain .db files, cleanup is a no-op.
func resolveDBPath(path string) (dbPath string, cleanup func(), err error) {
	noop := func() {}

	ext := archiveExt(path)
	if ext == "" {
		return path, noop, nil
	}

	tmpDir, err := os.MkdirTemp("", "smelt-archive-*")
	if err != nil {
		return "", noop, fmt.Errorf("creating temp dir: %w", err)
	}
	cleanupDir := func() { _ = os.RemoveAll(tmpDir) }

	dbPath, err = extractDB(path, ext, tmpDir)
	if err != nil {
		cleanupDir()
		return "", noop, err
	}

	return dbPath, cleanupDir, nil
}

// archiveExt returns the archive extension if the path looks like a supported
// archive, or empty string if it's a plain file.
func archiveExt(path string) string {
	lower := strings.ToLower(path)
	for _, ext := range []string{".tar.gz", ".tar.zst", ".tar.xz"} {
		if strings.HasSuffix(lower, ext) {
			return ext
		}
	}
	return ""
}

// extractDB opens an archive, finds the first .db file, extracts it to
// destDir, and returns the path.
func extractDB(archivePath, ext, destDir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("opening archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	var tr *tar.Reader

	switch ext {
	case ".tar.gz":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", fmt.Errorf("gzip reader: %w", err)
		}
		defer func() { _ = gz.Close() }()
		tr = tar.NewReader(gz)

	case ".tar.zst":
		zr, err := zstd.NewReader(f)
		if err != nil {
			return "", fmt.Errorf("zstd reader: %w", err)
		}
		defer zr.Close()
		tr = tar.NewReader(zr)

	case ".tar.xz":
		xr, err := xz.NewReader(f)
		if err != nil {
			return "", fmt.Errorf("xz reader: %w", err)
		}
		tr = tar.NewReader(xr)

	default:
		return "", fmt.Errorf("unsupported archive format: %s", ext)
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tar: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		name := filepath.Base(hdr.Name)
		if !strings.HasSuffix(name, ".db") {
			continue
		}

		outPath := filepath.Join(destDir, name)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return "", fmt.Errorf("creating %s: %w", outPath, err)
		}

		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return "", fmt.Errorf("extracting %s: %w", name, err)
		}
		if err := out.Close(); err != nil {
			return "", fmt.Errorf("closing %s: %w", name, err)
		}

		return outPath, nil
	}

	return "", fmt.Errorf("no .db file found in archive %s", archivePath)
}
