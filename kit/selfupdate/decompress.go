package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ulikunitz/xz"
)

func decompress(src io.Reader, url, cmd string) (io.Reader, error) {
	switch {
	case strings.HasSuffix(url, ".zip"):
		return decompressZip(src, cmd)
	case strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tgz"):
		return decompressTarGz(src, cmd)
	case strings.HasSuffix(url, ".gzip") || strings.HasSuffix(url, ".gz"):
		return decompressGzip(src, cmd)
	case strings.HasSuffix(url, ".tar.xz"):
		return decompressTarXz(src, cmd)
	case strings.HasSuffix(url, ".xz"):
		return decompressXz(src)
	default:
		return src, nil
	}
}

func decompressZip(src io.Reader, cmd string) (io.Reader, error) {
	// Zip format requires its file size for decompressing.
	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
	}

	r := bytes.NewReader(buf)
	z, err := zip.NewReader(r, r.Size())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
	}

	// We go over all the files in the zip archive and try to find the executable.
	for _, file := range z.File {
		_, name := filepath.Split(file.Name)
		if !file.FileInfo().IsDir() && matchExecutableName(cmd, name) {
			return file.Open()
		}
	}

	return nil, fmt.Errorf("%w (%s)", ErrReleaseBinary, cmd)
}

func decompressTarGz(src io.Reader, cmd string) (io.Reader, error) {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
	}

	return decompressTar(gz, cmd)
}

func decompressGzip(src io.Reader, cmd string) (io.Reader, error) {
	r, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
	}

	name := r.Header.Name
	if !matchExecutableName(cmd, name) {
		return nil, fmt.Errorf("%w (%s)", ErrReleaseBinary, cmd)
	}

	return r, nil
}

func decompressTarXz(src io.Reader, cmd string) (io.Reader, error) {
	xzip, err := xz.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
	}

	return decompressTar(xzip, cmd)
}

func decompressXz(src io.Reader) (io.Reader, error) {
	xzip, err := xz.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
	}

	return xzip, nil
}

func decompressTar(src io.Reader, cmd string) (io.Reader, error) {
	t := tar.NewReader(src)
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrDecompression, err)
		}

		_, name := filepath.Split(h.Name)
		if matchExecutableName(cmd, name) {
			return t, nil
		}
	}

	return nil, fmt.Errorf("%w (%s)", ErrReleaseBinary, cmd)
}

func matchExecutableName(cmd, target string) bool {
	// If it directly matches, we early return.
	if cmd == target {
		return true
	}

	// If not, we try with multiple combinations that includes the
	// OS, the architecture and different separators like '_' or '-'.
	for _, sep := range []rune{'_', '-'} {
		c := fmt.Sprintf("%s%c%s%c%s", cmd, sep, runtime.GOOS, sep, runtime.GOARCH)
		if runtime.GOOS == "windows" {
			c += ".exe"
		}

		if c == target {
			return true
		}
	}

	return false
}
