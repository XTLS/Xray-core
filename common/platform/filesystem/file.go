package filesystem

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
)

type FileReaderFunc func(path string) (io.ReadCloser, error)

var NewFileReader FileReaderFunc = func(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

func ReadFile(path string) ([]byte, error) {
	reader, err := NewFileReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return buf.ReadAllToBytes(reader)
}

func ReadAsset(file string) ([]byte, error) {
	path, _, err := getAssetFileLocation(file)
	if err != nil {
		return nil, err
	}
	return ReadFile(path)
}

func OpenAsset(file string) (io.ReadCloser, int64, error) {
	path, info, err := getAssetFileLocation(file)
	if err != nil {
		return nil, 0, err
	}
	r, err := NewFileReader(path)
	return r, info.Size(), err
}

func StatAsset(file string) (os.FileInfo, error) {
	_, info, err := getAssetFileLocation(file)
	return info, err
}

func ResolveAsset(file string) (string, error) {
	path, _, err := getAssetFileLocation(file)
	return path, err
}

func getAssetFileLocation(file string) (string, os.FileInfo, error) {
	if !filepath.IsLocal(file) || file == "." {
		return "", nil, errors.New("asset path must stay in asset directory")
	}
	local, err := filepath.Localize(file)
	if err != nil {
		return "", nil, err
	}
	return ResolveRegularFile(platform.GetAssetLocation(local))
}

func ReadCert(file string) ([]byte, error) {
	if filepath.IsAbs(file) {
		return ReadFile(file)
	}
	return ReadFile(platform.GetCertLocation(file))
}

func CopyFile(dst string, src string) error {
	bytes, err := ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(bytes)
	return err
}

// ResolveLuaFile finds a local .lua script and returns its resolved absolute path.
// Relative paths: XRAY_LOCATION_CONFDIR > XRAY_LOCATION_CONFIG > working dir > executable dir.
func ResolveLuaFile(path string) (resolved string, err error) {
	if filepath.IsAbs(path) {
		resolved, _, err = ResolveRegularFile(path)
	} else {
		for _, dir := range []string{
			platform.GetConfDirPath(),
			platform.NewEnvFlag(platform.ConfigLocation).GetValue(func() string { return "" }),
			".",
			platform.GetExecutableDir(),
		} {
			if dir != "" {
				if resolved, _, err = ResolveRegularFile(filepath.Join(dir, path)); err == nil || !errors.Is(err, os.ErrNotExist) {
					break
				}
			}
		}
	}
	if err != nil {
		return "", err
	}
	if filepath.Ext(resolved) != ".lua" {
		return "", errors.New("Lua file extension must be .lua")
	}
	return resolved, nil
}

// ResolveRegularFile returns an absolute path and metadata of a regular file.
// File symlinks are resolved when possible; otherwise the original path is kept.
func ResolveRegularFile(path string) (string, os.FileInfo, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve file path: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, fmt.Errorf("failed to inspect file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Best effort: EvalSymlinks may fail when junctions are involved.
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			path = resolved
		}
		info, err = os.Stat(path)
		if err != nil {
			return "", nil, fmt.Errorf("failed to inspect file %q: %w", path, err)
		}
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("file is not a regular file: %s", path)
	}
	// Hard links are not handled.
	return path, info, nil
}
