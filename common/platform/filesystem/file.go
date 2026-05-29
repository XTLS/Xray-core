package filesystem

import (
	"errors"
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

func OpenAsset(file string) (io.ReadCloser, error) {
	path, _, err := getAssetFileLocation(file)
	if err != nil {
		return nil, err
	}
	return NewFileReader(path)
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
	path := platform.GetAssetLocation(local)
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, errors.New("asset is not a regular file")
	}
	return path, info, nil
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
