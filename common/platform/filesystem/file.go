package filesystem

import (
	"io"
	"io/ioutil"

	"github.com/xtls/xray-core/common/platform"
)

type FileReaderFunc func(path string) (io.ReadCloser, error)

func ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func ReadAsset(file string) ([]byte, error) {
	return ReadFile(platform.GetAssetLocation(file))
}

func CopyFile(dst string, src string) error {
	bytes, err := ReadFile(src)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(dst, bytes, 0644); err != nil {
		return err
	}
	return nil
}
