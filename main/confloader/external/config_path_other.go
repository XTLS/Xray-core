//go:build !windows

package external

import (
	"os"
	"path/filepath"
)

func configFilePath(file *os.File) (string, error) {
	path, err := filepath.Abs(file.Name())
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}
