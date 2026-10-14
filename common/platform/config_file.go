package platform

import (
	"io"
	"os"
	"path/filepath"
)

type configFile struct {
	path string
	info os.FileInfo
}

var configFiles []configFile

// ReadConfigFile reads a config source and records local regular files.
func ReadConfigFile(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	path := ""
	if info.Mode().IsRegular() && file != os.Stdin {
		path, err = filepath.Abs(file.Name())
		if err != nil {
			return nil, err
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		configFiles = append(configFiles, configFile{path: path, info: info})
	}
	return data, nil
}

func isConfigFile(path string, info os.FileInfo) bool {
	for _, file := range configFiles {
		if file.path == path || os.SameFile(file.info, info) {
			return true
		}
	}
	return false
}
