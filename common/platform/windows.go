//go:build windows
// +build windows

package platform

import (
	"flag"
	"os"
	"path/filepath"
)

func LineSeparator() string {
	return "\r\n"
}

func TestAssetPath(file string) string {
	if flag.Lookup("test.v") != nil {
		path := filepath.Join("..", "..", "resources", file)
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return ""
		}
		if err != nil {
			return ""
		}
		return path
	}
	return ""
}

// GetAssetLocation searches for `file` in the env dir and the executable dir
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)

	if testPath := TestAssetPath(file); testPath != "" {
		return testPath
	}

	return filepath.Join(assetPath, file)
}

// GetCertLocation searches for `file` in the env dir and the executable dir
func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}
