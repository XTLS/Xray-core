//go:build !windows
// +build !windows

package platform

import (
	"flag"
	"os"
	"path/filepath"
)

func LineSeparator() string {
	return "\n"
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

// GetAssetLocation searches for `file` in the env dir, the executable dir, and certain locations
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	defPath := filepath.Join(assetPath, file)
	for _, p := range []string{
		defPath,
		filepath.Join("/usr/local/share/xray/", file),
		filepath.Join("/usr/share/xray/", file),
		filepath.Join("/opt/share/xray/", file),
	} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}

		// asset found
		return p
	}

	if testPath := TestAssetPath(file); testPath != "" {
		return testPath
	}

	// asset not found, let the caller throw out the error
	return defPath
}

// GetCertLocation searches for `file` in the env dir and the executable dir
func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}
