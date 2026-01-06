//go:build windows
// +build windows

package platform

import (
	"os"
	"path/filepath"
)

func LineSeparator() string {
	return "\r\n"
}

// GetAssetLocation searches for `file` in the env dir and the executable dir
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	defPath := filepath.Join(assetPath, file)

	for _, p := range []string{
		defPath,
		filepath.Join("..", "..", "resources", file),
	} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}

		// asset found
		return p
	}

	return defPath
}

// GetCertLocation searches for `file` in the env dir and the executable dir
func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}
