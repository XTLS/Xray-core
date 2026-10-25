//go:build windows
// +build windows

package platform

import "path/filepath"

func LineSeparator() string {
	return "\r\n"
}

// GetAssetLocation searches for `file` in the env dir and the executable dir
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(GetExecutableDir)
	return filepath.Join(assetPath, file)
}

// GetCertLocation searches for `file` in the env dir and the executable dir
func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(GetExecutableDir)
	return filepath.Join(certPath, file)
}
