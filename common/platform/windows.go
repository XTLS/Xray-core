//go:build windows
// +build windows

package platform

import "path/filepath"

func ExpandEnv(s string) string {
	// TODO
	return s
}

func LineSeparator() string {
	return "\r\n"
}

func GetToolLocation(file string) string {
	toolPath := NewEnvFlag(ToolLocation).GetValue(getExecutableDir)
	return filepath.Join(toolPath, file+".exe")
}

// GetAssetLocation searches for `file` in the executable dir
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	return filepath.Join(assetPath, file)
}

func GetCertificateLocation(file string) string {
	certificatePath := NewEnvFlag(CertificateLocation).GetValue(getExecutableDir)
	return filepath.Join(certificatePath, file)
}
