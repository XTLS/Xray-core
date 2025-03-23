//go:build !windows
// +build !windows

package platform

import (
	"os"
	"path/filepath"
)

func ExpandEnv(s string) string {
	return os.ExpandEnv(s)
}

func LineSeparator() string {
	return "\n"
}

func GetToolLocation(file string) string {
	toolPath := NewEnvFlag(ToolLocation).GetValue(getExecutableDir)
	return filepath.Join(toolPath, file)
}

// GetAssetLocation searches for `file` in certain locations
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

	// asset not found, let the caller throw out the error
	return defPath
}

func GetCertificateLocation(file string) string {
	certificatePath := NewEnvFlag(CertificateLocation).GetValue(getExecutableDir)
	return filepath.Join(certificatePath, file)
}
