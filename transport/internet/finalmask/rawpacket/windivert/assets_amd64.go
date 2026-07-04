//go:build windows && amd64

package windivert

import _ "embed"

//go:embed assets/WinDivert64.sys
var sysBytes []byte

func assetFiles() []assetFile {
	return []assetFile{{"WinDivert64.sys", sysBytes}}
}

func driverSysName() string { return "WinDivert64.sys" }
