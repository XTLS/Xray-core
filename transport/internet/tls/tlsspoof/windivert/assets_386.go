//go:build windows && 386

package windivert

import _ "embed"

//go:embed assets/WinDivert32.sys
var sysBytes []byte

func assetFiles() []assetFile {
	return []assetFile{{"WinDivert32.sys", sysBytes}}
}

func driverSysName() string { return "WinDivert32.sys" }
