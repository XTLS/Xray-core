//go:build windows && !amd64 && !386

package windivert

func assetFiles() []assetFile { return nil }

func driverSysName() string { return "" }
