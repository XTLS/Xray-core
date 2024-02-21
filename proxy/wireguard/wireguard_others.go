//go:build !linux || android

package wireguard

func IsLinux() bool {
	return false
}

func CheckUnixKernelTunDeviceEnabled() bool {
	return true
}

func CheckUnixKernelNetAdminCapEnabled() bool {
	return false
}

func CheckUnixKernelIPv6IsEnabled() bool {
	return false
}

func CheckUnixKernelIPv4SrcValidMarkEnabled() bool {
	return false
}

func CheckUnixKernelTunSupported() bool {
	return false
}

func CheckUnixWireGuardKernelModuleEnabled() bool {
	return false
}
