//go:build linux

package wireguard

import (
	"os"
	"os/exec"
	"strings"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func IsLinux() bool {
	return true
}

func CheckUnixKernelTunDeviceEnabled() bool {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return false
	}
	return true
}

func CheckUnixKernelNetAdminCapEnabled() bool {
	orig := cap.GetProc()
	c, err := orig.Dup()
	if err != nil {
		return false
	}
	on, _ := c.GetFlag(cap.Effective, cap.NET_ADMIN)
	return on
}

func CheckUnixKernelIPv4SrcValidMarkEnabled() bool {
	buf, _ := os.ReadFile("/proc/sys/net/ipv4/conf/all/src_valid_mark")
	value := strings.TrimSpace(string(buf))
	return value == "1"
}

func CheckUnixKernelIPv6IsEnabled() bool {
	buf, _ := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	value := strings.TrimSpace(string(buf))
	return value == "0"
}

// CheckUnixKernelTunSupported returns true if kernel tun is supported.
// 1. check if the current process has CAP_NET_ADMIN capability
// 2. check if /proc/sys/net/ipv4/conf/all/src_valid_mark exists and is set to 1
// 3. check if iptables is available
func CheckUnixKernelTunSupported() bool {
	if !CheckUnixKernelTunDeviceEnabled() || !CheckUnixKernelNetAdminCapEnabled() {
		return false
	}
	outCmd := exec.Command("sh", "-c", "command -v iptables")
	outBuffer, err := outCmd.CombinedOutput()
	if err != nil {
		return false
	}
	iptablesPath := strings.TrimSpace(string(outBuffer))
	return iptablesPath != ""
}
