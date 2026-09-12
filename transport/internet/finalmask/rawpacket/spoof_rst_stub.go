//go:build !linux

package rawpacket

import "log"

// suppressKernelRST is a no-op off Linux: the kernel only emits RST
// replies on the host that owns the port, and raw sockets are privileged
// there anyway. Return false so the caller knows no rule is managed.
func suppressKernelRST(port uint16) bool {
	if port != 0 {
		log.Printf("[rawpacket] kernel RST suppression only supported on linux (port %d left as-is)", port)
	}
	return false
}

func restoreKernelRST(port uint16, managed bool) {}
