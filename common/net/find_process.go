package net

import "sync/atomic"

// ProcessFinder finds the process that owns a local connection. It returns the process ID, the
// process name and the absolute path of the executable file, as FindProcess does.
type ProcessFinder func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)

var processFinder atomic.Pointer[ProcessFinder]

// RegisterProcessFinder replaces the process lookup of the platform with f. An application that
// embeds Xray-core can register a finder that keeps a cache of the socket tables. Xray-core can
// call f from many goroutines at the same time. Thus f must be safe for concurrent use. On
// Android, FindProcess calls f instead of the finder of RegisterAndroidProcessFinder. A nil
// finder restores the lookup of the platform.
func RegisterProcessFinder(f ProcessFinder) {
	if f == nil {
		processFinder.Store(nil)
		return
	}
	processFinder.Store(&f)
}

// FindProcess finds the process that owns the local connection from srcIP:srcPort to
// destIP:destPort. If RegisterProcessFinder set a finder, FindProcess calls that finder.
func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (PID int, Name string, AbsolutePath string, err error) {
	if finder := processFinder.Load(); finder != nil {
		return (*finder)(network, srcIP, srcPort, destIP, destPort)
	}
	return findProcess(network, srcIP, srcPort, destIP, destPort)
}
