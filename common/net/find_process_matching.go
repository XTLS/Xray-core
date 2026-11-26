//go:build !linux || android

package net

// FindProcessMatching is FindProcess for a caller that needs only the processes that accept returns true for.
// If accept returns false for the owner of the socket, the error is ErrProcessNotMatched.
// Only Linux uses accept to make the lookup faster: the other platforms get the owner from the system.
func FindProcessMatching(network, srcIP string, srcPort uint16, destIP string, destPort uint16, accept func(pid int, name, absPath string) bool) (int, string, string, error) {
	pid, name, absPath, err := FindProcess(network, srcIP, srcPort, destIP, destPort)
	if err != nil {
		return pid, name, absPath, err
	}
	if accept != nil && !accept(pid, name, absPath) {
		return 0, "", "", ErrProcessNotMatched
	}
	return pid, name, absPath, nil
}
