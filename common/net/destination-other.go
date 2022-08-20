//go:build !darwin

package net

// OriginalDst uses ioctl to read original destination from /dev/pf
func OriginalDst(conn Conn) (Destination, error) {
	return Destination{}, newError("This platform is not supported")
}
