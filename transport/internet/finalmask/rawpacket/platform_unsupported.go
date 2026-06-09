//go:build !darwin && !freebsd && !linux && !(windows && (amd64 || 386))

package rawpacket

const PlatformSupported = false
