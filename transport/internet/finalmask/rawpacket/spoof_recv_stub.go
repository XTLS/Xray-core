//go:build !darwin && !freebsd && !linux && !(windows && (amd64 || 386))

package rawpacket

import "fmt"

type rawRecvSocket struct{}

func newRawRecvSocket(proto uint8, bufSize int) (*rawRecvSocket, error) {
	return nil, fmt.Errorf("rawpacket: raw sockets not supported on this platform")
}

func (r *rawRecvSocket) recv() ([]byte, bool) {
	return nil, false
}

func (r *rawRecvSocket) closed() bool {
	return true
}

func (r *rawRecvSocket) close() {}
