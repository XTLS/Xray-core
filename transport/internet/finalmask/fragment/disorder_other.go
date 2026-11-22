//go:build plan9 || js

package fragment

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
)

func setTTL(conn net.Conn, ttl int) error {
	return errors.New("fragment: disorder modes are not supported on this platform")
}

func getTTL(conn net.Conn) (int, error) {
	return 0, errors.New("fragment: disorder modes are not supported on this platform")
}

func sendOOB(conn net.Conn, b []byte) (int, error) {
	return 0, errors.New("fragment: disorder modes are not supported on this platform")
}

func enableNoDelay(conn net.Conn) error {
	return nil
}
