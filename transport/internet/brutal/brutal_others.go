//go:build !linux

package brutal

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

func SetBrutal(conn *net.TCPConn, sendBPS uint64) error {
	return errors.New("brutal not available on this platform")
}
