// +build !confonly

package quic

import (
	"sync"

	"github.com/xtls/xray-core/v1/common/bytespool"
)

var pool *sync.Pool

func init() {
	pool = bytespool.GetPool(2048)
}

func getBuffer() []byte {
	return pool.Get().([]byte)
}

func putBuffer(p []byte) {
	pool.Put(p)
}
