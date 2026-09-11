package xdns

import "sync"

var pool255 = sync.Pool{
	New: func() any {
		return make([]byte, 255)
	},
}
