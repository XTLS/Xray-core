package buf

import "sync"

const SniffBufferSize = 32767

var sniffBufferPool = sync.Pool{
	New: func() interface{} {
		return NewWithSize(SniffBufferSize)
	},
}

// GetSniffBuffer returns a pooled buffer for protocol sniffing.
func GetSniffBuffer() *Buffer {
	b := sniffBufferPool.Get().(*Buffer)
	b.Clear()
	return b
}

// PutSniffBuffer returns a sniff buffer to the pool.
func PutSniffBuffer(b *Buffer) {
	if b == nil {
		return
	}
	sniffBufferPool.Put(b)
}
