package proxy

import (
	"net"
	"sync"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/features/stats"
)

// spliceProgress keeps traffic statistics up to date while a spliced
// connection is running. TCPConn.ReadFrom moves data entirely in the kernel
// and returns only when the connection ends, so updating the counters after it
// returns would leave long-lived connections invisible until they close.
type spliceProgress struct {
	conn         net.Conn
	readCounter  stats.Counter
	writeCounter stats.Counter
	statWriter   *dispatcher.SizeStatWriter

	mu      sync.Mutex
	base    int64
	counted int64
}

func (p *spliceProgress) add(n int64) {
	if n <= 0 {
		return
	}
	if p.readCounter != nil {
		p.readCounter.Add(n)
	}
	if p.writeCounter != nil {
		p.writeCounter.Add(n)
	}
	if p.statWriter != nil {
		p.statWriter.Counter.Add(n)
	}
}

// sample reports the bytes received since the previous sample.
func (p *spliceProgress) sample() {
	cur, ok := tcpBytesReceived(p.conn)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if cur <= p.base+p.counted {
		return
	}
	delta := cur - p.base - p.counted
	p.counted += delta
	p.add(delta)
}

// finish reconciles the sampled total with the exact number of bytes copied.
func (p *spliceProgress) finish(total int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if delta := total - p.counted; delta > 0 {
		p.counted = total
		p.add(delta)
	}
}
