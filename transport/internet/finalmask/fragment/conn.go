package fragment

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

type fragmentConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool
}

func NewConnClient(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	conn := &fragmentConn{
		Conn:   raw,
		config: c,

		server: server,
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	return NewConnClient(c, raw, server)
}

func (c *fragmentConn) TcpMaskConn() {}

func (c *fragmentConn) RawConn() net.Conn {
	return c.Conn
}

func (c *fragmentConn) Splice() bool {
	if c.server {
		return false
	}
	return true
}

// lengthForSegment returns the length range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) lengthForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.LengthsMin) {
		segIdx = len(c.config.LengthsMin) - 1
	}
	return c.config.LengthsMin[segIdx], c.config.LengthsMax[segIdx]
}

// delayForSegment returns the delay range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) delayForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.DelaysMin) {
		segIdx = len(c.config.DelaysMin) - 1
	}
	return c.config.DelaysMin[segIdx], c.config.DelaysMax[segIdx]
}

// mergeTlsHelloSegments returns true only when delays has exactly one zero entry.
func (c *fragmentConn) mergeTlsHelloSegments() bool {
	return len(c.config.DelaysMax) == 1 && c.config.DelaysMax[0] == 0
}

func (c *fragmentConn) Write(p []byte) (n int, err error) {
	c.count++

	if c.config.PacketsFrom == 0 && c.config.PacketsTo == 1 {
		if c.count != 1 || len(p) <= 5 || p[0] != 22 {
			return c.Conn.Write(p)
		}
		recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
		if len(p) < recordLen {
			return c.Conn.Write(p)
		}
		data := p[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		mergeHello := c.mergeTlsHelloSegments()
		maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
		var splitNum int64
		for from := 0; ; {
			lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
			to := from + int(crypto.RandBetween(lengthMin, lengthMax))
			if to > len(data) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], p)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if mergeHello {
				hello = append(hello, buff[:5+l]...)
			} else {
				delayMin, delayMax := c.delayForSegment(int(splitNum))
				_, err := c.Conn.Write(buff[:5+l])
				if delayMax > 0 {
					time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
				}
				if err != nil {
					return 0, err
				}
			}
			splitNum++
			if from == len(data) {
				if len(hello) > 0 {
					_, err := c.Conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(p) > recordLen {
					n, err := c.Conn.Write(p[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(p), nil
			}
		}
	}

	if c.config.PacketsFrom != 0 && (c.count < uint64(c.config.PacketsFrom) || c.count > uint64(c.config.PacketsTo)) {
		return c.Conn.Write(p)
	}
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	var splitNum int64
	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(crypto.RandBetween(lengthMin, lengthMax))
		if to > len(p) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		delayMin, delayMax := c.delayForSegment(int(splitNum))
		if delayMax > 0 {
			time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
		}
		splitNum++
		if from >= len(p) {
			return from, nil
		}
	}
}
