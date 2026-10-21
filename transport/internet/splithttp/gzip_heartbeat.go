package splithttp

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func acceptsGzip(acceptEncoding string) bool {
	gzipQ, anyQ := -1.0, -1.0
	for _, part := range strings.Split(acceptEncoding, ",") {
		coding, params, _ := strings.Cut(part, ";")
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			if v, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(param)), "q="); ok {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
					q = f
				} else {
					q = 0
				}
			}
		}
		switch strings.ToLower(strings.TrimSpace(coding)) {
		case "gzip", "x-gzip":
			gzipQ = max(gzipQ, q)
		case "*":
			anyQ = q
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return anyQ > 0
}

// gzipWriter writes a gzip stream of stored (uncompressed) deflate blocks,
// without compress/flate's per-writer buffers. An empty block makes decoders
// emit the data received so far, and also serves as the heartbeat.
type gzipWriter struct {
	w    io.Writer
	crc  uint32
	size uint32
	buf  [8]byte
}

func (g *gzipWriter) write(b []byte) error {
	n, err := g.w.Write(b)
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	return err
}

func (g *gzipWriter) block(final bool, b []byte) error {
	g.buf[0] = 0
	if final {
		g.buf[0] = 1
	}
	binary.LittleEndian.PutUint16(g.buf[1:], uint16(len(b)))
	binary.LittleEndian.PutUint16(g.buf[3:], ^uint16(len(b)))
	if err := g.write(g.buf[:5]); err != nil {
		return err
	}
	if len(b) > 0 {
		return g.write(b)
	}
	return nil
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), 0xffff)]
		if err := g.block(false, chunk); err != nil {
			return n, err
		}
		g.crc = crc32.Update(g.crc, crc32.IEEETable, chunk)
		g.size += uint32(len(chunk))
		n += len(chunk)
		b = b[len(chunk):]
	}
	return n, g.block(false, nil)
}

func (g *gzipWriter) Close() error {
	if err := g.block(true, nil); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(g.buf[:4], g.crc)
	binary.LittleEndian.PutUint32(g.buf[4:], g.size)
	return g.write(g.buf[:])
}

func (c *httpServerConn) enableGzip() error {
	c.Lock()
	defer c.Unlock()
	c.gz = &gzipWriter{w: c.ResponseWriter}
	c.lastWrite = time.Now()
	if err := c.gz.write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff}); err != nil {
		return err
	}
	c.ResponseWriter.(http.Flusher).Flush()
	return nil
}

// caller must hold the lock
func (c *httpServerConn) writeGzip(b []byte) (int, error) {
	if c.gzFinished {
		return 0, io.ErrClosedPipe
	}
	n, err := c.gz.Write(b)
	if err == nil {
		c.ResponseWriter.(http.Flusher).Flush()
		c.lastWrite = time.Now()
	}
	return n, err
}

func (c *httpServerConn) gzipHeartbeat(interval *RangeConfig) {
	timer := time.NewTimer(time.Duration(interval.rand()) * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-c.Wait():
			return
		case <-timer.C:
		}
		d := time.Duration(interval.rand()) * time.Millisecond
		c.Lock()
		if c.Done() || c.gzFinished {
			c.Unlock()
			return
		}
		if idle := time.Since(c.lastWrite); idle >= d {
			if err := c.gz.block(false, nil); err != nil {
				c.Instance.Close()
				c.Unlock()
				return
			}
			c.ResponseWriter.(http.Flusher).Flush()
			c.lastWrite = time.Now()
		} else {
			d -= idle
		}
		c.Unlock()
		timer.Reset(d)
	}
}

// writes the gzip trailer, must be called before ServeHTTP returns
func (c *httpServerConn) finishGzip() {
	c.Lock()
	defer c.Unlock()
	if c.gz == nil || c.gzFinished {
		return
	}
	c.gzFinished = true
	if c.gz.Close() == nil {
		c.ResponseWriter.(http.Flusher).Flush()
	}
}
