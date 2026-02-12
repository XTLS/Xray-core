package sudoku

import (
	"bufio"
	"io"
	"net"
	"sync"
)

const ioBufferSize = 32 * 1024

type tcpConn struct {
	net.Conn

	table *table
	codec *codec

	reader *bufio.Reader
	rawBuf []byte

	pending []byte
	hintBuf []byte

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewTCPConn(raw net.Conn, config *Config) (net.Conn, error) {
	t, err := getTable(config)
	if err != nil {
		return nil, err
	}

	pMin, pMax := normalizedPadding(config)
	return &tcpConn{
		Conn:    raw,
		table:   t,
		codec:   newCodec(t, pMin, pMax),
		reader:  bufio.NewReaderSize(raw, ioBufferSize),
		rawBuf:  make([]byte, ioBufferSize),
		hintBuf: make([]byte, 0, 4),
		pending: make([]byte, 0, 4096),
	}, nil
}

func (c *tcpConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	encoded, err := c.codec.encode(p)
	if err != nil {
		return 0, err
	}

	if err := writeAll(c.Conn, encoded); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if n, ok := drainPending(p, &c.pending); ok {
		return n, nil
	}

	for len(c.pending) == 0 {
		nr, rErr := c.reader.Read(c.rawBuf)
		if nr > 0 {
			var dErr error
			c.hintBuf, c.pending, dErr = decodeBytes(c.table, c.rawBuf[:nr], c.hintBuf, c.pending)
			if dErr != nil {
				return 0, dErr
			}
		}

		if rErr != nil {
			if rErr == io.EOF && len(c.pending) > 0 {
				break
			}
			return 0, rErr
		}
	}

	n, _ := drainPending(p, &c.pending)
	return n, nil
}

func drainPending(p []byte, pending *[]byte) (int, bool) {
	if len(*pending) == 0 {
		return 0, false
	}

	n := copy(p, *pending)
	if n >= len(*pending) {
		*pending = (*pending)[:0]
		return n, true
	}

	remaining := len(*pending) - n
	copy(*pending, (*pending)[n:])
	*pending = (*pending)[:remaining]
	return n, true
}

func writeAll(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
