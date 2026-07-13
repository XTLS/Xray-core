package splithttp

import (
	goerrors "errors"
	"io"
	"net"
	"time"

	"golang.org/x/net/http2"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *splitConn) Read(b []byte) (int, error) {
	n, err := c.reader.Read(b)
	// A peer-initiated HTTP/2 stream reset (e.g. "stream error: stream ID N;
	// INTERNAL_ERROR; received from peer") means the remote closed the downlink
	// carrying this XHTTP session. Surface it as io.EOF so the proxy treats it
	// as a normal connection teardown rather than logging it as an outbound
	// failure. Only the HTTP/2 downlink yields http2.StreamError; the HTTP/1.1
	// and HTTP/3 paths are unaffected.
	if err != nil {
		var h2StreamErr http2.StreamError
		if goerrors.As(err, &h2StreamErr) {
			err = io.EOF
		}
	}
	return n, err
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}
