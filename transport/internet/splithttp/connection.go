package splithttp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrBadRespCode = errors.New("bad response code")
	BadCodes       = map[int]struct{}{502: {}, 503: {}, 505: {}}
)

// Optimised to read only response codes
// Reads response codes until getting EOF or error
func ConnHttpReadRespCodes(conn net.Conn) (codes []int, err error) {
	buff := &bytes.Buffer{}
	if _, err = io.Copy(buff, conn); err != nil {
		return nil, err
	}

	for {
		var line string
		line, err = buff.ReadString('\n')
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return codes, err
		}

		if strings.HasPrefix(line, "HTTP/") {
			parts := strings.Split(line, " ")
			if len(parts) < 2 {
				continue
			}
			if code, err := strconv.Atoi(parts[1]); err == nil {
				codes = append(codes, code)
			}
		}

		for {
			line, err := buff.ReadString('\n')
			if err != nil && err == io.EOF {
				break
			} else if err != nil {
				return codes, err
			}
			if line == "\r\n" || line == "\n" {
				break // End of headers
			}
		}
	}

	return codes, err
}

// ConnHolder implements the net.Conn interface
// adds logic of reading the responses before writing the next request
// Used as a bugfix for HTTP1.1
type ConnHolder struct {
	ResponsesToRead int
	Conn            net.Conn
}

func NewConnHolder(conn net.Conn) *ConnHolder {
	return &ConnHolder{
		ResponsesToRead: 0,
		Conn:            conn,
	}
}

func (ch *ConnHolder) Read(b []byte) (n int, err error) {
	n, err = ch.Conn.Read(b)
	if err != nil {
		return n, err
	}
	ch.ResponsesToRead += 1
	return n, err
}

func (ch *ConnHolder) Write(b []byte) (n int, err error) {
	if ch.ResponsesToRead > 0 {
		codes, err := ConnHttpReadRespCodes(ch)
		if err != nil {
			return len(b), err
		}
		ch.ResponsesToRead -= len(codes)
		for _, code := range codes {
			if _, isBadCode := BadCodes[code]; isBadCode {
				return len(b), errors.Join(ErrBadRespCode, fmt.Errorf("get response code %d", code))
			}
		}
	}
	return ch.Conn.Write(b)
}

// Just calling the same method on the Connection to implement interface
func (ch *ConnHolder) Close() error                       { return ch.Conn.Close() }
func (ch *ConnHolder) LocalAddr() net.Addr                { return ch.Conn.LocalAddr() }
func (ch *ConnHolder) RemoteAddr() net.Addr               { return ch.Conn.RemoteAddr() }
func (ch *ConnHolder) SetDeadline(t time.Time) error      { return ch.Conn.SetDeadline(t) }
func (ch *ConnHolder) SetReadDeadline(t time.Time) error  { return ch.Conn.SetReadDeadline(t) }
func (ch *ConnHolder) SetWriteDeadline(t time.Time) error { return ch.Conn.SetWriteDeadline(t) }

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *splitConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *splitConn) Close() error {
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
