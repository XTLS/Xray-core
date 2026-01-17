package hysteria

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/net"
)

type interConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
}

func (i *interConn) Read(b []byte) (int, error) {
	return i.stream.Read(b)
}

func (i *interConn) Write(b []byte) (int, error) {
	return i.stream.Write(b)
}

func (i *interConn) Close() error {
	return i.stream.Close()
}

func (i *interConn) LocalAddr() net.Addr {
	return i.local
}

func (i *interConn) RemoteAddr() net.Addr {
	return i.remote
}

func (i *interConn) SetDeadline(t time.Time) error {
	return i.stream.SetDeadline(t)
}

func (i *interConn) SetReadDeadline(t time.Time) error {
	return i.stream.SetReadDeadline(t)
}

func (i *interConn) SetWriteDeadline(t time.Time) error {
	return i.stream.SetWriteDeadline(t)
}

type InterUdpConn struct {
	conn   *quic.Conn
	local  net.Addr
	remote net.Addr

	id        uint32
	ch        chan []byte
	closed    bool
	closeFunc func()
}

func (i *InterUdpConn) Read(p []byte) (int, error) {
	b, ok := <-i.ch
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, b)
	if n != len(b) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (i *InterUdpConn) Write(p []byte) (int, error) {
	binary.BigEndian.PutUint32(p, i.id)
	if err := i.conn.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (i *InterUdpConn) Close() error {
	i.closeFunc()
	return nil
}

func (i *InterUdpConn) LocalAddr() net.Addr {
	return i.local
}

func (i *InterUdpConn) RemoteAddr() net.Addr {
	return i.remote
}

func (i *InterUdpConn) SetDeadline(t time.Time) error {
	return nil
}

func (i *InterUdpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (i *InterUdpConn) SetWriteDeadline(t time.Time) error {
	return nil
}
