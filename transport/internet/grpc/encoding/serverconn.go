// +build !confonly

package encoding

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"
)

type ServerConn struct {
	server GRPCService_TunServer
	reader io.Reader
	over   context.CancelFunc
}

func (s *ServerConn) Read(b []byte) (n int, err error) {
	if s.reader == nil {
		h, err := s.server.Recv()
		if err != nil {
			return 0, newError("unable to read from gRPC tunnel").Base(err)
		}
		s.reader = bytes.NewReader(h.Data)
	}
	n, err = s.reader.Read(b)
	if err == io.EOF {
		s.reader = nil
		return n, nil
	}
	return n, err
}

func (s *ServerConn) Write(b []byte) (n int, err error) {
	err = s.server.Send(&Hunk{Data: b[:]})
	if err != nil {
		return 0, newError("Unable to send data over gRPC").Base(err)
	}
	return len(b), nil
}

func (s *ServerConn) Close() error {
	s.over()
	return nil
}

func (s ServerConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (s ServerConn) RemoteAddr() net.Addr {
	newError("gRPC transport do not support get remote address").AtWarning().WriteToLog()
	return &net.UnixAddr{
		Name: "@placeholder",
		Net:  "unix",
	}
}

func (s ServerConn) SetDeadline(t time.Time) error {
	return nil
}

func (s ServerConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s ServerConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func NewServerConn(server GRPCService_TunServer, over context.CancelFunc) *ServerConn {
	return &ServerConn{
		server: server,
		reader: nil,
		over:   over,
	}
}
