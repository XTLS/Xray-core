package quic

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

var MaxIncomingStreams = 2
var currentStream = 0

type interConn struct {
	ctx         context.Context
	quicConn    quic.Connection // small udp packet can be sent with Datagram directly 
	streams     []quic.Stream	// other packets can be sent via steam, it offer mux, reliability, fragmentation and ordering 
	readChannel chan readResult
	reader      buf.MultiBufferContainer
	done        *done.Instance
	local       net.Addr
	remote      net.Addr
}

type readResult struct {
	buffer []byte
	err    error 
}

func NewConnInitReader(ctx context.Context, quicConn quic.Connection, done *done.Instance, remote net.Addr) *interConn {
	c := &interConn{
		ctx:         ctx,
		quicConn:    quicConn,
		readChannel: make(chan readResult),
		reader:      buf.MultiBufferContainer{},
		done:        done,
		local:       quicConn.LocalAddr(),
		remote:      remote,
	}
	go func() {
		for {
			received, e := c.quicConn.ReceiveDatagram(c.ctx)
			errors.LogInfo(c.ctx, "Read ReceiveDatagram ", len(received))
			c.readChannel <- readResult{buffer: received, err: e}
		}
	}()
	go c.acceptStreams()
	return c
}

func (c *interConn) acceptStreams() {
	for {
		stream, err := c.quicConn.AcceptStream(context.Background())
		errors.LogInfo(c.ctx, "Read AcceptStream ", err)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to accept stream")
			select {
			case <-c.quicConn.Context().Done():
				return
			case <-c.done.Wait():
				if err := c.quicConn.CloseWithError(0, ""); err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to close connection")
				}
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}
		go func() {
			for {
				received := make([]byte, buf.Size)
				i, e := stream.Read(received)
				errors.LogInfo(c.ctx, "Read stream ", i)
				c.readChannel <- readResult{buffer: received[:i], err: e}
			}
		}()
		c.streams = append(c.streams, stream)
	}
}

func (c *interConn) Read(b []byte) (int, error) {	
	if c.reader.MultiBuffer.Len() > 0 {
		return c.reader.Read(b)
	}
	received := <- c.readChannel
	if received.err != nil {
		return 0, received.err
	}
	buffer := buf.New()
	buffer.Write(received.buffer)
	c.reader.MultiBuffer = append(c.reader.MultiBuffer, buffer)
	errors.LogInfo(c.ctx, "Read copy ", len(received.buffer))
	return c.reader.Read(b)
}

func (c *interConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *interConn) Write(b []byte) (int, error) {
	if len(b) > 1240 { // TODO: why quic-go increase internal MTU causing packet loss?
		if len(c.streams) < MaxIncomingStreams {
			stream, err := c.quicConn.OpenStream()
			errors.LogInfo(c.ctx, "Write OpenStream ", err)
			if err == nil {
				c.streams = append(c.streams, stream)
			} else {
				errors.LogInfoInner(c.ctx, err, "failed to openStream: ")
			}
		}
		currentStream++;
		if currentStream > len(c.streams) - 1 {
			currentStream = 0;
		}
		errors.LogInfo(c.ctx, "Write stream ", len(b), currentStream, len(c.streams))
		return c.streams[currentStream].Write(b)
	}
	var err = c.quicConn.SendDatagram(b)
	errors.LogInfo(c.ctx, "Write SendDatagram ", len(b), err)
	if _, ok := err.(*quic.DatagramTooLargeError); ok {
		if len(c.streams) < MaxIncomingStreams {
			stream, err := c.quicConn.OpenStream()
			errors.LogInfo(c.ctx, "Write OpenStream ", err)
			if err == nil {
				c.streams = append(c.streams, stream)
			} else {
				errors.LogInfoInner(c.ctx, err, "failed to openStream: ")
			}
		}
		currentStream++;
		if currentStream > len(c.streams) - 1 {
			currentStream = 0;
		}
		errors.LogInfo(c.ctx, "Write stream ", len(b), currentStream, len(c.streams))
		return c.streams[currentStream].Write(b)
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *interConn) Close() error {
	var err error
	for _, s := range c.streams {
		e := s.Close()
		if e != nil {
			err = e
		}
	}
	return err
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *interConn) SetDeadline(t time.Time) error {
	var err error
	for _, s := range c.streams {
		e := s.SetDeadline(t)
		if e != nil {
			err = e
		}
	}
	return err
}

func (c *interConn) SetReadDeadline(t time.Time) error {
	var err error
	for _, s := range c.streams {
		e := s.SetReadDeadline(t)
		if e != nil {
			err = e
		}
	}
	return err
}

func (c *interConn) SetWriteDeadline(t time.Time) error {
	var err error
	for _, s := range c.streams {
		e := s.SetWriteDeadline(t)
		if e != nil {
			err = e
		}
	}
	return err
}
