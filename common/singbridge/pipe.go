package singbridge

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/bufio"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

func CopyConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, serverConn net.Conn) error {
	conn := &PipeConnWrapper{
		W:    link.Writer,
		Conn: inboundConn,
	}
	if ir, ok := link.Reader.(io.Reader); ok {
		conn.R = ir
	} else {
		conn.R = &buf.BufferedReader{Reader: link.Reader}
	}
	cancel := func() {
		common.Interrupt(conn.R)
	}
	conn.T = signal.CancelAfterInactivity(ctx, cancel, 300*time.Second)
	return ReturnError(bufio.CopyConn(ctx, conn, serverConn))
}

type PipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn

	// A simple patch to avoid goroutine leak since sing infra cannot awake read block by write err
	T *signal.ActivityTimer
}

func (w *PipeConnWrapper) Close() error {
	return nil
}

func (w *PipeConnWrapper) Read(b []byte) (n int, err error) {
	w.T.Update()
	return w.R.Read(b)
}

func (w *PipeConnWrapper) Write(p []byte) (n int, err error) {
	w.T.Update()
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}
