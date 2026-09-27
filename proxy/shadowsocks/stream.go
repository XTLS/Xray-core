package shadowsocks

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func (c *Client) dialServer(ctx context.Context, dialer internet.Dialer, network net.Network) (stat.Connection, error) {
	dest := c.server.Destination
	dest.Network = network
	var conn stat.Connection
	err := retry.ExponentialBackoffContext(ctx, 5, 100).On(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		conn, err = dialer.Dial(ctx, dest)
		return err
	})
	if conn != nil && ctx.Err() != nil {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	return conn, err
}

func (c *Client) requestFor(destination net.Destination) (*protocol.RequestHeader, error) {
	user := c.server.User
	if _, ok := user.Account.(*MemoryAccount); !ok {
		return nil, errors.New("user account is not valid")
	}
	request := &protocol.RequestHeader{Version: Version, Address: destination.Address, Port: destination.Port, User: user}
	if destination.Network == net.Network_TCP {
		request.Command = protocol.RequestCommandTCP
	} else {
		request.Command = protocol.RequestCommandUDP
	}
	return request, nil
}

// PrepareStream keeps cipher framing local. The old Process and this path use
// the same destination dial and request construction; no Link enters execution.
func (c *Client) PrepareStream(ctx context.Context, source *exchange.Stream, dialer internet.Dialer) (exchange.Stream, error) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() || ob.Target.Network != net.Network_TCP {
		return exchange.Stream{}, errors.New("invalid Shadowsocks stream target")
	}
	ob.Name, ob.CanSpliceCopy = "shadowsocks", 3
	request, err := c.requestFor(ob.Target)
	if err != nil {
		return exchange.Stream{}, err
	}
	conn, err := c.dialServer(ctx, dialer, net.Network_TCP)
	if err != nil {
		return exchange.Stream{}, errors.New("failed to find an available destination").Base(err)
	}
	ownedConn := conn
	timeouts := c.policyManager.ForLevel(c.server.User.Level).Timeouts
	finishPreparation := exchange.GuardPreparation(ctx, func() { _ = ownedConn.Close() }, timeouts.ConnectionIdle)
	defer finishPreparation()
	fail := func(err error) (exchange.Stream, error) { _ = ownedConn.Close(); return exchange.Stream{}, err }
	buffered := buf.NewBufferedWriter(&buf.SequentialWriter{Writer: conn})
	bodyWriter, err := WriteTCPRequest(request, buffered)
	if err != nil {
		return fail(err)
	}
	if initial, err := exchange.ReadInitial(source, 100*time.Millisecond, buf.Size); err != nil {
		return fail(err)
	} else if len(initial) > 0 {
		if err := bodyWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(initial)}); err != nil {
			return fail(err)
		}
	}
	if err := buffered.SetBuffered(false); err != nil {
		return fail(err)
	}
	response := &ssResponseReader{conn: conn, user: request.User}
	stream := exchange.Stream{
		Reader: response,
		Writer: &ssBodyWriter{writer: bodyWriter},
		Abort:  func() { _ = conn.Close() },
	}
	if half, ok := stat.TryUnwrapStatsConn(conn).(interface{ CloseWrite() error }); ok {
		stream.CloseWrite = half.CloseWrite
	}
	if half, ok := stat.TryUnwrapStatsConn(conn).(interface{ CloseRead() error }); ok {
		stream.CloseRead = func() error { response.release(); return half.CloseRead() }
	}
	if stream.CloseRead == nil {
		stream.CloseRead = func() error { response.release(); return nil }
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := finishPreparation(); err != nil {
		return fail(err)
	}
	stream.Policy = &timeouts
	return stream, nil
}

// ssBodyWriter is a codec-local byte projection. Authentication framing still
// owns its buffers and returns only after the complete accepted frame write.
type ssBodyWriter struct{ writer buf.Writer }

func (w *ssBodyWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(p)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

type ssResponseReader struct {
	conn    io.Reader
	user    *protocol.MemoryUser
	reader  buf.Reader
	current buf.MultiBuffer
	pending error
}

func (r *ssResponseReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.reader == nil {
		reader, err := ReadTCPResponse(r.user, r.conn)
		if err != nil {
			return 0, err
		}
		r.reader = reader
	}
	for len(r.current) == 0 {
		if r.pending != nil {
			err := r.pending
			r.pending = nil
			return 0, err
		}
		mb, err := r.reader.ReadMultiBuffer()
		r.current, r.pending = mb, err
		for len(r.current) > 0 && r.current[0].IsEmpty() {
			r.current[0].Release()
			r.current = r.current[1:]
		}
		if len(mb) == 0 && err == nil {
			continue
		}
	}
	n, err := r.current[0].Read(p)
	if r.current[0].IsEmpty() {
		r.current[0].Release()
		r.current = r.current[1:]
	}
	if err == io.EOF {
		err = nil
	}
	if len(r.current) == 0 && r.pending != nil && err == nil {
		err = r.pending
		r.pending = nil
	}
	return n, err
}

func (r *ssResponseReader) release() { buf.ReleaseMulti(r.current); r.current = nil }
