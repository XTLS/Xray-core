package outbound

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// PrepareStream retains the ordinary VLESS header/startup semantics. Vision,
// packet and reverse commands keep their existing owners until their cohorts.
func (h *Handler) PrepareStream(ctx context.Context, source *exchange.Stream, dialer internet.Dialer) (exchange.Stream, error) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	target := ob.Target
	if !target.IsValid() || target.Network != net.Network_TCP {
		return exchange.Stream{}, errors.New("invalid VLESS stream target")
	}
	account, ok := h.server.User.Account.(*vless.MemoryAccount)
	if !ok || account.Flow != "" {
		return exchange.Stream{}, proxy.ErrLegacyStreamShape
	}
	if target.Address.Family().IsDomain() && (target.Address.Domain() == "v1.mux.cool" || target.Address.Domain() == "v1.rvs.cool") {
		return exchange.Stream{}, proxy.ErrLegacyStreamShape
	}
	ob.Name, ob.CanSpliceCopy = "vless", 3
	conn, err := h.dialServer(ctx, dialer)
	if err != nil {
		return exchange.Stream{}, err
	}
	ownedConn := conn
	timeouts := h.policyManager.ForLevel(h.server.User.Level).Timeouts
	finishPreparation := exchange.GuardPreparation(ctx, func() { _ = ownedConn.Close() }, timeouts.ConnectionIdle)
	defer finishPreparation()
	fail := func(err error) (exchange.Stream, error) { _ = ownedConn.Close(); return exchange.Stream{}, err }
	if h.encryption != nil {
		conn, err = h.encryption.Handshake(conn)
		if err != nil {
			return fail(errors.New("ML-KEM-768 handshake failed").Base(err))
		}
	}
	request := &protocol.RequestHeader{Version: encoding.Version, User: h.server.User, Command: protocol.RequestCommandTCP, Address: target.Address, Port: target.Port}
	addons := &encoding.Addons{Flow: account.Flow}
	buffered := bufio.NewWriterSize(conn, 8192)
	if err := encoding.EncodeRequestHeader(buffered, request, addons); err != nil {
		return fail(err)
	}
	if initial, err := exchange.ReadInitial(source, 500*time.Millisecond, 8192); err != nil {
		return fail(err)
	} else if len(initial) > 0 {
		if _, err := buffered.Write(initial); err != nil {
			return fail(err)
		}
	}
	if err := buffered.Flush(); err != nil {
		return fail(err)
	}
	stream := exchange.Stream{Reader: &vlessResponseReader{conn: conn, request: request}, Writer: conn, Abort: func() { _ = conn.Close() }}
	if half, ok := stat.TryUnwrapStatsConn(conn).(interface{ CloseWrite() error }); ok {
		stream.CloseWrite = half.CloseWrite
	}
	if half, ok := stat.TryUnwrapStatsConn(conn).(interface{ CloseRead() error }); ok {
		stream.CloseRead = half.CloseRead
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

// Ordinary TCP has only a response header, not a body framing layer.
type vlessResponseReader struct {
	conn    io.Reader
	request *protocol.RequestHeader
	ready   bool
}

func (r *vlessResponseReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !r.ready {
		if _, err := encoding.DecodeResponseHeader(r.conn, r.request); err != nil {
			return 0, err
		}
		r.ready = true
	}
	return r.conn.Read(p)
}
