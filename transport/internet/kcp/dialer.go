package kcp

import (
	"context"
	"io"
	"sync/atomic"

	"github.com/hosemorinho412/xray-core/common"
	"github.com/hosemorinho412/xray-core/common/buf"
	"github.com/hosemorinho412/xray-core/common/dice"
	"github.com/hosemorinho412/xray-core/common/errors"
	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/transport/internet"
	"github.com/hosemorinho412/xray-core/transport/internet/stat"
	"github.com/hosemorinho412/xray-core/transport/internet/tls"
)

var globalConv = uint32(dice.RollUint16())

func fetchInput(_ context.Context, input io.Reader, reader PacketReader, conn *Connection) {
	cache := make(chan *buf.Buffer, 1024)
	go func() {
		for {
			payload := buf.New()
			if _, err := payload.ReadFrom(input); err != nil {
				payload.Release()
				close(cache)
				return
			}
			select {
			case cache <- payload:
			default:
				payload.Release()
			}
		}
	}()

	for payload := range cache {
		segments := reader.Read(payload.Bytes())
		payload.Release()
		if len(segments) > 0 {
			conn.Input(segments)
		}
	}
}

// DialKCP dials a new KCP connections to the specific destination.
func DialKCP(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	dest.Network = net.Network_UDP
	errors.LogInfo(ctx, "dialing mKCP to ", dest)

	rawConn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, errors.New("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	kcpSettings := streamSettings.ProtocolSettings.(*Config)

	header, err := kcpSettings.GetPackerHeader()
	if err != nil {
		return nil, errors.New("failed to create packet header").Base(err)
	}
	security, err := kcpSettings.GetSecurity()
	if err != nil {
		return nil, errors.New("failed to create security").Base(err)
	}
	reader := &KCPPacketReader{
		Header:   header,
		Security: security,
	}
	writer := &KCPPacketWriter{
		Header:   header,
		Security: security,
		Writer:   rawConn,
	}

	conv := uint16(atomic.AddUint32(&globalConv, 1))
	session := NewConnection(ConnMetadata{
		LocalAddr:    rawConn.LocalAddr(),
		RemoteAddr:   rawConn.RemoteAddr(),
		Conversation: conv,
	}, writer, rawConn, kcpSettings)

	go fetchInput(ctx, rawConn, reader, session)

	var iConn stat.Connection = session

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		iConn = tls.Client(iConn, config.GetTLSConfig(tls.WithDestination(dest)))
	}

	return iConn, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, DialKCP))
}
