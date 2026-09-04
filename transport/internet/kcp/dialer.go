package kcp

import (
	"context"
	"io"
	reflect "reflect"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
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

	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, errors.New("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	if streamSettings.UdpmaskManager != nil {
		var pktConn net.PacketConn
		var udpAddr *net.UDPAddr
		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			pktConn = c.PacketConn
			udpAddr = c.RemoteAddr().(*net.UDPAddr)
		case *cnc.Connection:
			pktConn = &internet.FakePacketConn{Conn: c}
			udpAddr = &net.UDPAddr{IP: c.RemoteAddr().(*net.TCPAddr).IP, Port: c.RemoteAddr().(*net.TCPAddr).Port}
		default:
			panic(reflect.TypeOf(c))
		}
		newConn, err := streamSettings.UdpmaskManager.WrapPacketConnClient(pktConn)
		if err != nil {
			pktConn.Close()
			return nil, errors.New("mask err").Base(err)
		}
		pktConn = newConn
		conn = &internet.PacketConnWrapper{
			PacketConn: pktConn,
			Dest:       udpAddr,
		}
	}

	kcpSettings := streamSettings.ProtocolSettings.(*Config)

	reader := &KCPPacketReader{}

	conv := uint16(atomic.AddUint32(&globalConv, 1))
	session := NewConnection(ConnMetadata{
		LocalAddr:    conn.LocalAddr(),
		RemoteAddr:   conn.RemoteAddr(),
		Conversation: conv,
	}, conn, conn, kcpSettings)

	go fetchInput(ctx, conn, reader, session)

	var iConn stat.Connection = session

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		iConn = tls.Client(iConn, config.GetTLSConfig(tls.WithDestination(dest)))
	}

	return iConn, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(ProtocolName, DialKCP))
}
