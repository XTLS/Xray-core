package rawpacket

import (
	"context"
	stdnet "net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const ProtocolName = "rawpacket"

type rawpacketListener struct {
	addr  stdnet.Addr
	done  chan struct{}
	relay *Relay
}

func (l *rawpacketListener) Close() error {
	if l.relay != nil {
		l.relay.Close()
	}
	close(l.done)
	return nil
}

func (l *rawpacketListener) Addr() stdnet.Addr {
	return l.addr
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(ProtocolName, func() interface{} {
		return new(Config)
	}))
	common.Must(internet.RegisterTransportDialer(ProtocolName, Dial))
	common.Must(internet.RegisterTransportListener(ProtocolName, listenRawpacket))
}

func listenRawpacket(ctx context.Context, address net.Address, port net.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	config := settings.ProtocolSettings.(*Config)
	if config.Mode == "remote" {
		cfg, err := config.buildRelayConfig()
		if err == nil {
			if cfg.ListenPort == 0 {
				cfg.ListenPort = uint16(port)
			}
			r, err := NewRelay(cfg)
			if err == nil {
				go r.Run()
				return &rawpacketListener{
					addr:  &stdnet.TCPAddr{IP: stdnet.IP{0, 0, 0, 0}, Port: int(port)},
					done:  make(chan struct{}),
					relay: r,
				}, nil
			}
		}
	}
	return &rawpacketListener{
		addr: &stdnet.TCPAddr{IP: stdnet.IP{0, 0, 0, 0}, Port: int(port)},
		done: make(chan struct{}),
	}, nil
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	conn, err := config.WrapConnClient(nil)
	if err != nil {
		return nil, err
	}
	return stat.Connection(conn), nil
}
