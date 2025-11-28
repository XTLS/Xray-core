package hysteria2

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/hysteria2/hyconfig"
	hyclient "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/client"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	vraytls "github.com/xtls/xray-core/transport/internet/tls"
)

type outboundHandler struct {
	tag            string
	proxyConfig    *OutboundConfig
	streamSettings *internet.MemoryStreamConfig
	clientConfig   *hyconfig.ClientConfig

	clientMu sync.Mutex
	client   hyclient.Client

	serverDest xnet.Destination
}

func newOutboundHandler(tag string, proxyConfig *OutboundConfig, stream *internet.MemoryStreamConfig) (*outboundHandler, error) {
	clientCfg, err := proxyConfig.decodeClientConfig()
	if err != nil {
		return nil, err
	}
	if clientCfg.Server == "" {
		return nil, errors.New("hysteria outbound: server is empty")
	}
	host, portStr, err := net.SplitHostPort(clientCfg.Server)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	return &outboundHandler{
		tag:            tag,
		proxyConfig:    proxyConfig,
		streamSettings: stream,
		clientConfig:   clientCfg,
		serverDest: xnet.Destination{
			Network: xnet.Network_UDP,
			Address: xnet.ParseAddress(host),
			Port:    xnet.Port(port),
		},
	}, nil
}

func (h *outboundHandler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("hysteria outbound: no outbound session")
	}
	dest := outbounds[len(outbounds)-1].Target
	cli, err := h.getClient(ctx, dialer)
	if err != nil {
		return err
	}

	switch dest.Network {
	case xnet.Network_TCP:
		return h.pipeTCP(ctx, cli, dest, link)
	case xnet.Network_UDP:
		return h.pipeUDP(ctx, cli, dest, link)
	default:
		return errors.New("unsupported network: ", dest.Network)
	}
}

func (h *outboundHandler) pipeTCP(ctx context.Context, cli hyclient.Client, dest xnet.Destination, link *transport.Link) error {
	conn, err := cli.TCP(dest.NetAddr())
	if err != nil {
		return err
	}
	defer conn.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- buf.Copy(buf.NewReader(conn), link.Writer)
	}()
	go func() {
		errCh <- buf.Copy(link.Reader, buf.NewWriter(conn))
	}()

	var first error
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil && first == nil {
			first = e
		}
	}
	return first
}

func (h *outboundHandler) pipeUDP(ctx context.Context, cli hyclient.Client, dest xnet.Destination, link *transport.Link) error {
	udpConn, err := cli.UDP()
	if err != nil {
		return err
	}
	defer udpConn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// Client -> remote
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				errCh <- err
				return
			}
			for _, b := range mb {
				sendDest := dest
				if b.UDP != nil {
					sendDest = *b.UDP
				}
				addr := sendDest.NetAddr()
				if sendErr := udpConn.Send(b.Bytes(), addr); sendErr != nil {
					buf.ReleaseMulti(mb)
					errCh <- sendErr
					return
				}
			}
			buf.ReleaseMulti(mb)
		}
	}()

	// Remote -> client
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			data, addr, err := udpConn.Receive()
			if err != nil {
				errCh <- err
				return
			}
			packet := buf.FromBytes(append([]byte(nil), data...))
			if parsed, perr := parseDestination(addr, xnet.Network_UDP); perr == nil {
				packet.UDP = &parsed
			}
			if writeErr := link.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); writeErr != nil {
				errCh <- writeErr
				return
			}
		}
	}()

	return task.Run(ctx, func() error {
		select {
		case err := <-errCh:
			if err == context.Canceled {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func (h *outboundHandler) getClient(ctx context.Context, dialer internet.Dialer) (hyclient.Client, error) {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	if h.client != nil {
		return h.client, nil
	}

	streamTLS := tlsFromStream(h.streamSettings)

	cfg, err := h.proxyConfig.BuildClient(ctx, h.clientConfig, h.serverDest, dialer, h.streamSettings, streamTLS)
	if err != nil {
		return nil, err
	}

	cli, _, err := hyclient.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	h.client = cli
	return cli, nil
}

func tlsFromStream(stream *internet.MemoryStreamConfig) *tls.Config {
	if stream == nil {
		return nil
	}
	if cfg := vraytls.ConfigFromStreamSettings(stream); cfg != nil {
		return cfg.GetTLSConfig()
	}
	return nil
}

type dialerConnFactory struct {
	ctx    context.Context
	dialer internet.Dialer
	dest   xnet.Destination
}

func (f *dialerConnFactory) New(_ net.Addr) (net.PacketConn, error) {
	ctx := f.ctx
	if session.OutboundsFromContext(ctx) == nil {
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
			Target: f.dest,
		}})
	}

	conn, err := f.dialer.Dial(ctx, f.dest)
	if err != nil {
		return nil, err
	}
	if pc, ok := conn.(net.PacketConn); ok {
		return pc, nil
	}
	return nil, fmt.Errorf("hysteria outbound: dialer did not return packet conn")
}

func (c *OutboundConfig) BuildClient(ctx context.Context, settings *hyconfig.ClientConfig, dest xnet.Destination, dialer internet.Dialer, stream *internet.MemoryStreamConfig, streamTLS *tls.Config) (*hyclient.Config, error) {
	useTLSFromStream := streamTLS != nil

	ctxWithOutbounds := ctx
	if session.OutboundsFromContext(ctx) == nil {
		ctxWithOutbounds = session.ContextWithOutbounds(ctx, []*session.Outbound{{
			Target: dest,
		}})
	}

	return settings.Build(hyconfig.ClientBuildOptions{
		UseTLSFromStream: useTLSFromStream,
		StreamTLS:        streamTLS,
		ConnFactory: &dialerConnFactory{
			ctx:    ctxWithOutbounds,
			dialer: dialer,
			dest:   dest,
		},
	})
}

func (c *OutboundConfig) decodeClientConfig() (*hyconfig.ClientConfig, error) {
	settings := &hyconfig.ClientConfig{}
	if c.Settings == nil {
		return settings, nil
	}
	raw, err := c.Settings.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// Implement proxy.Outbound
func (h *outboundHandler) Start() error { return nil }
func (h *outboundHandler) Close() error {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	if h.client != nil {
		_ = h.client.Close()
		h.client = nil
	}
	return nil
}
