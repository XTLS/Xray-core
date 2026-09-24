package masque

import (
	"context"
	go_errors "errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	establishTimeout = 10 * time.Second
	retryInterval    = time.Second
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	remoteDNS     []netip.Addr

	ctx    context.Context
	cancel context.CancelFunc

	tunnel atomic.Pointer[tunnel]

	mu        sync.Mutex
	lastErr   error
	lastErrAt time.Time
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*masque.Config); !ok {
		return nil, errors.New("not masque transport")
	}
	if tls.ConfigFromStreamSettings(streamSettings) == nil {
		return nil, errors.New(`MASQUE requires "security": "tls"`)
	}
	if config.Server == nil {
		return nil, errors.New(`no target server found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	dns := config.RemoteDns
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}
	}
	remoteDNS := make([]netip.Addr, 0, len(dns))
	for _, s := range dns {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, errors.New("invalid remote DNS server ", s).Base(err)
		}
		remoteDNS = append(remoteDNS, addr)
	}

	c := &Client{
		server:        server,
		policyManager: p,
		remoteDNS:     remoteDNS,
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "masque"
	ob.CanSpliceCopy = 3

	t, err := c.getTunnel(ctx, dialer)
	if err != nil {
		return errors.New("failed to establish CONNECT-IP tunnel").Base(err)
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	if newCtx != nil {
		ctx = newCtx
	}

	var reader buf.Reader
	var writer buf.Writer

	switch ob.Target.Network {
	case net.Network_TCP:
		var conn net.Conn
		var err error
		if sessionPolicy.Timeouts.Handshake != 0 {
			timeoutCtx, timeoutCancel := context.WithTimeout(ctx, sessionPolicy.Timeouts.Handshake)
			conn, err = t.tnet.DialContext(timeoutCtx, "tcp", ob.Target.NetAddr())
			timeoutCancel()
		} else {
			conn, err = t.tnet.Dial("tcp", ob.Target.NetAddr())
		}
		if err != nil {
			return errors.New("failed to create TCP connection").Base(err)
		}
		defer conn.Close()
		reader = buf.NewReader(conn)
		writer = buf.NewWriter(conn)
	case net.Network_UDP:
		conn, err := t.tnet.Dial("udp", ob.Target.NetAddr())
		if err != nil {
			return errors.New("failed to create UDP connection").Base(err)
		}
		defer conn.Close()
		uc := &wireguard.UDPConnClient{
			PacketConn: conn.(*internet.PacketConnWrapper).PacketConn,
			Dest:       conn.RemoteAddr().(*net.UDPAddr),
		}
		reader = uc
		writer = uc
	default:
		panic(ob.Target.Network)
	}

	requestFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}

	responseFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func (c *Client) getTunnel(ctx context.Context, dialer internet.Dialer) (*tunnel, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return nil, errors.New("closed")
	}
	if t := c.tunnel.Load(); t != nil {
		select {
		case <-t.done:
		default:
			return t, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.lastErr != nil && time.Since(c.lastErrAt) < retryInterval {
		return nil, c.lastErr
	}

	t, err := c.establish(ctx, dialer)
	if err != nil {
		c.lastErr, c.lastErrAt = err, time.Now()
		return nil, err
	}
	c.lastErr = nil
	c.tunnel.Store(t)
	if c.ctx.Err() != nil {
		if c.tunnel.CompareAndSwap(t, nil) {
			t.close()
		}
		return nil, errors.New("closed")
	}
	return t, nil
}

func (c *Client) establish(ctx context.Context, dialer internet.Dialer) (*tunnel, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), establishTimeout)
	defer cancel()
	defer context.AfterFunc(c.ctx, cancel)()
	conn, err := dialer.Dial(ctx, c.server.Destination)
	if err != nil {
		return nil, err
	}
	mconn, ok := stat.TryUnwrapStatsConn(conn).(*masque.Conn)
	if !ok {
		conn.Close()
		return nil, errors.New("not a CONNECT-IP connection")
	}
	t, err := newTunnel(conn, mconn.LocalAddrs(), c.remoteDNS)
	if err != nil {
		conn.Close()
		return nil, err
	}
	errors.LogInfo(ctx, "MASQUE: tunnel established from ", mconn.LocalAddrs())
	return t, nil
}

func (c *Client) Close() error {
	c.cancel()
	if t := c.tunnel.Swap(nil); t != nil {
		t.close()
	}
	return nil
}

type tunnel struct {
	conn      stat.Connection
	dev       tun.Device
	tnet      *wireguard.Net
	done      chan struct{}
	closeOnce sync.Once
}

func newTunnel(conn stat.Connection, local []netip.Addr, remoteDNS []netip.Addr) (*tunnel, error) {
	var dns []netip.Addr
	for _, addr := range remoteDNS {
		if slices.ContainsFunc(local, func(l netip.Addr) bool { return l.Is4() == addr.Is4() }) {
			dns = append(dns, addr)
		}
	}
	if len(dns) == 0 {
		errors.LogWarning(context.Background(), "MASQUE: no remote DNS server is reachable from the assigned addresses ", local, ", domain names will fail to resolve")
		dns = remoteDNS
	}

	dev, tnet, _, err := wireguard.CreateNetTUN(local, dns, masque.MinPacketSize, true)
	if err != nil {
		return nil, err
	}
	t := &tunnel{
		conn: conn,
		dev:  dev,
		tnet: tnet,
		done: make(chan struct{}),
	}
	go t.readFromTunnel()
	go t.writeToTunnel()
	return t, nil
}

func (t *tunnel) readFromTunnel() {
	defer t.close()
	b := make([]byte, buf.Size)
	for {
		n, err := t.conn.Read(b)
		if err != nil {
			if go_errors.Is(err, io.ErrShortBuffer) {
				continue
			}
			errors.LogInfoInner(context.Background(), err, "MASQUE: tunnel closed")
			return
		}
		t.dev.Write([][]byte{b[:n]}, 0)
	}
}

func (t *tunnel) writeToTunnel() {
	bufs := [][]byte{make([]byte, masque.MinPacketSize)}
	sizes := []int{0}
	for {
		if _, err := t.dev.Read(bufs, sizes, 0); err != nil {
			return
		}
		if _, err := t.conn.Write(bufs[0][:sizes[0]]); err != nil {
			var ptb *masque.PacketTooBigError
			if go_errors.As(err, &ptb) {
				go t.dev.Write([][]byte{ptb.ICMP}, 0)
			}
		}
	}
}

func (t *tunnel) close() {
	t.closeOnce.Do(func() {
		close(t.done)
		t.conn.Close()
		t.dev.Close()
	})
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
