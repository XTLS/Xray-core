package outbound

import (
	"context"
	"github.com/xtls/xray-core/transport/pipe"
	"io"
	"sync/atomic"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	mux "github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func (h *Handler) ConfigureMux(config *proxyman.MultiplexingConfig, dialer internet.Dialer) {
	if config == nil || !config.Enabled {
		return
	}
	h.muxConfig = config
	manager := func(concurrency int32) *mux.ClientManager {
		return &mux.ClientManager{Picker: &mux.IncrementalWorkerPicker{
			Factory: &muxWorkerFactory{handler: h, dialer: dialer, strategy: mux.ClientStrategy{
				MaxConcurrency: uint32(concurrency), MaxConnection: 1024,
			}},
		}}
	}
	if config.Concurrency >= 0 {
		config.Concurrency = max(config.Concurrency, 128)
		h.mux = manager(config.Concurrency)
	}
	if config.XudpConcurrency > 0 {
		h.xudp = manager(config.XudpConcurrency)
	}
}

func (h *Handler) muxFor(ctx context.Context) (*mux.ClientManager, error) {
	if h.muxConfig == nil {
		return nil, nil
	}
	outbounds := session.OutboundsFromContext(ctx)
	target := outbounds[len(outbounds)-1].Target
	if target.Network == net.Network_UDP {
		if target.Port == 443 {
			switch h.muxConfig.XudpProxyUDP443 {
			case "reject":
				return nil, errors.New("XUDP rejected UDP/443 traffic")
			case "skip":
				return nil, nil
			}
		}
		if h.muxConfig.XudpConcurrency < 0 {
			return nil, nil
		}
		if h.xudp != nil {
			return h.xudp, nil
		}
	}
	return h.mux, nil
}

type muxWorkerFactory struct {
	handler  *Handler
	dialer   internet.Dialer
	strategy mux.ClientStrategy
}

func (f *muxWorkerFactory) Create() (*mux.ClientWorker, error) {
	type result struct {
		worker *mux.ClientWorker
		err    error
	}
	ready := make(chan result, 1)
	ctx := session.ContextWithOutbounds(f.handler.ctx, []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527),
	}})
	go func() {
		err := f.handler.process(ctx, nil, f.dialer, func(ctx context.Context, link *transport.Link) error {
			worker, err := mux.NewClientWorker(*link, f.strategy)
			if err != nil {
				return err
			}
			defer worker.Close()
			ready <- result{worker: worker}
			select {
			case <-ctx.Done():
			case <-worker.WaitClosed():
			}
			return nil
		})
		if err != nil {
			ready <- result{err: err}
		}
	}()
	r := <-ready
	return r.worker, r.err
}

// muxCarrier owns the VLESS codecs and transport. Native response reads are
// accumulated independently of Mux frame parsing in one bounded receive pipe.
type muxCarrier struct {
	ctx      context.Context
	gate     *buf.BufferedWriter
	ready    atomic.Bool
	reader   *pipe.Reader
	writer   buf.Writer
	activity *signal.ActivityTimer
	cancel   context.CancelFunc
	readErr  error
}

func (c *muxCarrier) ReadMultiBuffer() (buf.MultiBuffer, error) {
	data, err := c.reader.ReadMultiBuffer()
	// The producer publishes readErr before closing the pipe writer.
	if err == io.EOF && c.readErr != nil {
		err = c.readErr
	}
	return data, err
}

func (c *muxCarrier) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := c.ctx.Err(); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	if !mb.IsEmpty() {
		c.activity.Update()
	}
	err := c.writer.WriteMultiBuffer(mb)
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *muxCarrier) Interrupt() {
	c.cancel()
	c.reader.Interrupt()
}

// A quiescent writer can drain and send EOF. Handshake or blocked writes
// need interruption before transport Close attempts to acquire their locks.
func (c *muxCarrier) stopTransport(conn stat.Connection) {
	if c.ready.Load() && c.gate.TryLock() {
		c.gate.Unlock()
		conn.Close()
		return
	}
	common.Interrupt(stat.TryUnwrapStatsConn(conn))
}
