package pprof

import (
	"context"
	"net/http"
	_ "net/http/pprof"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

type PprofHandler struct {
	ohm outbound.Manager
	tag string
}

// NewPprofHandler creates a new PprofHandler based on the given config.
func NewPprofHandler(ctx context.Context, config *Config) (*PprofHandler, error) {
	c := &PprofHandler{
		tag: config.Tag,
	}
	common.Must(core.RequireFeatures(ctx, func(om outbound.Manager) {
		c.ohm = om
	}))
	return c, nil
}

func (p *PprofHandler) Type() interface{} {
	return (*PprofHandler)(nil)
}

func (p *PprofHandler) Start() error {
	listener := &OutboundListener{
		buffer: make(chan net.Conn, 4),
		done:   done.New(),
	}

	go func() {
		if err := http.Serve(listener, http.DefaultServeMux); err != nil {
			newError("failed to start pprof server").Base(err).AtError().WriteToLog()
		}
	}()

	if err := p.ohm.RemoveHandler(context.Background(), p.tag); err != nil {
		newError("failed to remove existing handler").WriteToLog()
	}

	return p.ohm.AddHandler(context.Background(), &Outbound{
		tag:      p.tag,
		listener: listener,
	})
}

func (p *PprofHandler) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewPprofHandler(ctx, cfg.(*Config))
	}))
}
