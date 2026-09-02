// Package blackhole is an outbound handler that blocks all connections.
package blackhole

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is an outbound connection that silently swallow the entire payload.
type Handler struct {
	response []byte
}

var http403response = http.Response{
	StatusCode: 403,
	ProtoMajor: 1,
	ProtoMinor: 1,
	Header: http.Header{
		"Connection":    {"close"},
		"Cache-Control": {"max-age=3600, public"},
	},
}

// New creates a new blackhole handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	response := []byte{}
	if config.Response != nil {
		switch config.Response.Type {
		case "", "none":
		case "http":
			var data bytes.Buffer
			common.Must(http403response.Write(&data))
			response = data.Bytes()
		case "custom":
			response = config.Response.CustomResponseData
		default:
			return nil, errors.New("unknown blackhole response: " + config.Response.Type)
		}
	}
	return &Handler{
		response: response,
	}, nil
}

// Process implements OutboundHandler.Dispatch().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	ob.Name = "blackhole"

	if len(h.response) > 0 {
		mbc := buf.MultiBufferContainer{}
		common.Must2(mbc.Write(h.response))
		link.Writer.WriteMultiBuffer(mbc.MultiBuffer)
		// Sleep a little here to make sure the response is sent to client.
		time.Sleep(time.Second)
	}
	defer common.Interrupt(link.Writer)
	defer common.Interrupt(link.Reader)
	// wait to drain all the possible incoming UDP data
	if ob.Target.Network == net.Network_UDP {
		ctx, cancel := context.WithCancel(ctx)
		timer := signal.CancelAfterInactivity(ctx, func() {
			cancel()
		}, time.Duration(30+dice.Roll(61))*time.Second)
		go buf.Copy(link.Reader, buf.Discard, buf.UpdateActivity(timer))
		<-ctx.Done()
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
