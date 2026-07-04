package inbound

import (
	"context"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/protobuf/proto"
)

// SelfDrivenInboundHandler adapts a proxy.SelfDrivenInbound (an inbound that
// dials out to its own carrier instead of listening on a socket) to the
// inbound.Handler interface. It has no workers/port; Start runs the proxy's
// Serve loop in a goroutine and Close cancels it.
type SelfDrivenInboundHandler struct {
	tag            string
	receiverConfig *proxyman.ReceiverConfig
	proxyConfig    interface{}
	proxy          proxy.SelfDrivenInbound
	cancel         context.CancelFunc
}

// NewSelfDrivenInboundHandler creates a handler for a self-driven inbound proxy.
func NewSelfDrivenInboundHandler(ctx context.Context, tag string, receiverConfig *proxyman.ReceiverConfig, proxyConfig interface{}) (*SelfDrivenInboundHandler, error) {
	newCtx := session.ContextWithInbound(ctx, &session.Inbound{Tag: tag})
	rawProxy, err := common.CreateObject(newCtx, proxyConfig)
	if err != nil {
		return nil, err
	}
	p, ok := rawProxy.(proxy.SelfDrivenInbound)
	if !ok {
		return nil, errors.New("not a self-driven inbound proxy").AtError()
	}
	return &SelfDrivenInboundHandler{
		tag:            tag,
		receiverConfig: receiverConfig,
		proxyConfig:    proxyConfig,
		proxy:          p,
	}, nil
}

// Start implements common.Runnable.
func (h *SelfDrivenInboundHandler) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.serveLoop(ctx)
	return nil
}

// serveLoop runs the proxy's Serve until the handler is closed, restarting it
// with capped exponential backoff if it returns early (e.g. a transient SFU
// outage). Backoff resets once a run has stayed up long enough to be considered
// stable.
func (h *SelfDrivenInboundHandler) serveLoop(ctx context.Context) {
	const (
		minBackoff = 2 * time.Second
		maxBackoff = 30 * time.Second
	)
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		err := h.proxy.Serve(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			errors.LogWarningInner(ctx, err, "self-driven inbound ", h.tag, " ended; restarting")
		} else {
			errors.LogInfo(ctx, "self-driven inbound ", h.tag, " ended; restarting")
		}
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// Close implements common.Closable.
func (h *SelfDrivenInboundHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

// Tag implements inbound.Handler.
func (h *SelfDrivenInboundHandler) Tag() string { return h.tag }

// ReceiverSettings implements inbound.Handler.
func (h *SelfDrivenInboundHandler) ReceiverSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.receiverConfig)
}

// ProxySettings implements inbound.Handler.
func (h *SelfDrivenInboundHandler) ProxySettings() *serial.TypedMessage {
	if pm, ok := h.proxyConfig.(proto.Message); ok {
		return serial.ToTypedMessage(pm)
	}
	return nil
}
