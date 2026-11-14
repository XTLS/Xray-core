package multiplex

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

type ServerWorker struct {
	*carrier
	dispatch func(context.Context, net.Destination, *transport.Link) error
}

func NewServerWorker(ctx context.Context, dispatch func(context.Context, net.Destination, *transport.Link) error, link *transport.Link) *ServerWorker {
	w := &ServerWorker{carrier: newCarrier(*link, 60*time.Second, false), dispatch: dispatch}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.CanSpliceCopy = 3
	}
	go w.run(ctx, w.handleStatusNew)
	return w
}

// A non-nil dispatch return rejects admission; accepted backend failures use the link.
func (w *ServerWorker) dispatchFlow(ctx context.Context, dest net.Destination, flow *inboundFlow) {
	if err := w.dispatch(ctx, dest, &transport.Link{Reader: flow, Writer: &flowOutput{flow}}); err != nil {
		if flow.GlobalID != [8]byte{} {
			XUDPManager.Lock()
			if XUDPManager.Map[flow.GlobalID] == flow {
				delete(XUDPManager.Map, flow.GlobalID)
			}
			XUDPManager.Unlock()
		}
		w.cancel(err)
		flow.Interrupt()
		flow.expire()
		errors.LogInfoInner(ctx, err, "failed to dispatch request to ", dest)
		w.closeCause(err)
	}
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	ctx = session.SubContextFromMultiplexInbound(ctx)
	if meta.Inbound != nil && meta.Inbound.Source.IsValid() && meta.Inbound.Local.IsValid() {
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			newInbound := *inbound
			newInbound.Source = meta.Inbound.Source
			newInbound.Local = meta.Inbound.Local
			ctx = session.ContextWithInbound(ctx, &newInbound)
		}
	}
	errors.LogInfo(ctx, "received request for ", meta.Target)
	{
		msg := &log.AccessMessage{
			To:     meta.Target,
			Status: log.AccessAccepted,
			Reason: "",
		}
		if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
			msg.From = inbound.Source
			msg.Email = inbound.User.Email
		}
		ctx = log.ContextWithAccessMessage(ctx, msg)
	}

	if network := session.AllowedNetworkFromContext(ctx); network != net.Network_Unknown {
		if meta.Target.Network != network {
			return errors.New("unexpected network ", meta.Target.Network) // it will break the whole multiplex connection
		}
	}

	if meta.GlobalID != [8]byte{} {
		return w.bindXUDP(ctx, meta, reader)
	}

	s := &Session{
		parent: w.sessionManager, sender: w.carrier,
		ID: meta.SessionID, transferType: protocol.TransferTypeStream,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	s.flow = newInboundFlow(ctx, [8]byte{})
	s.flow.binding, s.flow.Status = s, Active
	if !w.sessionManager.Add(s) {
		s.flow.Interrupt()
		return errors.New("failed to add new session")
	}
	go s.flow.emit(s)
	dest := meta.Target
	go w.dispatchFlow(ctx, dest, s.flow)
	if !meta.Option.Has(OptionData) {
		return nil
	}

	return copyFramePayload(reader, s, meta.Target)
}
