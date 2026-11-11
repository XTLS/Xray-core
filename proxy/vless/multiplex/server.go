package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type ServerWorker struct {
	*carrier
	dispatch func(context.Context, net.Destination, *transport.Link) error
}

func NewServerWorker(ctx context.Context, dispatch func(context.Context, net.Destination, *transport.Link) error, link *transport.Link) *ServerWorker {
	w := &ServerWorker{carrier: newCarrier(*link, 60*time.Second), dispatch: dispatch}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.CanSpliceCopy = 3
	}
	go w.run(ctx, w.handleStatusNew)
	return w
}

// newLink transfers both endpoints to the native handler. Successful dispatch
// return does not revoke either endpoint, including a legal asynchronous handoff.
func (w *ServerWorker) newLink(ctx context.Context, dest net.Destination) *transport.Link {
	opt := pipe.OptionsFromContext(ctx)
	requestReader, requestWriter := pipe.New(opt...)
	responseReader, responseWriter := pipe.New(opt...)
	go func() {
		if err := w.dispatch(ctx, dest, &transport.Link{Reader: requestReader, Writer: responseWriter}); err != nil {
			requestReader.Interrupt()
			errors.LogInfoInner(ctx, err, "failed to dispatch request to ", dest)
			responseWriter.Interrupt()
		}
	}()
	return &transport.Link{Reader: responseReader, Writer: requestWriter}
}

func handle(ctx context.Context, s *Session, output buf.Writer) {
	writer := NewResponseWriter(s.ID, output, s.transferType)
	if err := buf.Copy(s, writer); err != nil {
		errors.LogInfoInner(ctx, err, "session ", s.ID, " ends.")
		writer.hasError = true
	}

	s.Close()
	writer.Close()
	s.endWritten()
}

// childResponse frames native output; its Session owns the one terminal event.
type childResponse struct {
	access  sync.Mutex
	session *Session
	writer  *Writer
}

func (r *childResponse) WriteMultiBuffer(mb buf.MultiBuffer) error {
	r.access.Lock()
	defer r.access.Unlock()
	r.session.parent.RLock()
	closed := r.session.closed
	r.session.parent.RUnlock()
	if closed {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	err := r.writer.WriteMultiBuffer(mb)
	if err != nil {
		r.writer.hasError = true
		r.Interrupt()
	}
	return err
}

func (r *childResponse) Close() error { r.session.close(false); return nil }
func (r *childResponse) Interrupt()   { r.session.Close() }

// end is called once, after logical retirement and request-writer EOF.
func (r *childResponse) end(failed bool) {
	go func() {
		r.access.Lock()
		defer r.access.Unlock()
		r.writer.hasError = r.writer.hasError || failed
		r.writer.Close()
		r.session.endWritten()
	}()
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	ctx = session.SubContextFromMuxInbound(ctx)
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
			return errors.New("unexpected network ", meta.Target.Network) // it will break the whole Mux connection
		}
	}

	if meta.GlobalID != [8]byte{} { // MUST ignore empty Global ID
		mb, err := readPacket(reader, meta.Target)
		if err != nil {
			return err
		}
		var input buf.Reader
		var output buf.Writer
		XUDPManager.Lock()
		x := XUDPManager.Map[meta.GlobalID]
		if x == nil {
			x = &XUDP{GlobalID: meta.GlobalID}
			XUDPManager.Map[meta.GlobalID] = x
			XUDPManager.Unlock()
		} else {
			if x.Status == Initializing { // nearly impossible
				buf.ReleaseMulti(mb)
				XUDPManager.Unlock()
				errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
				// It's not a good idea to return an err here, so just let client wait.
				// Client will receive an End frame after sending a Keep frame.
				return nil
			}
			x.Status = Initializing
			previous := x.Mux
			XUDPManager.Unlock()
			previous.Close() // detach from previous Mux
			input, output = previous.input, previous.output
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			if err = output.WriteMultiBuffer(mb); err != nil {
				common.Interrupt(input)
				common.Close(output)
				mb = buf.MultiBuffer{b}
			} else {
				b.Release()
				mb = nil
			}
			errors.LogInfoInner(ctx, err, "XUDP hit ", meta.GlobalID)
		}
		if mb != nil {
			ctx = session.ContextWithTimeoutOnly(ctx, true)
			link := w.newLink(ctx, meta.Target)
			link.Writer.WriteMultiBuffer(mb) // it's meaningless to test a new pipe
			input, output = link.Reader, link.Writer
			errors.LogInfoInner(ctx, err, "XUDP new ", meta.GlobalID)
		}
		s := &Session{
			input:        input,
			output:       output,
			parent:       w.sessionManager,
			keepUntilEnd: true,
			ID:           meta.SessionID,
			transferType: protocol.TransferTypePacket,
			done:         done.New(),
			XUDP:         x,
		}
		// Admit and publish together, in the same lock order as Session.Close.
		w.sessionManager.Lock()
		XUDPManager.Lock()
		x.Mux = s
		if w.sessionManager.closed {
			x.Expire = time.Now().Add(time.Minute)
			x.Status = Expiring
			XUDPManager.Unlock()
			w.sessionManager.Unlock()
			s.Close()
			return errors.New("failed to add new session")
		}
		w.sessionManager.count++
		w.sessionManager.sessions[s.ID] = s
		x.Status = Active
		XUDPManager.Unlock()
		w.sessionManager.Unlock()
		go handle(ctx, s, w.link.Writer)
		return nil
	}

	requestReader, requestWriter := pipe.New(pipe.OptionsFromContext(ctx)...)
	s := &Session{
		output: requestWriter, parent: w.sessionManager, keepUntilEnd: true,
		ID: meta.SessionID, transferType: protocol.TransferTypeStream,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	response := &childResponse{session: s, writer: NewResponseWriter(s.ID, w.link.Writer, s.transferType)}
	s.onClose = response.end
	if !w.sessionManager.Add(s) {
		requestReader.Interrupt()
		requestWriter.Close()
		return errors.New("failed to add new session")
	}
	dest := meta.Target
	go func() {
		if err := w.dispatch(ctx, dest, &transport.Link{Reader: requestReader, Writer: response}); err != nil {
			requestReader.Interrupt()
			errors.LogInfoInner(ctx, err, "failed to dispatch request to ", dest)
			response.Interrupt()
		}
	}()
	if !meta.Option.Has(OptionData) {
		return nil
	}

	return copyFramePayload(reader, s, meta.Target)
}
