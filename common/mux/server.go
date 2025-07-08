package mux

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type Server struct {
	dispatcher routing.Dispatcher
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
	})
	return s
}

// Type implements common.HasType.
func (s *Server) Type() interface{} {
	return s.dispatcher.Type()
}

// Dispatch implements routing.Dispatcher
func (s *Server) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.Dispatch(ctx, dest)
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	_, err := NewServerWorker(ctx, s.dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if err != nil {
		return nil, err
	}

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// DispatchLink implements routing.Dispatcher
func (s *Server) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.DispatchLink(ctx, dest, link)
	}
	_, err := NewServerWorker(ctx, s.dispatcher, link)
	return err
}

// Start implements common.Runnable.
func (s *Server) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	return nil
}

type ServerWorker struct {
	dispatcher     routing.Dispatcher
	link           *transport.Link
	sessionManager *SessionManager
}

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	worker := &ServerWorker{
		dispatcher:     d,
		link:           link,
		sessionManager: NewSessionManager(),
	}
	go worker.run(ctx)
	return worker, nil
}

func handle(ctx context.Context, s *Session, output buf.Writer) {
	writer := NewResponseWriter(s.ID, output, s.transferType)
	if err := buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "session ", s.ID, " ends.")
		writer.hasError = true
	}

	writer.Close()
	s.Close(false)
}

func (w *ServerWorker) ActiveConnections() uint32 {
	return uint32(w.sessionManager.Size())
}

func (w *ServerWorker) Closed() bool {
	return w.sessionManager.Closed()
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	// deep-clone outbounds because it is going to be mutated concurrently
	// (Target and OriginalTarget)
	ctx = session.ContextCloneOutboundsAndContent(ctx)
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
		mb, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
		if err != nil {
			return err
		}
		XUDPManager.Lock()
		x := XUDPManager.Map[meta.GlobalID]
		if x == nil {
			x = &XUDP{GlobalID: meta.GlobalID}
			XUDPManager.Map[meta.GlobalID] = x
			XUDPManager.Unlock()
		} else {
			if x.Status == Initializing { // nearly impossible
				XUDPManager.Unlock()
				errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
				// It's not a good idea to return an err here, so just let client wait.
				// Client will receive an End frame after sending a Keep frame.
				return nil
			}
			x.Status = Initializing
			XUDPManager.Unlock()
			x.Mux.Close(false) // detach from previous Mux
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			if err = x.Mux.output.WriteMultiBuffer(mb); err != nil {
				x.Interrupt()
				mb = buf.MultiBuffer{b}
			} else {
				b.Release()
				mb = nil
			}
			errors.LogInfoInner(ctx, err, "XUDP hit ", meta.GlobalID)
		}
		if mb != nil {
			ctx = session.ContextWithTimeoutOnly(ctx, true)
			// Actually, it won't return an error in Xray-core's implementations.
			link, err := w.dispatcher.Dispatch(ctx, meta.Target)
			if err != nil {
				XUDPManager.Lock()
				delete(XUDPManager.Map, x.GlobalID)
				XUDPManager.Unlock()
				err = errors.New("XUDP new ", meta.GlobalID).Base(errors.New("failed to dispatch request to ", meta.Target).Base(err))
				return err // it will break the whole Mux connection
			}
			link.Writer.WriteMultiBuffer(mb) // it's meaningless to test a new pipe
			x.Mux = &Session{
				input:  link.Reader,
				output: link.Writer,
			}
			errors.LogInfoInner(ctx, err, "XUDP new ", meta.GlobalID)
		}
		x.Mux = &Session{
			input:        x.Mux.input,
			output:       x.Mux.output,
			parent:       w.sessionManager,
			ID:           meta.SessionID,
			transferType: protocol.TransferTypePacket,
			XUDP:         x,
		}
		x.Status = Active
		if !w.sessionManager.Add(x.Mux) {
			x.Mux.Close(false)
			return errors.New("failed to add new session")
		}
		go handle(ctx, x.Mux, w.link.Writer)
		return nil
	}

	link, err := w.dispatcher.Dispatch(ctx, meta.Target)
	if err != nil {
		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		return errors.New("failed to dispatch request.").Base(err)
	}
	s := &Session{
		input:        link.Reader,
		output:       link.Writer,
		parent:       w.sessionManager,
		ID:           meta.SessionID,
		transferType: protocol.TransferTypeStream,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	if !w.sessionManager.Add(s) {
		s.Close(false)
		return errors.New("failed to add new session")
	}
	go handle(ctx, s, w.link.Writer)
	if !meta.Option.Has(OptionData) {
		return nil
	}

	rr := s.NewReader(reader, &meta.Target)
	err = buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}
	return err
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := w.sessionManager.Get(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader, &meta.Target)
	err := buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream writer. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

func (w *ServerWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := w.sessionManager.Get(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleFrame(ctx context.Context, reader *buf.BufferedReader) error {
	var meta FrameMetadata
	err := meta.Unmarshal(reader)
	if err != nil {
		return errors.New("failed to read metadata").Base(err)
	}

	switch meta.SessionStatus {
	case SessionStatusKeepAlive:
		err = w.handleStatusKeepAlive(&meta, reader)
	case SessionStatusEnd:
		err = w.handleStatusEnd(&meta, reader)
	case SessionStatusNew:
		err = w.handleStatusNew(ctx, &meta, reader)
	case SessionStatusKeep:
		err = w.handleStatusKeep(&meta, reader)
	default:
		status := meta.SessionStatus
		return errors.New("unknown status: ", status).AtError()
	}

	if err != nil {
		return errors.New("failed to process data").Base(err)
	}
	return nil
}

func (w *ServerWorker) run(ctx context.Context) {
	reader := &buf.BufferedReader{Reader: w.link.Reader}

	defer w.sessionManager.Close()
	defer common.Close(w.link.Writer)
	defer common.Interrupt(w.link.Reader)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := w.handleFrame(ctx, reader)
			if err != nil {
				if errors.Cause(err) != io.EOF {
					errors.LogInfoInner(ctx, err, "unexpected EOF")
				}
				return
			}
		}
	}
}
