package inbound

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is an inbound connection handler that handles messages in VMess protocol.
type Handler struct {
	policyManager  policy.Manager
	clients        *vmess.TimedUserValidator
	usersByEmail   *sync.Map // normalized email -> *protocol.MemoryUser
	defaultLevel   uint32
	sessionHistory *encoding.SessionHistory
}

// New creates a new VMess inbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		policyManager:  v.GetFeature(policy.ManagerType()).(policy.Manager),
		clients:        vmess.NewTimedUserValidator(),
		usersByEmail:   new(sync.Map),
		defaultLevel:   config.GetDefault().GetLevel(),
		sessionHistory: encoding.NewSessionHistory(),
	}

	for _, user := range config.User {
		mUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get VMess user").Base(err)
		}

		if err := handler.AddUser(ctx, mUser); err != nil {
			return nil, errors.New("failed to initiate user").Base(err)
		}
	}

	return handler, nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	return h.sessionHistory.Close()
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (h *Handler) GetOrGenerateUser(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	if existing, ok := h.usersByEmail.Load(email); ok {
		return existing.(*protocol.MemoryUser)
	}
	id := uuid.New()
	raw := &vmess.Account{Id: id.String()}
	account, err := raw.AsAccount()
	common.Must(err)
	user := &protocol.MemoryUser{Level: h.defaultLevel, Email: email, Account: account}
	actual, exists := h.usersByEmail.LoadOrStore(email, user)
	if !exists {
		h.clients.Add(user)
	}
	return actual.(*protocol.MemoryUser)
}

func (h *Handler) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	user, _ := h.usersByEmail.Load(strings.ToLower(email))
	result, _ := user.(*protocol.MemoryUser)
	return result
}

func (h *Handler) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return h.clients.GetUsers()
}

func (h *Handler) GetUsersCount(context.Context) int64 {
	return h.clients.GetCount()
}

func (h *Handler) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if user.Email != "" {
		if _, exists := h.usersByEmail.LoadOrStore(strings.ToLower(user.Email), user); exists {
			return errors.New("User ", user.Email, " already exists.")
		}
	}
	return h.clients.Add(user)
}

func (h *Handler) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}
	if _, found := h.usersByEmail.LoadAndDelete(strings.ToLower(email)); !found {
		return errors.New("User ", email, " not found.")
	}
	h.clients.Remove(email)
	return nil
}

// codecBody discards decoded input when the connection or reader has stopped.
type codecBody struct {
	ctx     context.Context
	reader  buf.Reader
	stopped atomic.Bool
}

func (b *codecBody) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if b.ctx.Err() != nil {
		return nil, context.Cause(b.ctx)
	}
	if b.stopped.Load() {
		return nil, io.ErrClosedPipe
	}
	mb, err := b.reader.ReadMultiBuffer()
	if b.ctx.Err() != nil {
		buf.ReleaseMulti(mb)
		return nil, context.Cause(b.ctx)
	}
	if b.stopped.Load() {
		buf.ReleaseMulti(mb)
		return nil, io.ErrClosedPipe
	}
	return mb, err
}

func (b *codecBody) Interrupt() {
	b.stopped.Store(true)
}

// responseWriter serializes concurrent writes before they reach the VMess codec.
type responseWriter struct {
	sync.Mutex
	buf.Writer
	ctx    context.Context
	cancel context.CancelCauseFunc
}

func (w *responseWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		buf.ReleaseMulti(mb)
		return nil
	}
	w.Lock()
	defer w.Unlock()
	if err := context.Cause(w.ctx); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	if err := w.Writer.WriteMultiBuffer(mb); err != nil {
		w.cancel(err)
		return err
	}
	return nil
}

func (w *responseWriter) Interrupt() { w.cancel(io.ErrClosedPipe) }

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := h.policyManager.ForLevel(0)
	if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err)
	}

	iConn := stat.TryUnwrapStatsConn(connection)
	_, isDrain := iConn.(*net.TCPConn)
	if !isDrain {
		_, isDrain = iConn.(*net.UnixConn)
	}

	reader := &buf.BufferedReader{Reader: buf.NewReader(connection)}
	svrSession := encoding.NewServerSession(h.clients, h.sessionHistory)
	request, err := svrSession.DecodeRequestHeader(reader, isDrain)
	if err != nil {
		if errors.Cause(err) != io.EOF {
			log.Record(&log.AccessMessage{
				From:   connection.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			err = errors.New("invalid request from ", connection.RemoteAddr()).Base(err)
		}
		return err
	}

	if request.Command != protocol.RequestCommandMux {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   connection.RemoteAddr(),
			To:     request.Destination(),
			Status: log.AccessAccepted,
			Reason: "",
			Email:  request.User.Email,
		})
	}

	errors.LogInfo(ctx, "received request for ", request.Destination())

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		errors.LogInfoInner(ctx, err, "unable to set back read deadline")
	}

	inbound := session.InboundFromContext(ctx)
	inbound.Name = "vmess"
	inbound.CanSpliceCopy = 3
	inbound.User = request.User

	ctx = policy.ContextWithBufferPolicy(ctx, h.policyManager.ForLevel(request.User.Level).Buffer)
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stopClose := context.AfterFunc(ctx, func() { common.Interrupt(iConn) })
	defer stopClose()

	bodyReader, err := svrSession.DecodeRequestBody(request, reader)
	if err != nil {
		return errors.New("failed to start decoding").Base(err)
	}
	wire := buf.NewBufferedWriter(buf.NewWriter(connection))
	// The empty response header fits in wire's initial buffer. Socket I/O is
	// deferred to the checked first flush.
	svrSession.EncodeResponseHeader(&protocol.ResponseHeader{}, wire)
	bodyWriter, err := svrSession.EncodeResponseBody(request, wire)
	if err != nil {
		return errors.New("failed to start decoding response").Base(err)
	}
	body := &codecBody{ctx: ctx, reader: bodyReader}
	wire.SetFlushNext()
	if request.Command == protocol.RequestCommandMux {
		worker := multiplex.NewServerWorker(ctx, dispatcher.DispatchLink, &transport.Link{Reader: body, Writer: bodyWriter})
		<-worker.WaitClosed()
		if err := worker.Err(); err != nil {
			return errors.New("connection ends").Base(err)
		}
		return nil
	}
	output := &responseWriter{Writer: bodyWriter, ctx: ctx, cancel: cancel}
	if err := dispatcher.DispatchLink(ctx, request.Destination(), &transport.Link{Reader: body, Writer: output}); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	if err := context.Cause(ctx); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
