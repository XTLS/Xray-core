package inbound

import (
	"context"
	goerrors "errors"
	"io"
	gonet "net"
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
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type userByEmail struct {
	sync.Mutex
	cache        map[string]*protocol.MemoryUser
	defaultLevel uint32
}

func newUserByEmail(config *DefaultConfig) *userByEmail {
	return &userByEmail{
		cache:        make(map[string]*protocol.MemoryUser),
		defaultLevel: config.Level,
	}
}

func (v *userByEmail) addNoLock(u *protocol.MemoryUser) bool {
	email := strings.ToLower(u.Email)
	_, found := v.cache[email]
	if found {
		return false
	}
	v.cache[email] = u
	return true
}

func (v *userByEmail) Add(u *protocol.MemoryUser) bool {
	v.Lock()
	defer v.Unlock()

	return v.addNoLock(u)
}

func (v *userByEmail) GetOrGenerate(email string) (*protocol.MemoryUser, bool) {
	email = strings.ToLower(email)

	v.Lock()
	defer v.Unlock()

	user, found := v.cache[email]
	if !found {
		id := uuid.New()
		rawAccount := &vmess.Account{
			Id: id.String(),
		}
		account, err := rawAccount.AsAccount()
		common.Must(err)
		user = &protocol.MemoryUser{
			Level:   v.defaultLevel,
			Email:   email,
			Account: account,
		}
		v.cache[email] = user
	}
	return user, found
}

func (v *userByEmail) Get(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	v.Lock()
	defer v.Unlock()
	return v.cache[email]
}

func (v *userByEmail) Remove(email string) bool {
	email = strings.ToLower(email)

	v.Lock()
	defer v.Unlock()

	if _, found := v.cache[email]; !found {
		return false
	}
	delete(v.cache, email)
	return true
}

// Handler is an inbound connection handler that handles messages in VMess protocol.
type Handler struct {
	policyManager         policy.Manager
	inboundHandlerManager feature_inbound.Manager
	clients               *vmess.TimedUserValidator
	usersByEmail          *userByEmail
	sessionHistory        *encoding.SessionHistory
}

// New creates a new VMess inbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		policyManager:         v.GetFeature(policy.ManagerType()).(policy.Manager),
		inboundHandlerManager: v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		clients:               vmess.NewTimedUserValidator(),
		usersByEmail:          newUserByEmail(config.GetDefaultValue()),
		sessionHistory:        encoding.NewSessionHistory(),
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
	return errors.Combine(
		h.sessionHistory.Close(),
		common.Close(h.usersByEmail),
	)
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (h *Handler) GetOrGenerateUser(email string) *protocol.MemoryUser {
	user, existing := h.usersByEmail.GetOrGenerate(email)
	if !existing {
		h.clients.Add(user)
	}
	return user
}

func (h *Handler) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return h.usersByEmail.Get(email)
}

func (h *Handler) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return h.clients.GetUsers()
}

func (h *Handler) GetUsersCount(context.Context) int64 {
	return h.clients.GetCount()
}

func (h *Handler) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if len(user.Email) > 0 && !h.usersByEmail.Add(user) {
		return errors.New("User ", user.Email, " already exists.")
	}
	return h.clients.Add(user)
}

func (h *Handler) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}
	if !h.usersByEmail.Remove(email) {
		return errors.New("User ", email, " not found.")
	}
	h.clients.Remove(email)
	return nil
}

// codecBody guards decoded input and owns raw interruption only when supplied.
type codecBody struct {
	ctx        context.Context
	reader     buf.Reader
	connection net.Conn
	stopped    atomic.Bool
}

func (b *codecBody) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if b.stopped.Load() {
		return nil, io.ErrClosedPipe
	}
	mb, err := b.reader.ReadMultiBuffer()
	if canceled := b.ctx.Err(); canceled != nil {
		buf.ReleaseMulti(mb)
		return nil, canceled
	}
	if b.stopped.Load() {
		buf.ReleaseMulti(mb)
		return nil, io.ErrClosedPipe
	}
	return mb, err
}

func (b *codecBody) Interrupt() {
	b.stopped.Store(true)
	if b.connection != nil {
		common.Interrupt(b.connection)
	}
}

// ordinaryResponse serializes codec writes and owns checked finalization.
// Interrupt never waits for its mutex.
type ordinaryResponse struct {
	sync.Mutex
	ctx         context.Context
	input       *codecBody
	body        buf.Writer
	output      *buf.BufferedWriter
	terminate   bool
	closed      bool
	wrote       bool
	interrupted atomic.Bool
	err         atomic.Pointer[error]
	done        *done.Instance
}

func (w *ordinaryResponse) remember(err error) error {
	if err != nil {
		w.err.CompareAndSwap(nil, &err)
		w.done.Close()
	}
	return err
}

func (w *ordinaryResponse) rememberIO(err error) error {
	if canceled := w.ctx.Err(); canceled != nil && (goerrors.Is(err, gonet.ErrClosed) || goerrors.Is(err, io.ErrClosedPipe)) {
		err = canceled
	}
	return w.remember(err)
}

func (w *ordinaryResponse) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		buf.ReleaseMulti(mb)
		return nil
	}
	w.Lock()
	defer w.Unlock()
	if terminal := w.err.Load(); terminal != nil {
		buf.ReleaseMulti(mb)
		return *terminal
	}
	if err := w.ctx.Err(); err != nil {
		buf.ReleaseMulti(mb)
		return w.remember(err)
	}
	if w.closed || w.interrupted.Load() {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	if err := w.body.WriteMultiBuffer(mb); err != nil {
		return w.rememberIO(err)
	}
	if !w.wrote {
		w.wrote = true
		return w.rememberIO(w.output.SetBuffered(false))
	}
	return nil
}

func (w *ordinaryResponse) Close() error {
	defer w.done.Close()
	w.Lock()
	defer w.Unlock()
	if terminal := w.err.Load(); terminal != nil {
		return *terminal
	}
	if err := w.ctx.Err(); err != nil {
		return w.remember(err)
	}
	if w.interrupted.Load() {
		return io.ErrClosedPipe
	}
	if w.closed {
		return nil
	}
	w.closed = true
	// The native first-response EOF flushes only the header, without a marker.
	if w.wrote && w.terminate {
		if err := w.body.WriteMultiBuffer(buf.MultiBuffer{}); err != nil {
			return w.rememberIO(err)
		}
	}
	return w.rememberIO(w.output.Flush())
}

func (w *ordinaryResponse) Interrupt() {
	w.interrupted.Store(true)
	w.done.Close()
	w.input.Interrupt()
}

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

	sessionPolicy = h.policyManager.ForLevel(request.User.Level)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(ctx, func() { common.Interrupt(iConn) })
	defer stopClose()

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	bodyReader, err := svrSession.DecodeRequestBody(request, reader)
	if err != nil {
		return errors.New("failed to start decoding").Base(err)
	}
	// Derive response keys in memory; socket failures must remain ordinary errors.
	header := buf.New()
	svrSession.EncodeResponseHeader(&protocol.ResponseHeader{}, header)
	wire := buf.NewBufferedWriter(buf.NewWriter(connection))
	bodyWriter, err := svrSession.EncodeResponseBody(request, wire)
	if err != nil {
		header.Release()
		return errors.New("failed to start decoding response").Base(err)
	}
	if err := wire.WriteMultiBuffer(buf.MultiBuffer{header}); err != nil {
		return errors.New("failed to prepare response header").Base(err)
	}
	if request.Command == protocol.RequestCommandMux {
		body := &codecBody{ctx: ctx, reader: bodyReader}
		// Start decoding before physical header I/O; wire orders header and body.
		worker := multiplex.NewServerWorker(ctx, dispatcher.DispatchLink, &transport.Link{Reader: body, Writer: bodyWriter})
		defer worker.Close()
		stopWorker := context.AfterFunc(worker.Context(), func() {
			if worker.Err() != nil {
				cancel()
			}
		})
		defer stopWorker()
		if err := wire.SetBuffered(false); err != nil {
			if canceled := ctx.Err(); canceled != nil {
				if cause := worker.Err(); cause != nil {
					err = cause
				} else {
					err = canceled
				}
			}
			cancel()
			return errors.New("failed to write response header").Base(err)
		}
		select {
		case <-ctx.Done():
		case <-worker.WaitClosed():
		}
		if err := worker.Err(); err != nil {
			return errors.New("connection ends").Base(err)
		}
		if err := ctx.Err(); err != nil {
			return errors.New("connection ends").Base(err)
		}
		return nil
	}
	account := request.User.Account.(*vmess.MemoryAccount)
	input := &codecBody{ctx: ctx, reader: bodyReader, connection: iConn}
	response := &ordinaryResponse{
		ctx: ctx, input: input, body: bodyWriter, output: wire,
		terminate: request.Option.Has(protocol.RequestOptionChunkStream) && !account.NoTerminationSignal,
		done:      done.New(),
	}
	if err := dispatcher.DispatchLink(ctx, request.Destination(), &transport.Link{Reader: input, Writer: response}); err != nil {
		response.remember(err)
		response.Interrupt()
	}
	select {
	case <-response.done.Wait():
	case <-ctx.Done():
	}
	if terminal := response.err.Load(); terminal != nil {
		return errors.New("connection ends").Base(*terminal)
	}
	if err := ctx.Err(); err != nil {
		return errors.New("connection ends").Base(err)
	}
	if response.interrupted.Load() {
		return errors.New("connection ends").Base(io.ErrClosedPipe)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
