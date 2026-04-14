package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"reflect"
	"strings"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/xtess"
	"github.com/xtls/xray-core/proxy/xtess/encoding"
	"github.com/xtls/xray-core/proxy/xtess/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse
}

func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil || len(config.Vnext) == 0 {
		return nil, errors.New(`no vnext found`)
	}
	if len(config.Vnext) != 1 {
		return nil, errors.New(`XTESS settings: "vnext" should have one and only one member`).AtError()
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext[0])
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	a := handler.server.User.Account.(*xtess.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, err := base64.RawURLEncoding.DecodeString(r)
			if err != nil {
				return nil, errors.New("invalid base64 in encryption config").Base(err).AtError()
			}
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		rvsCtx := session.ContextWithInbound(ctx, &session.Inbound{
			Tag:  a.Reverse.Tag,
			User: handler.server.User,
		})
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx:        rvsCtx,
			handler:    handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		go func() {
			time.Sleep(2 * time.Second)
			handler.reverse.Start()
		}()
	}

	return handler, nil
}

func (h *Handler) Close() error {
	if h.reverse != nil {
		return h.reverse.Close()
	}
	return nil
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	inboundTag := ""
	if ib := session.InboundFromContext(ctx); ib != nil {
		inboundTag = ib.Tag
	}

	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "xtess"

	rec := h.server
	var conn stat.Connection
	if err := retry.ExponentialBackoff(5, 200).On(func() error {
		var err error
		conn, err = dialer.Dial(ctx, rec.Destination)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return errors.New("failed to find an available destination").Base(err).AtWarning()
	}
	defer conn.Close()

	ob.Conn = conn

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	if command == protocol.RequestCommandUDP && (target.Port == 53 || target.Port == 853 || target.Port == 443) && (inboundTag != "dns-module") && xtess.DefaultXORKey != nil && len(xtess.DefaultXORKey) > 0 {
		if request.Address.Family().IsIP() {
			ip := request.Address.IP()
			newIp := make([]byte, len(ip))
			copy(newIp, ip)
			xtess.MakeXORTransformByte(xtess.DefaultXORKey[0])(newIp)
			request.Address = net.IPAddress(newIp)
		}
	}

	if command == protocol.RequestCommandTCP && (target.Port == 5222 || target.Port == 853 || target.Port == 443) && (inboundTag != "dns-module") && xtess.DefaultXORKey != nil && len(xtess.DefaultXORKey) > 0 {
		if request.Address.Family().IsIP() {
			ip := request.Address.IP()
			newIp := make([]byte, len(ip))
			copy(newIp, ip)
			xtess.MakeXORTransformByte(xtess.DefaultXORKey[0])(newIp)
			request.Address = net.IPAddress(newIp)
		}
	}

	account := request.User.Account.(*xtess.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case xtess.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case xtess.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough
		case protocol.RequestCommandTCP:
			var t reflect.Type
			var p uintptr
			if commonConn, ok := conn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.CanSpliceCopy = 3
				}
				t = reflect.TypeOf(commonConn).Elem()
				p = uintptr(unsafe.Pointer(commonConn))
			} else if tlsConn, ok := iConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(tlsConn.Conn))
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(utlsConn.Conn))
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(realityConn.Conn))
			} else {
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
		}
	default:
		ob.CanSpliceCopy = 3
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader
	clientWriter := link.Writer

	if xtess.DefaultXORKey != nil && len(xtess.DefaultXORKey) > 0 {
		t := xtess.MakeXORTransformByte(xtess.DefaultXORKey[0])

		clientReader = xtess.NewTransformReader(clientReader, t)
		clientWriter = xtess.NewTransformWriter(clientWriter, t)
	}

	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == xtess.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == xtess.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage XTESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out xtess header separately from first payload")
		}
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == xtess.XRV {
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
		}
		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == xtess.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == xtess.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == xtess.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	tag         string
	dispatcher  routing.Dispatcher
	ctx         context.Context
	handler     *Handler
	workers     []*reverse.BridgeWorker
	monitorTask *task.Periodic
}

func (r *Reverse) monitor() error {
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range r.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	if len(activeWorkers) != len(r.workers) {
		r.workers = activeWorkers
	}

	var numConnections uint32
	var numWorker uint32
	for _, w := range r.workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(r.ctx, w, link1)
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.workers = append(r.workers, w)
		go func() {
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
	}
	return nil
}

func (r *Reverse) Start() error {
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	return r.monitorTask.Close()
}
