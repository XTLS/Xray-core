package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	proxymanConfig "github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
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
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/proxy/vless/reverse"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *reverse.Bridge
	ctx           context.Context
	stop          context.CancelFunc
	multiplex     *multiplex.Client

	testpre  uint32
	initpre  sync.Once
	preConns chan *ConnExpire
}

type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	handler.ctx, handler.stop = context.WithCancel(context.Background())

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err)
		}
	}

	if a.Reverse != nil {
		rvsCtx := session.ContextWithInbound(ctx, &session.Inbound{
			Tag:  a.Reverse.Tag,
			Name: "vless-reverse",
			User: handler.server.User, // TODO: email
		})
		if sc := a.Reverse.Sniffing; sc != nil && sc.Enabled {
			request, err := proxymanConfig.BuildSniffingRequest(sc)
			if err != nil {
				return nil, errors.New("failed to build reverse sniffing request").Base(err)
			}
			rvsCtx = session.ContextWithContent(rvsCtx, &session.Content{
				SniffingRequest: request,
			})
		}
		handler.reverse = reverse.NewBridge(rvsCtx, a.Reverse.Tag,
			v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			func(ctx context.Context) (context.Context, *transport.Link, error) {
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
					Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
				}})
				return handler.process(ctx, nil, session.FullHandlerFromContext(ctx).(internet.Dialer), true)
			})
		go func() {
			select {
			case <-handler.ctx.Done():
			case <-time.After(2 * time.Second):
				handler.reverse.Start()
			}
		}()
	}

	if config.Multiplex != nil {
		dialer := session.FullHandlerFromContext(ctx).(internet.Dialer)
		network := ""
		if settings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok {
			network = settings.ProtocolName
		}
		handler.multiplex = multiplex.NewClient(handler.ctx, config.Multiplex, network,
			func(ctx context.Context) (context.Context, *transport.Link, error) {
				return handler.process(ctx, nil, dialer, true)
			})
	}

	handler.testpre = a.Testpre

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	h.stop()
	if h.multiplex != nil {
		h.multiplex.Close()
	}
	if h.reverse != nil {
		return h.reverse.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	if handled, err := h.multiplex.Dispatch(ctx, link); handled || err != nil {
		return err
	}
	_, _, err := h.process(ctx, link, dialer, false)
	return err
}

func (h *Handler) process(ctx context.Context, link *transport.Link, dialer internet.Dialer, native bool) (nativeCtx context.Context, nativeLink *transport.Link, err error) {
	ctx, cancel := context.WithCancel(ctx)
	var rawConn stat.Connection
	var stopOpening func() bool
	var timer *signal.ActivityTimer
	defer func() {
		if !native || err != nil {
			if timer != nil {
				timer.SetTimeout(0)
			}
			cancel()
			if rawConn != nil {
				rawConn.Close()
			}
		}
	}()

	var opening *time.Timer
	if native {
		opening = time.AfterFunc(h.policyManager.ForLevel(h.server.User.Level).Timeouts.Handshake, cancel)
		defer opening.Stop()
	}
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return nil, nil, errors.New("target not specified")
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection

	if h.testpre > 0 && h.reverse == nil {
		h.initpre.Do(func() {
			h.preConns = make(chan *ConnExpire)
			for range h.testpre { // TODO: randomize
				go func() {
					ctx := xctx.ContextWithID(h.ctx, session.NewID())
					for ctx.Err() == nil {
						conn, err := dialer.Dial(ctx, rec.Destination)
						if err != nil {
							errors.LogWarningInner(ctx, err, "pre-connect failed")
							continue
						}
						select {
						case <-ctx.Done():
							conn.Close()
							return
						case h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)}:
						}
						time.Sleep(time.Millisecond * 200) // TODO: customize & randomize
					}
				}()
			}
		})
		for {
			var connTime *ConnExpire
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-h.ctx.Done():
				return nil, nil, h.ctx.Err()
			case connTime = <-h.preConns:
			}
			if time.Now().Before(connTime.Expire) {
				conn = connTime.Conn
				break
			}
			connTime.Conn.Close()
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return nil, nil, errors.New("failed to find an available destination").Base(err)
		}
	}
	rawConn = conn
	if native {
		stopOpening = context.AfterFunc(ctx, func() { common.Interrupt(stat.TryUnwrapStatsConn(rawConn)) })
	}

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return nil, nil, errors.New("ML-KEM-768 handshake failed").Base(err)
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if native && target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return nil, nil, errors.New("nice try baby")
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

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput **bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return nil, nil, errors.New("XTLS rejected UDP/443 traffic")
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			var target net.Conn
			if commonConn, ok := conn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.CanSpliceCopy = 3 // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
				}
				target = commonConn
			} else if tlsConn, ok := iConn.(*tls.Conn); ok {
				target = tlsConn.Conn
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				target = utlsConn.Conn
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				target = realityConn.Conn
			} else {
				return nil, nil, errors.New("XTLS only supports TLS and REALITY directly for now.")
			}
			input, rawInput = vless.AccessTLSBuffers(target)
		default:
			panic("unknown VLESS request command")
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
	timer = signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	requestWriter := buf.NewWriter(conn)
	if native && requestAddons.Flow == "" {
		requestWriter = multiplex.WrapWriter(ctx, cancel, requestWriter, timer)
	}
	bufferWriter := buf.NewBufferedWriter(requestWriter)
	if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
		return nil, nil, errors.New("failed to encode request header").Base(err)
	}

	// default: serverWriter := bufferWriter
	serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
	if request.Command == protocol.RequestCommandMux && request.Port == 666 {
		serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
	}

	if requestAddons.Flow == vless.XRV {
		if tlsConn, ok := iConn.(*tls.Conn); ok {
			if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
				return nil, nil, errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version)
			}
		} else if utlsConn, ok := iConn.(*tls.UConn); ok {
			if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
				return nil, nil, errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version)
			}
		}
	}

	postRequest := func() error {
		clientReader := link.Reader
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err)
		}

		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err)
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	openResponse := func() (buf.Reader, error) {
		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return nil, errors.New("failed to decode response header").Base(err)
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		return serverReader, nil
	}

	if native {
		receiveLimit := int32(64 * 1024)
		bufferWriter.SetFlushNext()
		if request.Command == protocol.RequestCommandRvs {
			receiveLimit = 2 * buf.Size
			if requestAddons.Flow == vless.XRV {
				if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{nil}); err != nil {
					return nil, nil, err
				}
			}
			if err := bufferWriter.SetBuffered(false); err != nil {
				return nil, nil, err
			}
		}
		if !opening.Stop() || !stopOpening() {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			return nil, nil, context.DeadlineExceeded
		}
		directLink, openErr := multiplex.OpenLink(ctx, cancel, rawConn, serverWriter, timer, receiveLimit, openResponse)
		if openErr != nil {
			return nil, nil, openErr
		}
		return ctx, directLink, nil
	}

	clientWriter := link.Writer
	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		serverReader, err := openResponse()
		if err != nil {
			return err
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err)
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return nil, nil, errors.New("connection ends").Base(err)
	}

	return nil, nil, nil
}
