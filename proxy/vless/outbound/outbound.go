package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"strings"
	"sync"
	"time"

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
	encryption    *encryption.ClientInstance
	closeReverse  func()
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

	muxConfig, err := multiplex.NormalizeConfig(config.Multiplex)
	if err != nil {
		return nil, err
	}
	a := server.User.Account.(*vless.MemoryAccount)
	dialer, _ := session.FullHandlerFromContext(ctx).(internet.Dialer)
	if dialer == nil && (a.Reverse != nil || muxConfig != nil) {
		return nil, errors.New("VLESS Reverse or multiplex requires an outbound dialer")
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	handler.ctx, handler.stop = context.WithCancel(context.Background())

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

	if a.Reverse == nil {
		handler.testpre = a.Testpre
	} else {
		rvsCtx := session.ContextWithInbound(ctx, &session.Inbound{
			Tag:           a.Reverse.Tag,
			Name:          "vless-reverse",
			User:          handler.server.User, // TODO: email
			CanSpliceCopy: 3,
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
		handler.closeReverse = reverse.StartIntranet(rvsCtx,
			v.GetFeature(routing.DispatcherType()).(routing.Dispatcher).DispatchLink,
			func(ctx context.Context) (context.Context, *transport.Link, error) {
				return handler.process(ctx, nil, dialer, protocol.RequestCommandRvs)
			})
	}

	if muxConfig != nil {
		network := ""
		if settings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok {
			network = settings.ProtocolName
		}
		handler.multiplex = multiplex.NewClient(handler.ctx, muxConfig, network,
			func(ctx context.Context) (context.Context, *transport.Link, error) {
				return handler.process(ctx, nil, dialer, protocol.RequestCommandMux)
			})
	}

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	h.stop()
	if h.closeReverse != nil {
		h.closeReverse()
	}
	return nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	if handled, err := h.multiplex.Dispatch(ctx, link); handled {
		return err
	}
	_, _, err := h.process(ctx, link, dialer, 0)
	return err
}

func (h *Handler) process(ctx context.Context, link *transport.Link, dialer internet.Dialer, command protocol.RequestCommand) (nativeCtx context.Context, nativeLink *transport.Link, err error) {
	native := command != 0
	if native {
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: h.server.Destination}})
	}
	ctx, cancel := context.WithCancel(ctx)
	var rawConn stat.Connection
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

	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return nil, nil, errors.New("target not specified")
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection

	account := rec.User.Account.(*vless.MemoryAccount)

	if !native && ob.Target.Network == net.Network_UDP && ob.Target.Port == 443 && account.Flow == vless.XRV {
		proxy.DropUDP(ctx, link.Reader)
		return nil, nil, errors.New("XTLS rejected UDP/443 traffic")
	}

	if h.testpre > 0 {
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
		context.AfterFunc(ctx, func() { common.Interrupt(stat.TryUnwrapStatsConn(rawConn)) })
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

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
	}
	if !native {
		request.Command = protocol.RequestCommandTCP
		if target.Network == net.Network_UDP {
			request.Command = protocol.RequestCommandUDP
		}
		request.Address, request.Port = target.Address, target.Port
	}

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput **bytes.Buffer
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
		case protocol.RequestCommandTCP, protocol.RequestCommandMux, protocol.RequestCommandRvs:
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
	if !native && session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	timer = signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	if requestAddons.Flow == vless.XRV {
		if outerTLS, ok := iConn.(interface {
			tls.Interface
			ConnectionState() gotls.ConnectionState
		}); ok {
			if err := outerTLS.HandshakeContext(ctx); err != nil {
				return nil, nil, errors.New("failed outer TLS handshake for Vision").Base(err)
			}
			if version := outerTLS.ConnectionState().Version; version != gotls.VersionTLS13 {
				return nil, nil, errors.New("failed to use "+requestAddons.Flow+", found outer tls version ", version)
			}
		}
	}

	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	singleXUDP := request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || request.Port != 53 && request.Port != 443)
	if singleXUDP {
		request.Command = protocol.RequestCommandMux
	}

	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
		return nil, nil, errors.New("failed to encode request header").Base(err)
	}

	// default: serverWriter := bufferWriter
	serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
	if singleXUDP {
		serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
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
		if singleXUDP {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		return serverReader, nil
	}

	if native {
		bufferWriter.SetFlushNext()
		if request.Command == protocol.RequestCommandRvs {
			timer.Update()
			if requestAddons.Flow == vless.XRV {
				if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{nil}); err != nil {
					return nil, nil, err
				}
			}
			if err := bufferWriter.SetBuffered(false); err != nil {
				return nil, nil, err
			}
		}
		directLink, openErr := multiplex.OpenLink(ctx, cancel, serverWriter, timer, openResponse)
		if openErr != nil {
			return nil, nil, openErr
		}
		return ctx, directLink, nil
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

		return nil
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
