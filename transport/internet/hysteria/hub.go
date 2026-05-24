package hysteria

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type httpHandler struct {
	sync.Mutex

	validator   *account.Validator
	config      *Config
	masqHandler http.Handler
	quicParams  *internet.QuicParams
	addConn     internet.ConnHandler
	conn        *quic.Conn

	auth bool
	user *protocol.MemoryUser
}

func (h *httpHandler) AuthHTTP(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost && r.Host == URLHost && r.URL.Path == URLPath {
		h.Lock()
		defer h.Unlock()

		if h.auth {
			w.Header().Set(ResponseHeaderUDPEnabled, strconv.FormatBool(h.validator != nil))
			w.Header().Set(CommonHeaderCCRX, strconv.FormatUint(h.quicParams.BrutalDown, 10))
			w.Header().Set(CommonHeaderPadding, AuthResponsePadding.String())
			w.WriteHeader(StatusAuthOK)
			return true
		}

		auth := r.Header.Get(RequestHeaderAuth)
		down, _ := strconv.ParseUint(r.Header.Get(CommonHeaderCCRX), 10, 64)

		var user *protocol.MemoryUser
		var ok bool
		if h.validator != nil && h.validator.GetCount() > 0 {
			user = h.validator.Get(auth)
		} else if h.config.Auth != "" {
			ok = auth == h.config.Auth
		}

		if user != nil || ok {
			h.auth = true
			h.user = user

			conn := h.conn
			quicParams := h.quicParams
			switch quicParams.Congestion {
			case "reno":
			case "bbr":
				congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
			case "", "brutal":
				if quicParams.BrutalUp == 0 || down == 0 {
					congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
				} else {
					congestion.UseBrutal(conn, min(quicParams.BrutalUp, down))
				}
			case "force-brutal":
				congestion.UseBrutal(conn, quicParams.BrutalUp)
			default:
				panic(quicParams.Congestion)
			}

			if h.validator != nil {
				udpSM := &udpSessionManager{
					conn: h.conn,
					m:    make(map[uint32]*InterConn),

					addConn:        h.addConn,
					udpIdleTimeout: time.Duration(h.config.UdpIdleTimeout) * time.Second,
					user:           h.user,
				}
				go udpSM.clean()
				go udpSM.run()
			}

			w.Header().Set(ResponseHeaderUDPEnabled, strconv.FormatBool(h.validator != nil))
			w.Header().Set(CommonHeaderCCRX, strconv.FormatUint(h.quicParams.BrutalDown, 10))
			w.Header().Set(CommonHeaderPadding, AuthResponsePadding.String())
			w.WriteHeader(StatusAuthOK)
			return true
		}
	}
	return false
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.AuthHTTP(w, r) {
		return
	}
	h.masqHandler.ServeHTTP(w, r)
}

func (h *httpHandler) StreamDispatcher(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil || !h.auth {
		return false, nil
	}

	switch ft {
	case FrameTypeTCPRequest:
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}

		h.addConn(&interConn{
			stream: stream,
			local:  h.conn.LocalAddr(),
			remote: h.conn.RemoteAddr(),

			user: h.user,
		})
		return true, nil
	default:
		return false, nil
	}
}

type Listener struct {
	validator   *account.Validator
	config      *Config
	masqHandler http.Handler
	quicParams  *internet.QuicParams
	addConn     internet.ConnHandler

	pktConn  net.PacketConn
	tr       *quic.Transport
	listener *quic.Listener
}

func (l *Listener) handleClient(conn *quic.Conn) {
	handler := &httpHandler{
		validator:   l.validator,
		config:      l.config,
		masqHandler: l.masqHandler,
		quicParams:  l.quicParams,
		addConn:     l.addConn,
		conn:        conn,
	}
	h3s := http3.Server{
		Handler:          handler,
		StreamDispatcher: handler.StreamDispatcher,
	}
	_ = h3s.ServeQUICConn(conn)
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			if err != quic.ErrServerClosed {
				errors.LogErrorInner(context.Background(), err, "failed to serve hysteria")
			}
			break
		}
		go l.handleClient(conn)
	}
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) Close() error {
	return errors.Combine(l.listener.Close(), l.tr.Close(), l.pktConn.Close())
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("address is domain")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	validator := ValidatorFromContext(ctx)
	config := streamSettings.ProtocolSettings.(*Config)

	if validator == nil && config.Auth == "" {
		return nil, errors.New("validator is nil")
	}

	var masqHandler http.Handler
	switch strings.ToLower(config.MasqType) {
	case "", "404":
		masqHandler = http.NotFoundHandler()
	case "file":
		masqHandler = http.FileServer(http.Dir(config.MasqFile))
	case "proxy":
		u, err := url.Parse(config.MasqUrl)
		if err != nil {
			return nil, err
		}
		transport := http.DefaultTransport.(*http.Transport)
		if config.MasqUrlInsecure {
			transport = transport.Clone()
			transport.TLSClientConfig = &gotls.Config{
				InsecureSkipVerify: true,
			}
		}
		masqHandler = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				if !config.MasqUrlRewriteHost {
					pr.Out.Host = pr.In.Host
				}
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			},
		}
	case "string":
		masqHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range config.MasqStringHeaders {
				w.Header().Set(k, v)
			}
			if config.MasqStringStatusCode != 0 {
				w.WriteHeader(int(config.MasqStringStatusCode))
			} else {
				w.WriteHeader(http.StatusOK)
			}
			_, _ = w.Write([]byte(config.MasqString))
		})
	default:
		return nil, errors.New("unknown masq type")
	}

	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
			UdpHop:     &internet.UdpHop{},
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		MaxIncomingStreams:             quicParams.MaxIncomingStreams,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           MaxDatagramFrameSize,
		AssumePeerMaxDatagramFrameSize: MaxDatagramFrameSize,
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = 8388608
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = 8388608
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	if quicParams.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = 1024
	}

	pktConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if streamSettings.UdpmaskManager != nil {
		newConn, err := streamSettings.UdpmaskManager.WrapPacketConnServer(pktConn)
		if err != nil {
			pktConn.Close()
			return nil, errors.New("mask err").Base(err)
		}
		pktConn = newConn
	}

	tr := &quic.Transport{Conn: pktConn}

	listener, err := tr.Listen(tlsConfig.GetTLSConfig(), quicConfig)
	if err != nil {
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, err
	}

	l := &Listener{
		validator:   validator,
		config:      config,
		masqHandler: masqHandler,
		quicParams:  quicParams,
		addConn:     handler,

		pktConn:  pktConn,
		tr:       tr,
		listener: listener,
	}

	go l.keepAccepting()

	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
