package splithttp

import (
	"context"
	"crypto/tls"
	"io"
	gonet "net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type requestHandler struct {
	config    *Config
	host      string
	path      string
	ln        *Listener
	sessionMu *sync.Mutex
	sessions  sync.Map
	localAddr gonet.TCPAddr
}

type httpSession struct {
	uploadQueue *uploadQueue
	// for as long as the GET request is not opened by the client, this will be
	// open ("undone"), and the session may be expired within a certain TTL.
	// after the client connects, this becomes "done" and the session lives as
	// long as the GET request.
	isFullyConnected *done.Instance
}

func (h *requestHandler) maybeReapSession(isFullyConnected *done.Instance, sessionId string) {
	shouldReap := done.New()
	go func() {
		time.Sleep(30 * time.Second)
		shouldReap.Close()
	}()

	select {
	case <-isFullyConnected.Wait():
		return
	case <-shouldReap.Wait():
		h.sessions.Delete(sessionId)
	}
}

func (h *requestHandler) upsertSession(sessionId string) *httpSession {
	// fast path
	currentSessionAny, ok := h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	// slow path
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	currentSessionAny, ok = h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	s := &httpSession{
		uploadQueue:      NewUploadQueue(h.ln.config.GetNormalizedScMaxBufferedPosts()),
		isFullyConnected: done.New(),
	}

	h.sessions.Store(sessionId, s)
	go h.maybeReapSession(s.isFullyConnected, sessionId)
	return s
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if len(h.host) > 0 && !internet.IsValidHTTPHost(request.Host, h.host) {
		errors.LogInfo(context.Background(), "failed to validate host, request:", request.Host, ", config:", h.host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if !strings.HasPrefix(request.URL.Path, h.path) {
		errors.LogInfo(context.Background(), "failed to validate path, request:", request.URL.Path, ", config:", h.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	h.config.WriteResponseHeader(writer)

	validRange := h.config.GetNormalizedXPaddingBytes()
	x_padding := int32(len(request.URL.Query().Get("x_padding")))
	if validRange.To > 0 && (x_padding < validRange.From || x_padding > validRange.To) {
		errors.LogInfo(context.Background(), "invalid x_padding length:", x_padding)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionId := ""
	subpath := strings.Split(request.URL.Path[len(h.path):], "/")
	if len(subpath) > 0 {
		sessionId = subpath[0]
	}

	if sessionId == "" && h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-one" && h.config.Mode != "stream-up" {
		errors.LogInfo(context.Background(), "stream-one mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	forwardedAddrs := http_proto.ParseXForwardedFor(request.Header)
	remoteAddr, err := gonet.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		remoteAddr = &gonet.TCPAddr{}
	}
	if len(forwardedAddrs) > 0 && forwardedAddrs[0].Family().IsIP() {
		remoteAddr = &net.TCPAddr{
			IP:   forwardedAddrs[0].IP(),
			Port: int(0),
		}
	}

	var currentSession *httpSession
	if sessionId != "" {
		currentSession = h.upsertSession(sessionId)
	}
	scMaxEachPostBytes := int(h.ln.config.GetNormalizedScMaxEachPostBytes().To)

	if request.Method == "POST" && sessionId != "" {
		seq := ""
		if len(subpath) > 1 {
			seq = subpath[1]
		}

		if seq == "" {
			if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-up" {
				errors.LogInfo(context.Background(), "stream-up mode is not allowed")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			err = currentSession.uploadQueue.Push(Packet{
				Reader: request.Body,
			})
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to upload (PushReader)")
				writer.WriteHeader(http.StatusConflict)
			} else {
				writer.WriteHeader(http.StatusOK)
				<-request.Context().Done()
			}
			return
		}

		if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "packet-up" {
			errors.LogInfo(context.Background(), "packet-up mode is not allowed")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		payload, err := io.ReadAll(request.Body)

		if len(payload) > scMaxEachPostBytes {
			errors.LogInfo(context.Background(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request had size ", len(payload), ". Adjust scMaxEachPostBytes on the server to be at least as large as client.")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (ReadAll)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		seqInt, err := strconv.ParseUint(seq, 10, 64)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (ParseUint)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Payload: payload,
			Seq:     seqInt,
		})

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (PushPayload)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.WriteHeader(http.StatusOK)
	} else if request.Method == "GET" || sessionId == "" {
		responseFlusher, ok := writer.(http.Flusher)
		if !ok {
			panic("expected http.ResponseWriter to be an http.Flusher")
		}

		if sessionId != "" {
			// after GET is done, the connection is finished. disable automatic
			// session reaping, and handle it in defer
			currentSession.isFullyConnected.Close()
			defer h.sessions.Delete(sessionId)
		}

		// magic header instructs nginx + apache to not buffer response body
		writer.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		writer.Header().Set("Cache-Control", "no-store")

		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			writer.Header().Set("Content-Type", "text/event-stream")
		}

		writer.WriteHeader(http.StatusOK)

		responseFlusher.Flush()

		downloadDone := done.New()

		conn := splitConn{
			writer: &httpResponseBodyWriter{
				responseWriter:  writer,
				downloadDone:    downloadDone,
				responseFlusher: responseFlusher,
			},
			reader:     request.Body,
			remoteAddr: remoteAddr,
		}
		if sessionId != "" {
			conn.reader = currentSession.uploadQueue
		}

		h.ln.addConn(stat.Connection(&conn))

		// "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
		select {
		case <-request.Context().Done():
		case <-downloadDone.Wait():
		}

		conn.Close()
	} else {
		errors.LogInfo(context.Background(), "unsupported method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type httpResponseBodyWriter struct {
	sync.Mutex
	responseWriter  http.ResponseWriter
	responseFlusher http.Flusher
	downloadDone    *done.Instance
}

func (c *httpResponseBodyWriter) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.downloadDone.Done() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.responseWriter.Write(b)
	if err == nil {
		c.responseFlusher.Flush()
	}
	return n, err
}

func (c *httpResponseBodyWriter) Close() error {
	c.Lock()
	defer c.Unlock()
	c.downloadDone.Close()
	return nil
}

type Listener struct {
	sync.Mutex
	server     http.Server
	h3server   *http3.Server
	listener   net.Listener
	h3listener *quic.EarlyListener
	config     *Config
	addConn    internet.ConnHandler
	isH3       bool
}

func ListenSH(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: addConn,
	}
	shSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = shSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
	}
	var listener net.Listener
	var err error
	var localAddr = gonet.TCPAddr{}
	handler := &requestHandler{
		config:    shSettings,
		host:      shSettings.Host,
		path:      shSettings.GetNormalizedPath(),
		ln:        l,
		sessionMu: &sync.Mutex{},
		sessions:  sync.Map{},
		localAddr: localAddr,
	}
	tlsConfig := getTLSConfig(streamSettings)
	l.isH3 = len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3"

	if port == net.Port(0) { // unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UNIX domain socket for XHTTP on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening UNIX domain socket for XHTTP on ", address)
	} else if l.isH3 { // quic
		Conn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UDP for XHTTP/3 on ", address, ":", port).Base(err)
		}
		h3listener, err := quic.ListenEarly(Conn, tlsConfig, nil)
		if err != nil {
			return nil, errors.New("failed to listen QUIC for XHTTP/3 on ", address, ":", port).Base(err)
		}
		l.h3listener = h3listener
		errors.LogInfo(ctx, "listening QUIC for XHTTP/3 on ", address, ":", port)

		l.h3server = &http3.Server{
			Handler: handler,
		}
		go func() {
			if err := l.h3server.ServeListener(l.h3listener); err != nil {
				errors.LogWarningInner(ctx, err, "failed to serve HTTP/3 for XHTTP/3")
			}
		}()
	} else { // tcp
		localAddr = gonet.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP for XHTTP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP for XHTTP on ", address, ":", port)
	}

	// tcp/unix (h1/h2)
	if listener != nil {
		if config := v2tls.ConfigFromStreamSettings(streamSettings); config != nil {
			if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
				listener = tls.NewListener(listener, tlsConfig)
			}
		}

		if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
			listener = goreality.NewListener(listener, config.GetREALITYConfig())
		}

		// h2cHandler can handle both plaintext HTTP/1.1 and h2c
		h2cHandler := h2c.NewHandler(handler, &http2.Server{})
		l.listener = listener
		l.server = http.Server{
			Handler:           h2cHandler,
			ReadHeaderTimeout: time.Second * 4,
			MaxHeaderBytes:    8192,
		}

		go func() {
			if err := l.server.Serve(l.listener); err != nil {
				errors.LogWarningInner(ctx, err, "failed to serve HTTP for XHTTP")
			}
		}()
	}

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	if ln.h3listener != nil {
		return ln.h3listener.Addr()
	}
	if ln.listener != nil {
		return ln.listener.Addr()
	}
	return nil
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	if ln.h3server != nil {
		if err := ln.h3server.Close(); err != nil {
			return err
		}
	} else if ln.listener != nil {
		return ln.listener.Close()
	}
	return errors.New("listener does not have an HTTP/3 server or a net.listener")
}
func getTLSConfig(streamSettings *internet.MemoryStreamConfig) *tls.Config {
	config := v2tls.ConfigFromStreamSettings(streamSettings)
	if config == nil {
		return &tls.Config{}
	}
	return config.GetTLSConfig()
}
func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenSH))
}
