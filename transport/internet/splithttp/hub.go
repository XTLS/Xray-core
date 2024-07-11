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

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type requestHandler struct {
	host      string
	path      string
	ln        *Listener
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
	currentSessionAny, ok := h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	s := &httpSession{
		uploadQueue:      NewUploadQueue(int(2 * h.ln.config.GetNormalizedMaxConcurrentUploads())),
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

	sessionId := ""
	subpath := strings.Split(request.URL.Path[len(h.path):], "/")
	if len(subpath) > 0 {
		sessionId = subpath[0]
	}

	if sessionId == "" {
		errors.LogInfo(context.Background(), "no sessionid on request:", request.URL.Path)
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

	currentSession := h.upsertSession(sessionId)

	if request.Method == "POST" {
		seq := ""
		if len(subpath) > 1 {
			seq = subpath[1]
		}

		if seq == "" {
			errors.LogInfo(context.Background(), "no seq on request:", request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		payload, err := io.ReadAll(request.Body)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		seqInt, err := strconv.ParseUint(seq, 10, 64)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Payload: payload,
			Seq:     seqInt,
		})

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.WriteHeader(http.StatusOK)
	} else if request.Method == "GET" {
		responseFlusher, ok := writer.(http.Flusher)
		if !ok {
			panic("expected http.ResponseWriter to be an http.Flusher")
		}

		// after GET is done, the connection is finished. disable automatic
		// session reaping, and handle it in defer
		currentSession.isFullyConnected.Close()
		defer h.sessions.Delete(sessionId)

		// magic header instructs nginx + apache to not buffer response body
		writer.Header().Set("X-Accel-Buffering", "no")
		// magic header to make the HTTP middle box consider this as SSE to disable buffer
		writer.Header().Set("Content-Type", "text/event-stream")

		writer.WriteHeader(http.StatusOK)
		// send a chunk immediately to enable CDN streaming.
		// many CDN buffer the response headers until the origin starts sending
		// the body, with no way to turn it off.
		writer.Write([]byte("ok"))
		responseFlusher.Flush()

		downloadDone := done.New()

		conn := splitConn{
			writer: &httpResponseBodyWriter{
				responseWriter:  writer,
				downloadDone:    downloadDone,
				responseFlusher: responseFlusher,
			},
			reader:     currentSession.uploadQueue,
			remoteAddr: remoteAddr,
		}

		h.ln.addConn(stat.Connection(&conn))

		// "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
		<-downloadDone.Wait()

	} else {
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
	server   http.Server
	listener net.Listener
	config   *Config
	addConn  internet.ConnHandler
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

	if port == net.Port(0) { // unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen unix domain socket(for SH) on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening unix domain socket(for SH) on ", address)
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
			return nil, errors.New("failed to listen TCP(for SH) on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP(for SH) on ", address, ":", port)
	}

	if config := v2tls.ConfigFromStreamSettings(streamSettings); config != nil {
		if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
	}

	handler := &requestHandler{
		host:      shSettings.Host,
		path:      shSettings.GetNormalizedPath(),
		ln:        l,
		sessions:  sync.Map{},
		localAddr: localAddr,
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
			errors.LogWarningInner(ctx, err, "failed to serve http for splithttp")
		}
	}()

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	return ln.listener.Addr()
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	return ln.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenSH))
}
