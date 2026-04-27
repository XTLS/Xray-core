package browser_dialer

import (
	"bytes"
	"context"
	stderrors "errors"
	"net"
	"net/http"
	"net/url"
	pathlib "path"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
)

var dialersByAddress = map[string]*dialerInstance{}
var serversByListenAddr = map[string]*dialerServer{}
var initialized bool
var pendingURLs map[string]struct{}

const browserDialerSubprotocol = "browser-dialer"

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func CheckLegacyEnv() error {
	envAddress := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	if envAddress == "" {
		return nil
	}
	return errors.PrintRemovedFeatureError("env "+platform.BrowserDialerAddress, "sockopt.dialerProxy with browser://host:port/uuid")
}

func IsBrowserDialerProxy(raw string) bool {
	_, _, ok := parseBrowserDialerAddress(raw)
	return ok
}

func BeginCollectingDialerProxyURLs() error {
	if initialized {
		return errors.New("browser dialer does not support dynamic add/remove; restart is required after changing configuration")
	}
	if err := CheckLegacyEnv(); err != nil {
		return err
	}
	pendingURLs = map[string]struct{}{}
	return nil
}

func RegisterDialerProxyURL(raw string) error {
	if !IsBrowserDialerProxy(raw) {
		return nil
	}
	if pendingURLs == nil {
		return errors.New("browser dialer url collection is not initialized")
	}
	pendingURLs[raw] = struct{}{}
	return nil
}

func ConfigureCollectedDialerProxyURLs() error {
	if initialized {
		return errors.New("browser dialer does not support dynamic add/remove; restart is required after changing configuration")
	}
	if err := CheckLegacyEnv(); err != nil {
		return err
	}
	listenAddrByPort := make(map[string]string, len(pendingURLs))
	for browserDialerURL := range pendingURLs {
		listenAddr, _, ok := parseBrowserDialerAddress(browserDialerURL)
		if !ok {
			return errors.New("invalid browser dialer url: ", browserDialerURL)
		}
		_, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return errors.New("invalid browser dialer listen address: ", listenAddr)
		}
		if existingAddr, found := listenAddrByPort[port]; found && existingAddr != listenAddr {
			return errors.New("browser dialer cannot use the same port with a different listen address: ", existingAddr, " and ", listenAddr)
		}
		listenAddrByPort[port] = listenAddr
	}
	for existingAddr := range serversByListenAddr {
		_, existingPort, splitErr := net.SplitHostPort(existingAddr)
		if splitErr != nil {
			continue
		}
		if newAddr, found := listenAddrByPort[existingPort]; found && newAddr != existingAddr {
			return errors.New("browser dialer cannot use the same port with a different listen address: ", existingAddr, " and ", newAddr)
		}
	}
	for browserDialerURL := range pendingURLs {
		if _, err := ensureDialerWithAddress(browserDialerURL); err != nil {
			return errors.New("failed to initialize browser dialer listener for url ", browserDialerURL).Base(err)
		}
	}
	return nil
}

// StartCollectedDialerProxyURLs starts listeners for browser dialer URLs
// prepared by ConfigureCollectedDialerProxyURLs.
// Subsequent calls after successful initialization return nil.
func StartCollectedDialerProxyURLs() error {
	if initialized {
		return nil
	}
	for listenAddr, server := range serversByListenAddr {
		if err := server.start(); err != nil {
			return errors.New("failed to start browser dialer listener on ", listenAddr).Base(err)
		}
	}
	initialized = true
	return nil
}

func StopCollectedDialerProxyURLs() error {
	var stopErrs []string
	for listenAddr, server := range serversByListenAddr {
		if err := server.stop(); err != nil {
			stopErrs = append(stopErrs, serial.Concat("failed to stop browser dialer listener on ", listenAddr, ": ", err))
		}
	}
	dialersByAddress = map[string]*dialerInstance{}
	serversByListenAddr = map[string]*dialerServer{}
	pendingURLs = nil
	initialized = false
	if len(stopErrs) > 0 {
		return errors.New(strings.Join(stopErrs, "; "))
	}
	return nil
}

type dialerInstance struct {
	conns chan *websocket.Conn
	page  []byte
}

type dialerServer struct {
	server     *http.Server
	pageRoutes map[string]*dialerInstance
	started    bool
}

func parseBrowserDialerAddress(addr string) (string, string, bool) {
	if addr == "" {
		return "", "", false
	}

	parsedAddr, err := url.Parse(addr)
	if err != nil || !strings.EqualFold(parsedAddr.Scheme, "browser") || parsedAddr.Host == "" || parsedAddr.Path == "" || parsedAddr.RawQuery != "" || parsedAddr.Fragment != "" {
		return "", "", false
	}
	listenAddr := parsedAddr.Host
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		return "", "", false
	}
	path := strings.TrimSuffix(parsedAddr.Path, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	cleanPath := pathlib.Clean(path)
	if cleanPath == "." || cleanPath == "/" || cleanPath != path {
		return "", "", false
	}
	if strings.Count(cleanPath, "/") != 1 {
		return "", "", false
	}
	id := strings.TrimPrefix(cleanPath, "/")
	id = strings.ToLower(id)
	parsedUUID, err := uuid.ParseString(id)
	if err != nil || parsedUUID.String() != id {
		return "", "", false
	}
	return listenAddr, "/" + id, true
}

func newDialerServer(listenAddr string) (*dialerServer, error) {
	dialer := &dialerServer{
		pageRoutes: make(map[string]*dialerInstance),
	}
	dialer.server = &http.Server{
		Addr: listenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pageDialer := dialer.pageRoutes[r.URL.Path]

			if pageDialer != nil && websocket.IsWebSocketUpgrade(r) {
				ok := false
				for _, protocol := range websocket.Subprotocols(r) {
					if protocol == browserDialerSubprotocol {
						ok = true
						break
					}
				}
				if !ok {
					closeConnection(w)
					return
				}
				if conn, err := upgrader.Upgrade(w, r, http.Header{"Sec-WebSocket-Protocol": []string{browserDialerSubprotocol}}); err == nil {
					pageDialer.conns <- conn
				} else {
					errors.LogError(context.Background(), "Browser dialer http upgrade unexpected error: ", err)
				}
				return
			}

			if pageDialer != nil {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				if _, err := w.Write(pageDialer.page); err != nil {
					errors.LogError(context.Background(), "Browser dialer http page write unexpected error: ", err)
				}
				return
			}

			closeConnection(w)
		}),
	}
	return dialer, nil
}

func (d *dialerServer) start() error {
	if d.started {
		return nil
	}
	listener, err := net.Listen("tcp", d.server.Addr)
	if err != nil {
		return err
	}
	d.started = true
	go func() {
		if err := d.server.Serve(listener); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
			errors.LogError(context.Background(), "Browser dialer http server unexpected error on ", d.server.Addr, ": ", err)
		}
	}()
	return nil
}

func (d *dialerServer) stop() error {
	if !d.started {
		return nil
	}
	d.started = false
	return d.server.Close()
}

func closeConnection(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	conn.Close()
}

func getDialerByAddress(addr string) (*dialerInstance, error) {
	listenAddr, path, ok := parseBrowserDialerAddress(addr)
	if !ok {
		return nil, errors.New("invalid browser dialer url: ", addr)
	}
	key := listenAddr + path
	if dialer, found := dialersByAddress[key]; found {
		return dialer, nil
	}
	return nil, errors.New("browser dialer is not configured for url: ", addr)
}

func ensureDialerWithAddress(addr string) (*dialerInstance, error) {
	listenAddr, path, ok := parseBrowserDialerAddress(addr)
	if !ok {
		return nil, errors.New("invalid browser dialer url: ", addr)
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, errors.New("invalid browser dialer listen address: ", listenAddr)
	}

	key := listenAddr + path
	if dialer, found := dialersByAddress[key]; found {
		return dialer, nil
	}

	server, found := serversByListenAddr[listenAddr]
	if !found {
		for existingAddr := range serversByListenAddr {
			_, existingPort, splitErr := net.SplitHostPort(existingAddr)
			if splitErr == nil && existingPort == port {
				return nil, errors.New("browser dialer cannot use the same port with a different listen address: ", existingAddr, " and ", listenAddr)
			}
		}
		newServer, serverErr := newDialerServer(listenAddr)
		if serverErr != nil {
			return nil, serverErr
		}
		server = newServer
		serversByListenAddr[listenAddr] = server
	}

	dialer := &dialerInstance{
		conns: make(chan *websocket.Conn, 256),
		page:  bytes.ReplaceAll(webpage, []byte("dialerPath"), []byte(strings.TrimPrefix(path, "/"))),
	}
	dialersByAddress[key] = dialer
	server.pageRoutes[path] = dialer
	return dialer, nil
}
