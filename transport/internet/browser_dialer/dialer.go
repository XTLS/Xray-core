package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"net"
	"net/http"
	"net/url"
	pathlib "path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

type task struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	Extra          any    `json:"extra,omitempty"`
	StreamResponse bool   `json:"streamResponse"`
}

var dialersByAddress = map[string]*dialerInstance{}
var serversByListenAddr = map[string]*dialerServer{}
var initMu sync.Mutex
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
	return errors.PrintRemovedFeatureError("env "+platform.BrowserDialerAddress, "sockopt.dialerProxy with http://host:port/uuid")
}

func IsBrowserDialerProxy(raw string) bool {
	_, _, ok := parseBrowserDialerAddress(raw)
	return ok
}

func BeginCollectingDialerProxyURLs() error {
	initMu.Lock()
	defer initMu.Unlock()

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
	initMu.Lock()
	defer initMu.Unlock()
	if pendingURLs == nil {
		return errors.New("browser dialer url collection is not initialized")
	}
	pendingURLs[raw] = struct{}{}
	return nil
}

func ConfigureCollectedDialerProxyURLs() error {
	initMu.Lock()
	defer initMu.Unlock()

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
		if err := EnsureDialerWithAddress(browserDialerURL); err != nil {
			return errors.New("failed to initialize browser dialer listener for url ", browserDialerURL).Base(err)
		}
	}
	for listenAddr, server := range serversByListenAddr {
		if err := server.start(); err != nil {
			return errors.New("failed to start browser dialer listener on ", listenAddr).Base(err)
		}
	}
	initialized = true
	return nil
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
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
	if err != nil || !strings.EqualFold(parsedAddr.Scheme, "http") || parsedAddr.Host == "" || parsedAddr.Path == "" || parsedAddr.RawQuery != "" || parsedAddr.Fragment != "" {
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
	if len(id) != 36 {
		return "", "", false
	}
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

func EnsureDialerWithAddress(addr string) error {
	if addr == "" {
		return nil
	}
	_, err := ensureDialerWithAddress(addr)
	return err
}

func DialWSWithAddress(addr string, uri string, ed []byte) (*websocket.Conn, error) {
	task := task{
		Method:         "WS",
		URL:            uri,
		StreamResponse: true,
	}

	if ed != nil {
		task.Extra = webSocketExtra{
			Protocol: base64.RawURLEncoding.EncodeToString(ed),
		}
	}

	return dialTaskWithAddress(addr, task)
}

type httpExtra struct {
	Referrer string            `json:"referrer,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Cookies  map[string]string `json:"cookies,omitempty"`
}

func httpExtraFromHeadersAndCookies(headers http.Header, cookies []*http.Cookie) *httpExtra {
	if len(headers) == 0 {
		return nil
	}

	extra := httpExtra{}
	if referrer := headers.Get("Referer"); referrer != "" {
		extra.Referrer = referrer
		headers.Del("Referer")
	}

	if len(headers) > 0 {
		extra.Headers = make(map[string]string)
		for header := range headers {
			extra.Headers[header] = headers.Get(header)
		}
	}

	if len(cookies) > 0 {
		extra.Cookies = make(map[string]string)
		for _, cookie := range cookies {
			extra.Cookies[cookie.Name] = cookie.Value
		}
	}

	return &extra
}

func DialGetWithAddress(addr string, uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	task := task{
		Method:         "GET",
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: true,
	}

	return dialTaskWithAddress(addr, task)
}

func DialPacketWithAddress(addr string, method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	task := task{
		Method:         method,
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: false,
	}

	conn, err := dialTaskWithAddress(addr, task)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.BinaryMessage, payload)
	if err != nil {
		return err
	}

	err = CheckOK(conn)
	if err != nil {
		return err
	}

	conn.Close()
	return nil
}

func dialTaskWithAddress(addr string, task task) (*websocket.Conn, error) {
	data, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}

	if addr == "" {
		return nil, errors.New("browser dialer is not configured; set sockopt.dialerProxy to http://host:port/uuid")
	}
	dialer, err := getDialerByAddress(addr)
	if err != nil {
		return nil, err
	}
	conns := dialer.conns

	var conn *websocket.Conn
	for {
		conn = <-conns
		if conn.WriteMessage(websocket.TextMessage, data) != nil {
			conn.Close()
		} else {
			break
		}
	}
	err = CheckOK(conn)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func CheckOK(conn *websocket.Conn) error {
	if _, p, err := conn.ReadMessage(); err != nil {
		conn.Close()
		return err
	} else if s := string(p); s != "ok" {
		conn.Close()
		return errors.New(s)
	}

	return nil
}
