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
)

//go:embed dialer.html
var webpage []byte

type task struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	Extra          any    `json:"extra,omitempty"`
	StreamResponse bool   `json:"streamResponse"`
}

var sockoptDialers map[string]*dialerInstance
var dialerServers map[string]*dialerServer
var mu sync.RWMutex

const browserDialerSubprotocol = "browser-dialer"
const uuidPathLength = 37

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func HasBrowserDialerWithAddress(addr string) bool {
	_, ok := parseBrowserDialerAddress(addr)
	return ok
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
}

type dialerInstance struct {
	conns    chan *websocket.Conn
	pagePath string
	page     []byte
}

type dialerServer struct {
	server     *http.Server
	pageRoutes map[string]*dialerInstance
}

type browserDialerAddress struct {
	listenAddr string
	path       string
}

func parseBrowserDialerAddress(addr string) (*browserDialerAddress, bool) {
	if addr == "" {
		return nil, false
	}

	index := strings.Index(addr, "/")
	if index <= 0 {
		return nil, false
	}

	listenAddr := addr[:index]
	path := strings.TrimSuffix(addr[index:], "/")
	if path == "" {
		return nil, false
	}
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		return nil, false
	}
	parsedPath, err := url.ParseRequestURI(path)
	if err != nil || parsedPath.RawQuery != "" || parsedPath.Fragment != "" {
		return nil, false
	}
	cleanPath := pathlib.Clean(path)
	if cleanPath == "." || cleanPath == "/" || cleanPath != path {
		return nil, false
	}
	if !isUUIDPath(cleanPath) {
		return nil, false
	}

	return &browserDialerAddress{
		listenAddr: listenAddr,
		path:       cleanPath,
	}, true
}

func isUUIDPath(path string) bool {
	if len(path) != uuidPathLength || path[0] != '/' || strings.Count(path, "/") != 1 {
		return false
	}

	u := path[1:]
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}

	return true
}

func newDialerInstance(path string) *dialerInstance {
	page := bytes.ReplaceAll(webpage, []byte("dialerPath"), []byte(strings.TrimPrefix(path, "/")))
	dialer := &dialerInstance{
		conns:    make(chan *websocket.Conn, 256),
		pagePath: path,
		page:     page,
	}
	return dialer
}

func newDialerServer(listenAddr string) *dialerServer {
	dialer := &dialerServer{
		pageRoutes: make(map[string]*dialerInstance),
	}
	dialer.server = &http.Server{
		Addr: listenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.RLock()
			pageDialer := dialer.pageRoutes[r.URL.Path]
			mu.RUnlock()

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
	return dialer
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

func startDialerServer(dialer *dialerServer) {
	if dialer == nil || dialer.server == nil {
		return
	}
	go func() {
		if err := dialer.server.ListenAndServe(); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
			errors.LogError(context.Background(), "Browser dialer http server unexpected error on ", dialer.server.Addr, ": ", err)
		}
	}()
}

func closeDialerInstance(d *dialerInstance) {
	if d == nil {
		return
	}
	for {
		select {
		case c := <-d.conns:
			c.Close()
		default:
			return
		}
	}
}

func getDialerByAddress(addr string) *dialerInstance {
	parsed, ok := parseBrowserDialerAddress(addr)
	if !ok {
		return nil
	}

	key := parsed.listenAddr + parsed.path
	startServer := false

	mu.Lock()
	if sockoptDialers == nil {
		sockoptDialers = make(map[string]*dialerInstance)
	}
	if dialerServers == nil {
		dialerServers = make(map[string]*dialerServer)
	}
	if dialer, found := sockoptDialers[key]; found {
		mu.Unlock()
		return dialer
	}

	server, found := dialerServers[parsed.listenAddr]
	if !found {
		server = newDialerServer(parsed.listenAddr)
		dialerServers[parsed.listenAddr] = server
		startServer = true
	}

	dialer := newDialerInstance(parsed.path)
	sockoptDialers[key] = dialer
	server.pageRoutes[dialer.pagePath] = dialer
	mu.Unlock()

	if startServer {
		startDialerServer(server)
	}

	return dialer
}

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	return DialWSWithAddress("", uri, ed)
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

func DialGet(uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	return DialGetWithAddress("", uri, headers, cookies)
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

func DialPacket(method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	return DialPacketWithAddress("", method, uri, headers, cookies, payload)
}

func DialPacketWithAddress(addr string, method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	return dialWithBody(addr, method, uri, headers, cookies, payload)
}

func dialWithBody(addr string, method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
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

func dialTask(task task) (*websocket.Conn, error) {
	return dialTaskWithAddress("", task)
}

func dialTaskWithAddress(addr string, task task) (*websocket.Conn, error) {
	data, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}

	conns := connsByAddress(addr)
	if conns == nil {
		if addr != "" {
			return nil, errors.New("browser dialer is not configured for sockopt.browserDialer: ", addr)
		}
		return nil, errors.New("browser dialer is not configured; set sockopt.browserDialer")
	}

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

func connsByAddress(addr string) chan *websocket.Conn {
	if addr == "" {
		return nil
	}
	dialer := getDialerByAddress(addr)
	if dialer == nil {
		return nil
	}
	return dialer.conns
}

func notifyRemovedEnv() {
	envAddress := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	if envAddress == "" {
		return
	}
	errors.LogWarning(context.Background(), errors.PrintRemovedFeatureError("env "+platform.BrowserDialerAddress, "sockopt.browserDialer"))
}

func init() {
	notifyRemovedEnv()
}
