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

var sockoptDialers map[string]*dialerInstance
var dialerServers map[string]*dialerServer
var dialerTags map[string]string
var mu sync.RWMutex

const browserDialerSubprotocol = "browser-dialer"

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func HasBrowserDialerWithAddress(addr string) bool {
	_, _, ok := parseBrowserDialerAddress(addr)
	return ok
}

func GetAddressByTag(tag string) (string, bool) {
	if tag == "" {
		return "", false
	}
	mu.RLock()
	defer mu.RUnlock()
	addr, ok := dialerTags[tag]
	return addr, ok
}

func ConfigureDialerTags(tags map[string]string) error {
	next := make(map[string]string, len(tags))
	for tag, addr := range tags {
		if tag == "" {
			return errors.New("browserDialers tag cannot be empty")
		}
		if addr == "" {
			return errors.New("browserDialers url cannot be empty for tag: ", tag)
		}
		if err := EnsureDialerWithAddress(addr); err != nil {
			return errors.New("invalid browserDialers entry for tag ", tag).Base(err)
		}
		next[tag] = addr
	}

	mu.Lock()
	dialerTags = next
	mu.Unlock()
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
}

func parseBrowserDialerAddress(addr string) (string, string, bool) {
	if addr == "" {
		return "", "", false
	}

	listenAddr, pathRaw, ok := strings.Cut(addr, "/")
	if !ok || listenAddr == "" || pathRaw == "" {
		return "", "", false
	}

	path := "/" + strings.TrimSuffix(pathRaw, "/")
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		return "", "", false
	}
	parsedPath, err := url.ParseRequestURI(path)
	if err != nil || parsedPath.RawQuery != "" || parsedPath.Fragment != "" {
		return "", "", false
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
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := dialer.server.Serve(listener); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
			errors.LogError(context.Background(), "Browser dialer http server unexpected error on ", dialer.server.Addr, ": ", err)
		}
	}()
	return dialer, nil
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
		return nil, errors.New("invalid sockopt.browserDialer: ", addr)
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, errors.New("invalid sockopt.browserDialer listen address: ", listenAddr)
	}

	key := listenAddr + path

	mu.Lock()
	defer mu.Unlock()

	if sockoptDialers == nil {
		sockoptDialers = make(map[string]*dialerInstance)
	}
	if dialerServers == nil {
		dialerServers = make(map[string]*dialerServer)
	}
	if dialer, found := sockoptDialers[key]; found {
		return dialer, nil
	}

	server, found := dialerServers[listenAddr]
	if !found {
		for existingAddr := range dialerServers {
			_, existingPort, splitErr := net.SplitHostPort(existingAddr)
			if splitErr == nil && existingPort == port {
				return nil, errors.New("sockopt.browserDialer cannot use the same port with a different listen address: ", existingAddr, " and ", listenAddr)
			}
		}
		newServer, serverErr := newDialerServer(listenAddr)
		if serverErr != nil {
			return nil, serverErr
		}
		server = newServer
		dialerServers[listenAddr] = server
	}

	dialer := &dialerInstance{
		conns: make(chan *websocket.Conn, 256),
		page:  bytes.ReplaceAll(webpage, []byte("dialerPath"), []byte(strings.TrimPrefix(path, "/"))),
	}
	sockoptDialers[key] = dialer
	server.pageRoutes[path] = dialer
	return dialer, nil
}

func EnsureDialerWithAddress(addr string) error {
	if addr == "" {
		return nil
	}
	_, err := getDialerByAddress(addr)
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
		return nil, errors.New("browser dialer is not configured; set sockopt.browserDialer")
	}
	dialer, err := getDialerByAddress(addr)
	if err != nil || dialer == nil {
		return nil, errors.New("browser dialer is not configured for sockopt.browserDialer: ", addr)
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
