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
var mu sync.Mutex

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func HasBrowserDialerWithAddress(addr string) bool {
	if addr == "" {
		return false
	}
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
}

type dialerInstance struct {
	conns  chan *websocket.Conn
	server *http.Server
}

func newDialerInstance(addr string) *dialerInstance {
	token := uuid.New()
	csrfToken := token.String()
	page := bytes.ReplaceAll(webpage, []byte("csrfToken"), []byte(csrfToken))
	wsPath := "/websocket/" + csrfToken
	dialer := &dialerInstance{
		conns: make(chan *websocket.Conn, 256),
	}
	dialer.server = &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == wsPath {
				if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
					dialer.conns <- conn
				} else {
					errors.LogError(context.Background(), "Browser dialer http upgrade unexpected error: ", err)
				}
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if _, err := w.Write(page); err != nil {
				errors.LogError(context.Background(), "Browser dialer http page write unexpected error: ", err)
			}
		}),
	}
	return dialer
}

func startDialerInstance(dialer *dialerInstance) {
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
	if d.server != nil {
		d.server.Close()
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
	if addr == "" {
		return nil
	}
	mu.Lock()
	if sockoptDialers == nil {
		sockoptDialers = make(map[string]*dialerInstance)
	}
	if dialer, found := sockoptDialers[addr]; found {
		mu.Unlock()
		return dialer
	}
	dialer := newDialerInstance(addr)
	sockoptDialers[addr] = dialer
	mu.Unlock()
	startDialerInstance(dialer)
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
