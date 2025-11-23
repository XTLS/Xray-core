package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
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

type pageWithConnMap struct {
	UUID        string
	ControlConn *websocket.Conn
	ConnMap     map[string]chan *websocket.Conn
}

var globalConnMap = make(map[string]*pageWithConnMap)

var globalConnMutex = &sync.Mutex{}

type task struct {
	Method   string `json:"m"` // request method
	URL      string `json:"u"` // destination URL
	ConnUUID string `json:"c"` // connection UUID
	Extra    any    `json:"e,omitempty"` // extra information (headers, WS subprotocol, referrer...)
}

var conns chan *websocket.Conn

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func init() {
	addr := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	if addr != "" {
		token := uuid.New()
		csrfToken := token.String()
		webpage = bytes.ReplaceAll(webpage, []byte("__CSRF_TOKEN__"), []byte(csrfToken))
		conns = make(chan *websocket.Conn, 256)
		go http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/ws") {
				if r.URL.Query().Get("token") == csrfToken {
					if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
						pathParts := strings.Split(r.URL.Path, "/")
						if len(pathParts) < 3 {
							errors.LogError(context.Background(), "Browser dialer failed WebSocket upgrade: Insufficient UUID")
						}
						globalConnMutex.Lock()
						pageUUID := pathParts[1]
						connUUID := pathParts[2]
						if connUUID == "ctrl" {
							page := &pageWithConnMap{
								UUID:        pageUUID,
								ControlConn: conn,
								ConnMap:     make(map[string]chan *websocket.Conn),
							}
							globalConnMap[pageUUID] = page
						} else {
							if globalConnMap[pageUUID] == nil {
								errors.LogError(context.Background(), "Browser dialer unexpected connection: Unknown page UUID")
							} else {
								c := globalConnMap[pageUUID].ConnMap[connUUID]
								if c != nil {
									select {
									case c <- conn:
									default:
										errors.LogError(context.Background(), "Browser dialer http upgrade unexpected error")
									}
								} else {
									conn.Close()
									errors.LogError(context.Background(), "Browser dialer error: Detected orphaned connection")
								}
							}
						}
						globalConnMutex.Unlock()
					} else {
						errors.LogError(context.Background(), "Browser dialer failed: Unhandled error")
					}
				}
			} else {
				w.Write(webpage)
			}
		}))
		go monitor()
	}
}

func HasBrowserDialer() bool {
	return conns != nil
}

type webSocketExtra struct {
	Protocol string `json:"p,omitempty"`
}

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	UUID := uuid.New()
	task := task{
		Method:   "WS",
		URL:      uri,
		ConnUUID: UUID.String(),
	}

	if ed != nil {
		task.Extra = webSocketExtra{
			Protocol: base64.RawURLEncoding.EncodeToString(ed),
		}
	}

	return dialTask(task)
}

type httpExtra struct {
	Referrer string            `json:"r,omitempty"`
	Headers  map[string]string `json:"h,omitempty"`
}

func httpExtraFromHeaders(headers http.Header) *httpExtra {
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

	return &extra
}

func DialGet(uri string, headers http.Header) (*websocket.Conn, error) {
	UUID := uuid.New()
	task := task{
		Method:   "GET",
		URL:      uri,
		ConnUUID: UUID.String(),
		Extra:    httpExtraFromHeaders(headers),
	}

	return dialTask(task)
}

func DialPost(uri string, headers http.Header, payload []byte) error {
	UUID := uuid.New()
	task := task{
		Method:   "POST",
		URL:      uri,
		ConnUUID: UUID.String(),
		Extra:    httpExtraFromHeaders(headers),
	}

	conn, err := dialTask(task)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.BinaryMessage, payload)
	if err != nil {
		return err
	}

	conn.Close()
	return nil
}

func dialTask(task task) (*websocket.Conn, error) {
	data, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}

	globalConnMutex.Lock()
	var ControlConn *websocket.Conn
	var pageUUID string
	// the order of iterating a map is random
	for uuid, page := range globalConnMap {
		ControlConn = page.ControlConn
		pageUUID = uuid
		break
	}
	if ControlConn == nil {
		return nil, errors.New("no control connection available")
	}
	var conn *websocket.Conn
	connChan := make(chan *websocket.Conn, 1)
	globalConnMap[pageUUID].ConnMap[task.ConnUUID] = connChan
	globalConnMutex.Unlock()
	defer func() {
		globalConnMutex.Lock()
		if globalConnMap[pageUUID] != nil {
			delete(globalConnMap[pageUUID].ConnMap, task.ConnUUID)
		}
		globalConnMutex.Unlock()
	}()
	err = ControlConn.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		return nil, errors.New("failed to send task to control connection").Base(err)
	}
	select {
	case conn = <-connChan:
		return conn, nil
	case <-time.After(5 * time.Second):
		return nil, errors.New("timeout waiting for connection")
	}
}

func monitor() {
	for {
		globalConnMutex.Lock()
		newGlobalConnMap := make(map[string]*pageWithConnMap)
		for pageUUID, page := range globalConnMap {
			newGlobalConnMap[pageUUID] = page
		}
		globalConnMutex.Unlock()
		for pageUUID, page := range newGlobalConnMap {
			if err := page.ControlConn.WriteControl(websocket.PingMessage, []byte{}, time.Time{}); err != nil {
				globalConnMutex.Lock()
				page.ControlConn.Close()
				if globalConnMap[pageUUID] == newGlobalConnMap[pageUUID] {
					delete(globalConnMap, pageUUID)
				}
				globalConnMutex.Unlock()
			}
		}
		time.Sleep(16 * time.Second)
	}
}
