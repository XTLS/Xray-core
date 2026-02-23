package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	u "github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

//go:embed dialer.mjs
var dialerModule []byte

type pageWithConnMap struct {
	UUID        string
	ControlConn *websocket.Conn
	ConnMap     map[string]chan *websocket.Conn
	ConnMapLock sync.Mutex
}

var globalConnMap *u.TypedSyncMap[string, *pageWithConnMap]

type task struct {
	Method   string `json:"m"`           // request method
	URL      string `json:"u"`           // destination URL
	ConnUUID string `json:"c"`           // connection UUID
	Extra    any    `json:"e,omitempty"` // extra information (headers, WS subprotocol, referrer...)
}

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   0,
	WriteBufferSize:  0,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		if r.URL.Query().Get("token") == csrfToken {
			return true
		} else {
			errors.LogError(context.Background(), "Browser dialer rejected connection: Invalid CSRF token")
			return false
		}
	},
}

var csrfToken string

func init() {
	addr := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	if addr == "" {
		return
	}
	token := uuid.New()
	csrfToken = token.String()
	globalConnMap = u.NewTypedSyncMap[string, *pageWithConnMap]()
	webpage = bytes.ReplaceAll(webpage, []byte("__CSRF_TOKEN__"), []byte(csrfToken))
	go http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// user requests the HTML page
		if r.URL.Path == "/dialer.mjs" {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			w.Write(dialerModule)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/ws") {
			w.Write(webpage)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			errors.LogError(context.Background(), "Browser dialer failed: Unhandled error")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/ws/")
		pathParts := strings.Split(path, "/")
		if len(pathParts) < 2 {
			errors.LogError(context.Background(), "Browser dialer failed WebSocket upgrade: Insufficient UUID")
			return
		}
		pageUUID := pathParts[0]
		connUUID := pathParts[1]
		if connUUID == "ctrl" {
			page := &pageWithConnMap{
				UUID:        pageUUID,
				ControlConn: conn,
				ConnMap:     make(map[string]chan *websocket.Conn),
			}
			if _, ok := globalConnMap.Load(pageUUID); ok {
				errors.LogError(context.Background(), "Browser dialer received duplicate control connection with same page UUID")
				conn.Close()
				return
			}
			globalConnMap.Store(pageUUID, page)
			go func() {
				_, reader, err := conn.NextReader()
				if err != nil {
					return
				}
				// design and implement control message handling in the future if needed
				io.Copy(io.Discard, reader)
			}()
		} else {
			var page *pageWithConnMap
			if page, _ = globalConnMap.Load(pageUUID); page == nil {
				errors.LogError(context.Background(), "Browser dialer received sub-connection without existing control connection")
				conn.Close()
				return
			}
			page.ConnMapLock.Lock()
			c := page.ConnMap[connUUID]
			page.ConnMapLock.Unlock()
			if c == nil {
				errors.LogError(context.Background(), "Browser dialer received a sub-connection but we didn't request it")
				conn.Close()
				return
			}
			select {
			case c <- conn:
			case <-time.After(5 * time.Second):
				conn.Close()
				errors.LogError(context.Background(), "Browser dialer http upgrade unexpected error")
			}
		}
	}))
	go monitor()
}

func HasBrowserDialer() bool {
	return globalConnMap != nil
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

	var Page *pageWithConnMap
	// the order of iterating a map is random
	globalConnMap.Range(func(_ string, page *pageWithConnMap) bool {
		Page = page
		return false
	})
	if Page == nil {
		return nil, errors.New("no control connection available")
	}
	var conn *websocket.Conn
	connChan := make(chan *websocket.Conn, 1)
	Page.ConnMapLock.Lock()
	Page.ConnMap[task.ConnUUID] = connChan
	Page.ConnMapLock.Unlock()
	defer func() {
		Page.ConnMapLock.Lock()
		delete(Page.ConnMap, task.ConnUUID)
		Page.ConnMapLock.Unlock()
	}()
	err = Page.ControlConn.WriteMessage(websocket.TextMessage, data)
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
	ticker := time.NewTicker(16 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		var pageToDel []*pageWithConnMap
		globalConnMap.Range(func(_ string, page *pageWithConnMap) bool {
			if err := page.ControlConn.WriteControl(websocket.PingMessage, []byte{}, time.Time{}); err != nil {
				pageToDel = append(pageToDel, page)
			}
			return true
		})
		for _, page := range pageToDel {
			globalConnMap.Delete(page.UUID)
		}
	}
}
