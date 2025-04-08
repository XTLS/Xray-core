package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hosemorinho412/xray-core/common/errors"
	"github.com/hosemorinho412/xray-core/common/platform"
	"github.com/hosemorinho412/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

type task struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Extra  any    `json:"extra,omitempty"`
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
		webpage = bytes.ReplaceAll(webpage, []byte("csrfToken"), []byte(csrfToken))
		conns = make(chan *websocket.Conn, 256)
		go http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/websocket" {
				if r.URL.Query().Get("token") == csrfToken {
					if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
						conns <- conn
					} else {
						errors.LogError(context.Background(), "Browser dialer http upgrade unexpected error")
					}
				}
			} else {
				w.Write(webpage)
			}
		}))
	}
}

func HasBrowserDialer() bool {
	return conns != nil
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
}

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	task := task{
		Method: "WS",
		URL:    uri,
	}

	if ed != nil {
		task.Extra = webSocketExtra{
			Protocol: base64.RawURLEncoding.EncodeToString(ed),
		}
	}

	return dialTask(task)
}

type httpExtra struct {
	Referrer string            `json:"referrer,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
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
	task := task{
		Method: "GET",
		URL:    uri,
		Extra:  httpExtraFromHeaders(headers),
	}

	return dialTask(task)
}

func DialPost(uri string, headers http.Header, payload []byte) error {
	task := task{
		Method: "POST",
		URL:    uri,
		Extra:  httpExtraFromHeaders(headers),
	}

	conn, err := dialTask(task)
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
	data, err := json.Marshal(task)
	if err != nil {
		return nil, err
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
