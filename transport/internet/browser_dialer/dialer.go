package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

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

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	data := []byte("WS " + uri)
	if ed != nil {
		data = append(data, " "+base64.RawURLEncoding.EncodeToString(ed)...)
	}

	return dialRaw(data)
}

func DialGet(uri string) (*websocket.Conn, error) {
	data := []byte("GET " + uri)
	return dialRaw(data)
}

func DialPost(uri string, payload []byte) error {
	data := []byte("POST " + uri)
	conn, err := dialRaw(data)
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

func dialRaw(data []byte) (*websocket.Conn, error) {
	var conn *websocket.Conn
	for {
		conn = <-conns
		if conn.WriteMessage(websocket.TextMessage, data) != nil {
			conn.Close()
		} else {
			break
		}
	}
	err := CheckOK(conn)
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
