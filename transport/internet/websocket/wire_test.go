package websocket

import (
	"bytes"
	"net/http"
	"slices"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
)

// recordListener keeps every write to its connections as it was made: under TLS, each of them is a record.
type recordListener struct {
	net.Listener
	writes [][]byte
}

type recordConn struct {
	net.Conn
	l *recordListener
}

func (l *recordListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	return recordConn{conn, l}, err
}

func (c recordConn) Write(b []byte) (int, error) {
	c.l.writes = append(c.l.writes, bytes.Clone(b))
	return c.Conn.Write(b)
}

// serverWrites returns the writes of a server with this upgrader to its connection, after the response.
func serverWrites(u *websocket.Upgrader) [][]byte {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	ln := &recordListener{Listener: listener}
	defer ln.Close()
	done := make(chan struct{})
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := u.Upgrade(w, r, nil)
		common.Must(err)
		c := NewConnection(conn, conn.RemoteAddr(), nil, 0)
		for _, size := range []int{1, 4082, 4083, 70000} {
			common.Must2(c.Write(bytes.Repeat([]byte{byte(size)}, size)))
		}
		c.Close()
		close(done)
	}))
	client, _, err := websocket.DefaultDialer.Dial("ws://"+ln.Addr().String(), nil)
	common.Must(err)
	defer client.Close()
	for err == nil {
		_, _, err = client.ReadMessage()
	}
	<-done
	return ln.writes[1:]
}

func TestWriteBufferPoolWire(t *testing.T) {
	// as it was before the write buffers came from a pool: one write for a message of up to 4082 bytes,
	// two for a larger one, and the close frame
	old := serverWrites(&websocket.Upgrader{})
	if now := serverWrites(upgrader); len(old) != 2+2*2+1 || !slices.EqualFunc(now, old, bytes.Equal) {
		t.Error("writes of the server: ", len(now), ", were: ", len(old))
	}
}
