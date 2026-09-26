package browser_dialer

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func streamSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	t.Cleanup(server.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case peer := <-accepted:
		t.Cleanup(func() { peer.Close() })
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		return client, peer
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket was not accepted")
		return nil, nil
	}
}

func TestDialGetStreamNegotiation(t *testing.T) {
	for _, response := range []string{"ok-read", "ok", "fail"} {
		t.Run(response, func(t *testing.T) {
			conn, browser := streamSocketPair(t)
			previous := conns
			conns = make(chan *websocket.Conn, 1)
			conns <- conn
			t.Cleanup(func() { conns = previous })
			received := make(chan task, 1)
			go func() {
				var request task
				if browser.ReadJSON(&request) == nil {
					received <- request
					browser.WriteMessage(websocket.TextMessage, []byte(response))
				}
			}()
			stream, remote, local, err := DialGetStream("https://xray.test/", http.Header{"Accept": {"*/*"}}, nil)
			if response == "fail" {
				if err == nil {
					t.Fatal("failed handshake accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			request := <-received
			if request.ReadWindow != streamReadWindow || !request.StreamResponse || request.Method != "GET" {
				t.Fatalf("unexpected task: %+v", request)
			}
			if remote == nil || local == nil {
				t.Fatal("missing socket addresses")
			}
			if stream.(*streamReader).acknowledge != (response == "ok-read") {
				t.Fatal("incorrect acknowledgement negotiation")
			}
		})
	}
}

func TestStreamReaderConsumption(t *testing.T) {
	for _, acknowledge := range []bool{true, false} {
		t.Run(strconv.FormatBool(acknowledge), func(t *testing.T) {
			conn, browser := streamSocketPair(t)
			stream := &streamReader{conn: conn, acknowledge: acknowledge}
			payload := make([]byte, streamReadWindow+streamReadWindow/4+17)
			for i := range payload {
				payload[i] = byte(i % 251)
			}
			acks := make(chan int, 8)
			ackDone := make(chan struct{})
			go func() {
				defer close(ackDone)
				for {
					_, message, err := browser.ReadMessage()
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(string(message))
					acks <- n
				}
			}()
			sent := make(chan error, 1)
			go func() {
				// Irregular WebSocket frames exercise partial reads and frame boundaries.
				for offset := 0; offset < len(payload); offset += 65537 {
					if err := browser.WriteMessage(websocket.BinaryMessage, payload[offset:min(offset+65537, len(payload))]); err != nil {
						sent <- err
						return
					}
				}
				sent <- nil
			}()
			select {
			case <-acks:
				t.Fatal("acknowledged bytes before the application read them")
			case <-time.After(20 * time.Millisecond):
			}
			if n, err := stream.Read(nil); n != 0 || err != nil {
				t.Fatalf("empty read = %d, %v", n, err)
			}
			var actual bytes.Buffer
			readBuffer := make([]byte, 32768)
			for actual.Len() < len(payload) {
				n, err := stream.Read(readBuffer)
				if err != nil {
					t.Fatal(err)
				}
				actual.Write(readBuffer[:n])
			}
			if !bytes.Equal(payload, actual.Bytes()) {
				t.Fatal("response changed across frame boundaries")
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if acknowledge {
				total := 0
				for range 2 {
					select {
					case n := <-acks:
						if n < streamReadWindow/2 || n >= streamReadWindow/2+len(readBuffer) {
							t.Fatalf("invalid consumed byte count: %d", n)
						}
						total += n
					case <-time.After(time.Second):
						t.Fatal("missing consumption acknowledgement")
					}
				}
				if total+stream.consumed != len(payload) {
					t.Fatal("acknowledgements did not account for the bytes read")
				}
			}
			stream.Close()
			<-ackDone
			if len(acks) != 0 {
				t.Fatal("unexpected acknowledgement (including on a legacy page)")
			}
		})
	}
}

func TestStreamReaderCloseUnblocksRead(t *testing.T) {
	conn, _ := streamSocketPair(t)
	stream := &streamReader{conn: conn, acknowledge: true}
	done := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		done <- err
	}()
	stream.Close()
	select {
	case err := <-done:
		if err == nil || err == io.EOF {
			t.Fatalf("closed socket read returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not unblock")
	}
}
