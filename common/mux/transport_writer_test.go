package mux

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ws "github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	enc "github.com/xtls/xray-core/transport/internet/grpc/encoding"
	xws "github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func writeMux(t *testing.T, w buf.Writer) {
	t.Helper()
	w = workerWriter(t, "server", w)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			mw := NewResponseWriter(uint16(id+1), w, protocol.TransferTypeStream)
			for j := 0; j < 50; j++ {
				m := buf.MergeBytes(nil, make([]byte, 4096))
				if err := mw.WriteMultiBuffer(m); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestWebSocketSharedMuxWriter(t *testing.T) {
	up := ws.Upgrader{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			if _, _, err = c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer s.Close()
	c, _, err := ws.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	xc := xws.NewConnection(c, &net.TCPAddr{}, nil, 0)
	writeMux(t, buf.NewWriter(xc))
}

type rpcServer struct {
	enc.UnimplementedGRPCServiceServer
	t *testing.T
}

func (s *rpcServer) TunMulti(stream grpc.BidiStreamingServer[enc.MultiHunk, enc.MultiHunk]) error {
	c := enc.NewMultiHunkConn(stream, nil, nil)
	writeMux(s.t, buf.NewWriter(c))
	return nil
}

func (s *rpcServer) Tun(stream grpc.BidiStreamingServer[enc.Hunk, enc.Hunk]) error {
	c := enc.NewHunkConn(stream, nil, nil)
	writeMux(s.t, buf.NewWriter(c))
	return nil
}

func TestGRPCSharedMuxWriter(t *testing.T) {
	for _, multi := range []bool{false, true} {
		name := "single"
		if multi {
			name = "multi"
		}
		t.Run(name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := grpc.NewServer()
			enc.RegisterGRPCServiceServer(s, &rpcServer{t: t})
			go s.Serve(l)
			defer s.Stop()
			cc, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client := enc.NewGRPCServiceClient(cc)
			if multi {
				stream, err := client.TunMulti(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for {
					_, err = stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("receive: %v", err)
						break
					}
				}
			} else {
				stream, err := client.Tun(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for {
					_, err = stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("receive: %v", err)
						break
					}
				}
			}
		})
	}
}
