package xpool_test

import (
	"context"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/xpool"
	"github.com/xtls/xray-core/common/xpool/sim"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// MockServer implements simple echo using XPool primitives
type MockServer struct {
	pool *xpool.ConnectionPool
}

func NewMockServer() *MockServer {
	s := &MockServer{
		pool: xpool.NewConnectionPool(xpool.PoolConfig{MaxIdle: 100, IdleTimeout: 120}, nil),
	}
	s.pool.SetNewSessionCallback(s.onNewSession)
	return s
}

func (s *MockServer) Accept(conn net.Conn) {
	gw := xpool.NewGatewayConn(conn, s.pool)
	<-gw.Done()
}

func (s *MockServer) onNewSession(conn *xpool.GatewayConn, seg *xpool.Segment) xpool.Session {
	sess := xpool.NewServerSession(seg.SID, conn)
	go s.handleSession(sess)
	return sess
}

func (s *MockServer) handleSession(sess *xpool.ServerSession) {
	defer sess.Close()
	// Echo loop
	for {
		mb, err := sess.ReadMultiBuffer()
		if err != nil {
			sess.CloseWrite()
			return
		}
		// Write back
		sess.WriteMultiBuffer(mb)
	}
}

func TestStability_RST(t *testing.T) {
	server := NewMockServer()

	// Capture active connections to inject faults
	var activeConns []*sim.FaultyConn
	var connMu sync.Mutex

	dialer := func() (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		fc1 := sim.Wrap(c1, sim.Config{})

		connMu.Lock()
		activeConns = append(activeConns, fc1)
		connMu.Unlock()

		go server.Accept(c2)
		return fc1, nil
	}

	client := xpool.NewClientManager(&xpool.ClientConfig{Enabled: true, MaxIdle: 5, IdleTimeout: 10}, dialer)

	// Prepare Data
	dataSize := 512 * 1024 // 512KB
	data := make([]byte, dataSize)
	rand.Read(data)

	// Dispatch
	ctx := context.Background()
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024 * 1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024 * 1024))
	link := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}

	go func() {
		if err := client.Dispatch(ctx, link); err != nil {
			t.Log("Dispatch error:", err)
		}
		downlinkWriter.Close() // Close output when dispatch done
	}()

	// Feeder
	go func() {
		// Write Target Address First (Required by Server)
		// 127.0.0.1:80 (AddressTypeIPv4=1)
		addrBuf := buf.New()
		addrBuf.WriteByte(1) // IPv4
		addrBuf.Write([]byte{127, 0, 0, 1})
		addrBuf.Write([]byte{0, 80})
		uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{addrBuf})

		// Write in chunks
		chunkSize := 8192
		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}
			b := buf.New()
			b.Write(data[i:end])
			uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{b})
			time.Sleep(1 * time.Millisecond) // Simulate stream
		}
		uplinkWriter.Close()
	}()

	// Fault injector (Disabled for baseline test)
	/*
	go func() {
		for {
			time.Sleep(50 * time.Millisecond)
			connMu.Lock()
			if len(activeConns) > 0 {
				// Pick random and RST
				idx := rand.Intn(len(activeConns))
				c := activeConns[idx]
				c.Close()

				// Remove from list
				activeConns[idx] = activeConns[len(activeConns)-1]
				activeConns = activeConns[:len(activeConns)-1]
			}
			connMu.Unlock()
		}
	}()
	*/

	// Verifier
	recvBuf := make([]byte, dataSize)
	// ReadAll
	n := 0

	// Skip echoed address (7 bytes)
	bytesToSkip := 7

	for {
		// downlinkReader is pipe.Reader -> buf.Reader
		// Read content
		mb, err := downlinkReader.ReadMultiBuffer()
		if err != nil {
			if err == io.EOF { break }
			t.Fatal("Read error:", err)
		}
		if bytesToSkip > 0 {
			if int(mb.Len()) <= bytesToSkip {
				bytesToSkip -= int(mb.Len())
				buf.ReleaseMulti(mb)
				continue
			}
			// Split
			// I need to skip bytes.
			dummy := make([]byte, bytesToSkip)
			mb, _ = buf.SplitBytes(mb, dummy)
			bytesToSkip = 0
		}

		copied := mb.Copy(recvBuf[n:])
		n += copied
		buf.ReleaseMulti(mb)
		if n == dataSize { break }
	}

	if n != dataSize {
		t.Errorf("Received %d bytes, want %d", n, dataSize)
	}

	// Compare content
	for i := 0; i < dataSize; i++ {
		if recvBuf[i] != data[i] {
			t.Fatalf("Data mismatch at %d", i)
		}
	}
}
