package tls

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

// waitConn returns a client connection of this package, with a fingerprint or without one, before its handshake,
// and the crypto/tls connection at its other end, which writes through wrap if there is one.
func waitConn(t *testing.T, fingerprint bool, serverConfig *gotls.Config, wrap func(net.Conn) net.Conn) (Interface, *gotls.Conn) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer listener.Close()
	dialed, err := net.Dial("tcp", listener.Addr().String())
	common.Must(err)
	accepted, err := listener.Accept()
	common.Must(err)
	t.Cleanup(func() {
		dialed.Close()
		accepted.Close()
	})
	if wrap != nil {
		accepted = wrap(accepted)
	}
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	keyPair, err := gotls.X509KeyPair(ct.ToPEM())
	common.Must(err)
	serverConfig.Certificates = []gotls.Certificate{keyPair}
	serverConfig.DynamicRecordSizingDisabled = true // records as large as what is written, up to 16384 bytes
	// a client that keeps no sessions gets no session tickets
	clientConfig := &gotls.Config{InsecureSkipVerify: true, MaxVersion: serverConfig.MaxVersion, ClientSessionCache: gotls.NewLRUClientSessionCache(1)}
	if fingerprint {
		return UClient(dialed, clientConfig, GetFingerprint("chrome")).(Interface), gotls.Server(accepted, serverConfig)
	}
	return Client(dialed, clientConfig).(Interface), gotls.Server(accepted, serverConfig)
}

// waitPair is waitConn after the handshake.
func waitPair(t *testing.T, fingerprint bool, version uint16, wrap func(net.Conn) net.Conn) (Interface, *gotls.Conn) {
	conn, peer := waitConn(t, fingerprint, &gotls.Config{MaxVersion: version}, wrap)
	go peer.Handshake()
	common.Must(conn.HandshakeContext(context.Background()))
	return conn, peer
}

func waitRead(reader buf.Reader, data []byte) error {
	rdata := make([]byte, len(data))
	if _, err := io.ReadFull(&buf.BufferedReader{Reader: reader}, rdata); err != nil {
		return err
	}
	if !bytes.Equal(rdata, data) {
		return errors.New("unexpected data")
	}
	return nil
}

// It fails if a TLS library moves what ReadWaiter looks into, which makes readers hold their buffers again.
func TestReadWaiterFields(t *testing.T) {
	for _, conn := range []net.Conn{&gotls.Conn{}, &utls.Conn{}, &reality.Conn{}} {
		var w ReadWaiter
		if w.Wait(conn); w.complete == nil || w.input == nil || w.rawInput == nil || w.hand == nil {
			t.Errorf("unexpected fields in %T", conn)
		}
	}
}

type unknownConn struct {
	net.Conn
}

func (c unknownConn) NetConn() net.Conn { return c.Conn }

// A connection that is not what it was is read as before: nothing waits for it.
func TestReadWaiterUnknownConn(t *testing.T) {
	conn, _ := waitConn(t, false, &gotls.Config{}, nil)
	defer time.AfterFunc(2*time.Second, func() { conn.Close() }).Stop()
	start := time.Now()
	new(ReadWaiter).Wait(unknownConn{conn.(*Conn).NetConn()})
	if time.Since(start) > time.Second {
		t.Fatal("it waits")
	}
}

// splitConn sends what it is given in pieces, the first ones cut inside a record header.
type splitConn struct {
	net.Conn
}

func (c splitConn) Write(b []byte) (int, error) {
	for n, size := 0, 1; n < len(b); n, size = n+size, size*4+1 {
		c.Conn.Write(b[n:min(n+size, len(b))])
		time.Sleep(time.Millisecond)
	}
	return len(b), nil
}

// A reader gets all of what is in the connection when it comes: what a header read with conn.Read
// has left of its record, and whatever of the records that follow has arrived.
func TestReadWaiter(t *testing.T) {
	for _, version := range []uint16{gotls.VersionTLS13, gotls.VersionTLS12} {
		for _, fingerprint := range []bool{false, true} {
			conn, peer := waitPair(t, fingerprint, version, func(conn net.Conn) net.Conn { return splitConn{conn} })
			common.Must(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
			data := bytes.Repeat([]byte{1}, 9000)
			go peer.Write(data)
			common.Must2(io.ReadFull(conn, make([]byte, 10)))
			time.Sleep(50 * time.Millisecond)
			reader := buf.NewReader(conn)
			err := waitRead(reader, data[10:])
			// then two records at a time, which are there before the reader or come while it waits
			for i, size := range []int{2, 16385, 40000, 3} {
				data := bytes.Repeat([]byte{byte(size)}, size)
				go func() {
					time.Sleep(time.Duration(i%2) * 20 * time.Millisecond)
					peer.Write(data[:size/2])
					peer.Write(data[size/2:])
				}()
				time.Sleep(time.Duration((i+1)%2) * 20 * time.Millisecond)
				if err == nil {
					err = waitRead(reader, data)
				}
			}
			if err != nil {
				t.Fatal("version: ", version, ", fingerprint: ", fingerprint, ", error: ", err)
			}
			// rawInput alone has its bytes: XTLS Vision drops it to release them
			var w *ReadWaiter
			switch c := conn.(type) {
			case *Conn:
				w = &c.readWaiter
			case *UConn:
				w = &c.readWaiter
			}
			if w.spare != nil && *w.spare != nil {
				t.Fatal("version: ", version, ", fingerprint: ", fingerprint, ", the bytes of rawInput are kept apart from it")
			}
		}
	}
}

// gateConn holds back what follows the first record of the largest size until it is opened.
type gateConn struct {
	net.Conn
	open chan struct{}
}

func (c gateConn) Write(b []byte) (int, error) {
	for end := 0; end+5 <= len(b); {
		size := 5 + int(b[end+3])<<8 + int(b[end+4])
		if end += size; size > 16384 && end < len(b) {
			c.Conn.Write(b[:end])
			<-c.open
			return c.Conn.Write(b[end:])
		}
	}
	return c.Conn.Write(b)
}

// A reader that comes after a read has timed out in the middle of a handshake message,
// a session ticket of three records, does not make the connection lose the part that it has.
func TestReadWaiterKeepsHandshakeMessage(t *testing.T) {
	for _, fingerprint := range []bool{false, true} {
		open := make(chan struct{})
		serverConfig := &gotls.Config{WrapSession: func(gotls.ConnectionState, *gotls.SessionState) ([]byte, error) {
			return make([]byte, 40000), nil
		}}
		conn, peer := waitConn(t, fingerprint, serverConfig, func(conn net.Conn) net.Conn { return gateConn{conn, open} })
		go func() {
			peer.Handshake()
			peer.Write([]byte("data"))
		}()
		common.Must(conn.HandshakeContext(context.Background()))
		common.Must(conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("fingerprint: ", fingerprint, ", read: ", err)
		}
		common.Must(conn.SetReadDeadline(time.Now().Add(3 * time.Second)))
		time.AfterFunc(50*time.Millisecond, func() { close(open) })
		if err := waitRead(buf.NewReader(conn), []byte("data")); err != nil {
			t.Fatal("fingerprint: ", fingerprint, ", error: ", err)
		}
	}
}

// A reader that comes while a write does the handshake leaves the connection to it. The race detector tells.
func TestReadWaiterDuringHandshake(t *testing.T) {
	for _, fingerprint := range []bool{false, true} {
		conn, peer := waitConn(t, fingerprint, &gotls.Config{}, nil)
		common.Must(conn.SetDeadline(time.Now().Add(5 * time.Second)))
		go func() {
			time.Sleep(100 * time.Millisecond)
			peer.Handshake()
			io.Copy(peer, peer)
		}()
		data := make([]byte, 5000)
		go conn.Write(data)
		time.Sleep(30 * time.Millisecond)
		if err := waitRead(buf.NewReader(conn), data); err != nil {
			t.Fatal("fingerprint: ", fingerprint, ", error: ", err)
		}
	}
}

func TestReadWaiterHoldsNothing(t *testing.T) {
	const conns = 50
	heap := func() int {
		var m runtime.MemStats
		runtime.GC()
		runtime.GC() // it takes two to empty a sync.Pool
		runtime.ReadMemStats(&m)
		return int(m.HeapAlloc)
	}
	for _, fingerprint := range []bool{false, true} {
		var readers []buf.Reader
		for range conns {
			conn, peer := waitPair(t, fingerprint, gotls.VersionTLS13, nil)
			// a record of the largest size leaves rawInput as large, and a read that fills its buffer is not the last
			data := make([]byte, 16384+100)
			go peer.Write(data)
			readers = append(readers, buf.NewReader(conn))
			common.Must(waitRead(readers[len(readers)-1], data))
		}
		holding := heap()
		for _, reader := range readers {
			go reader.ReadMultiBuffer()
		}
		time.Sleep(200 * time.Millisecond)
		// without waiting, each of them takes a buffer of 8192 bytes instead
		if released := (holding - heap()) / conns; released < 12000 {
			t.Error("fingerprint: ", fingerprint, ", bytes released per waiting connection: ", released)
		}
	}
}
