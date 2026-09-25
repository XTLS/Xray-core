package buf_test

import (
	"crypto/tls"
	"io"
	"testing"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestWriterCreation(t *testing.T) {
	tcpServer := tcp.Server{}
	dest, err := tcpServer.Start()
	if err != nil {
		t.Fatal("failed to start tcp server: ", err)
	}
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	if err != nil {
		t.Fatal("failed to dial a TCP connection: ", err)
	}
	defer conn.Close()

	{
		writer := NewWriter(conn)
		if _, ok := writer.(*BufferToBytesWriter); !ok {
			t.Fatal("writer is not a BufferToBytesWriter")
		}

		writer2 := NewWriter(writer.(io.Writer))
		if writer2 != writer {
			t.Fatal("writer is not reused")
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	{
		writer := NewWriter(tlsConn)
		if _, ok := writer.(*SequentialWriter); !ok {
			t.Fatal("writer is not a SequentialWriter")
		}
	}
}

// mbConn only moves MultiBuffers, its Read and Write would panic.
type mbConn struct {
	net.Conn
	mb MultiBuffer
}

func (c *mbConn) ReadMultiBuffer() (MultiBuffer, error) {
	mb := c.mb
	c.mb = nil
	return mb, nil
}

func (c *mbConn) WriteMultiBuffer(mb MultiBuffer) error {
	c.mb, _ = MergeMulti(c.mb, mb)
	return nil
}

func TestStatConnPassThrough(t *testing.T) {
	for _, counted := range []bool{false, true} {
		inner := &mbConn{}
		conn := &stat.CounterConnection{Connection: inner}
		rc, wc := new(stats.Counter), new(stats.Counter)
		if counted {
			conn.ReadCounter, conn.WriteCounter = rc, wc
		}
		r, w := NewReader(conn), NewWriter(conn)
		if !counted && (r != Reader(inner) || w != Writer(inner)) {
			t.Fatalf("got %T and %T, want the inner conn", r, w)
		}

		mb := MultiBuffer{New(), New()}
		mb[0].Extend(Size)
		mb[1].Extend(100)
		common.Must(w.WriteMultiBuffer(mb))
		mb, _ = r.ReadMultiBuffer()
		if mb.Len() != Size+100 {
			t.Fatal("moved ", mb.Len(), " bytes")
		}
		ReleaseMulti(mb)
		if counted && (rc.Value() != Size+100 || wc.Value() != Size+100) {
			t.Fatal("counted ", rc.Value(), " read and ", wc.Value(), " written")
		}
	}
}
