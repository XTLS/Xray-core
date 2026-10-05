package buf_test

import (
	"io"
	"net"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// sizesConn has no file descriptor. It notes the size of every Write, and how many Buffers
// of the MultiBuffer that is being written are not released by then.
type sizesConn struct {
	net.Conn
	join         int32
	mb           MultiBuffer
	writes, held []int
}

func (c *sizesConn) JoinSize() int32 { return c.join }

func (c *sizesConn) Write(b []byte) (int, error) {
	held := 0
	for _, b := range c.mb {
		if b.Cap() > 0 {
			held++
		}
	}
	c.writes, c.held = append(c.writes, len(b)), append(c.held, held)
	return len(b), nil
}

// NewWriter joins the Buffers of a MultiBuffer for a connection that asks for it, as many bytes as it asks for,
// and holds none of them through a Write that has all of it.
func TestNewWriterJoins(t *testing.T) {
	for _, test := range []struct {
		conn                  func(*sizesConn) io.Writer
		join                  int32
		buffers, writes, held []int
	}{
		{func(c *sizesConn) io.Writer { return struct{ io.Writer }{c} }, 2 * Size, []int{3, 5}, []int{3, 5}, nil},
		{func(c *sizesConn) io.Writer { return c }, 0, []int{3, 5}, []int{3, 5}, nil},
		{func(c *sizesConn) io.Writer { return c }, 2 * Size, []int{3, 5}, []int{8}, []int{0}},
		{func(c *sizesConn) io.Writer { return &stat.CounterConnection{Connection: c} }, 2 * Size, []int{Size, Size, Size, Size, 8}, []int{2 * Size, 2 * Size, 8}, []int{3, 1, 0}},
		{func(c *sizesConn) io.Writer { return c }, 4 * Size, []int{8, Size, Size, Size, Size}, []int{4 * Size, 8}, []int{1, 0}},
	} {
		conn := &sizesConn{join: test.join}
		for _, n := range test.buffers {
			b := New()
			b.Extend(int32(n))
			conn.mb = append(conn.mb, b)
		}
		common.Must(NewWriter(test.conn(conn)).WriteMultiBuffer(conn.mb))
		if !slices.Equal(conn.writes, test.writes) || test.held != nil && !slices.Equal(conn.held, test.held) {
			t.Errorf("%T, %v bytes at once, Buffers of %v bytes: Writes of %v with %v Buffers held, want %v with %v",
				test.conn(conn), test.join, test.buffers, conn.writes, conn.held, test.writes, test.held)
		}
	}
}
