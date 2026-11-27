//go:build !openbsd

package buf_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sync/errgroup"
)

func TestReadvReader(t *testing.T) {
	tcpServer := &tcp.Server{
		MsgProcessor: func(b []byte) []byte {
			return b
		},
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	common.Must(err)
	defer conn.Close()

	const size = 8192
	data := make([]byte, 8192)
	common.Must2(rand.Read(data))

	var errg errgroup.Group
	errg.Go(func() error {
		writer := NewWriter(conn)
		mb := MergeBytes(nil, data)

		return writer.WriteMultiBuffer(mb)
	})

	defer func() {
		if err := errg.Wait(); err != nil {
			t.Error(err)
		}
	}()

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	common.Must(err)

	reader := NewReadVReader(conn, rawConn, nil)
	var rmb MultiBuffer
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal("unexpected error: ", err)
		}
		rmb, _ = MergeMulti(rmb, mb)
		if rmb.Len() == size {
			break
		}
	}

	rdata := make([]byte, size)
	SplitBytes(rmb, rdata)

	if r := cmp.Diff(data, rdata); r != "" {
		t.Fatal(r)
	}
}

// ReadMultiBuffer through the stats wrapper counts every byte, on the single-buffer path and on the
// readv path that the reader switches to after a full buffer.
func TestReadvReaderStatsConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	common.Must(err)
	defer client.Close()
	server, err := ln.Accept()
	common.Must(err)
	const size = 4 * Size
	common.Must2(server.Write(make([]byte, size)))
	server.Close()

	counter := new(stats.Counter)
	reader := NewReader(&stat.CounterConnection{Connection: client, ReadCounter: counter})
	read := int32(0)
	for {
		mb, err := reader.ReadMultiBuffer()
		read += mb.Len()
		ReleaseMulti(mb)
		if errors.Is(err, io.EOF) {
			break
		}
		common.Must(err)
	}
	if read != size || counter.Value() != size {
		t.Error("read ", read, " bytes, counted ", counter.Value(), ", want ", size)
	}
}

// source returns what reader reads from.
func source(reader Reader) io.Reader {
	switch r := reader.(type) {
	case *ReadVReader:
		return r.Reader
	case *SingleReader:
		return r.Reader
	case *PacketReader:
		return r.Reader
	}
	return nil
}

// NewReader looks inside the stats wrapper. Only ReadVReader reads the inner connection, since it
// counts the bytes itself; other readers read through the wrapper.
func TestNewReaderStatsConn(t *testing.T) {
	if v := platform.NewEnvFlag(platform.UseReadV).GetValue(func() string { return "auto" }); v != "auto" && v != "enable" {
		t.Skip("readv is disabled")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer ln.Close()
	tcpConn, err := net.Dial("tcp", ln.Addr().String())
	common.Must(err)
	defer tcpConn.Close()

	pipeConn, _ := net.Pipe()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	common.Must(err)
	defer udpConn.Close()

	unixLn, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	common.Must(err)
	defer unixLn.Close()
	unixConn, err := net.Dial("unix", unixLn.Addr().String())
	common.Must(err)
	defer unixConn.Close()

	for _, test := range []struct {
		name  string
		conn  net.Conn
		want  string
		inner bool // reads conn, not the wrapper
	}{
		{"tcp", tcpConn, "*buf.ReadVReader", true},
		{"pipe", pipeConn, "*buf.SingleReader", false},
		{"udp", udpConn, "*buf.PacketReader", false},
		{"unix", unixConn, "*buf.PacketReader", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			statConn := &stat.CounterConnection{Connection: test.conn}
			wantSource := io.Reader(statConn)
			if test.inner {
				wantSource = test.conn
			}
			reader := NewReader(statConn)
			if got := fmt.Sprintf("%T", reader); got != test.want || source(reader) != wantSource {
				t.Errorf("%s reading %T, want %s reading %T", got, source(reader), test.want, wantSource)
			}
		})
	}
}
