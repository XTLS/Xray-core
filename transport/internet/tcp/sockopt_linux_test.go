//go:build linux
// +build linux

package tcp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	unsafe "unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestGetOriginalDestination(t *testing.T) {
	tcpServer := tcp.Server{}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	config, err := internet.ToMemoryStreamConfig(nil)
	common.Must(err)
	conn, err := Dial(context.Background(), dest, config)
	common.Must(err)
	defer conn.Close()

	originalDest, err := GetOriginalDestination(conn)
	if !(dest == originalDest || strings.Contains(err.Error(), "failed to call getsockopt")) {
		t.Error("unexpected state")
	}
}

func TestSockoptParams(t *testing.T) {
	type BrutalParams struct {
		rate      uint64
		cwnd_gain uint32
	}

	params := BrutalParams{
		rate:      15 * 1024 * 1024 / 8,
		cwnd_gain: 15,
	}

	raw := unsafe.Slice(
		(*byte)(unsafe.Pointer(&params)),
		unsafe.Sizeof(params),
	)

	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf, 15*1024*1024/8)
	binary.LittleEndian.PutUint32(buf[8:], 15)

	fmt.Println(len(raw), raw)
	fmt.Println(len(buf), buf)

	if !bytes.Equal(raw, buf) {
		t.Fatal("!bytes.Equal(raw, buf)")
	}
}
