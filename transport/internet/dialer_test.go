package internet_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
)

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}

func TestDialInterfaceMissing(t *testing.T) {
	// #7160: a sockopt.interface that does not exist must fail the dial,
	// not open the connection unbound
	sockopt := &SocketConfig{
		Interface: "nosuchif0",
	}

	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	_, err = DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), sockopt)
	if err == nil {
		t.Error("dial with a nonexistent sockopt.interface must fail")
	} else if !strings.Contains(err.Error(), "nosuchif0") {
		t.Error("error does not name the interface: ", err)
	}

	_, err = DialSystem(context.Background(), net.UDPDestination(net.LocalHostIP, dest.Port), sockopt)
	if err == nil {
		t.Error("udp dial with a nonexistent sockopt.interface must fail")
	} else if !strings.Contains(err.Error(), "nosuchif0") {
		t.Error("error does not name the interface: ", err)
	}
}
