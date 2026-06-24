package hysteria

import (
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/hysteria/account"
)

func TestVlessRouteFromAuth(t *testing.T) {
	const routeID = net.Port(0x1234)

	tests := []struct {
		name string
		auth string
		want net.Port
	}{
		{
			name: "hyphenated UUID",
			auth: "00000000-0000-1234-8000-000000000000",
			want: routeID,
		},
		{
			name: "plain UUID",
			auth: "00000000000012348000000000000000",
			want: routeID,
		},
		{
			name: "password auth",
			auth: "password",
			want: 0,
		},
		{
			name: "invalid UUID",
			auth: "00000000-0000-123k-8000-000000000000",
			want: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := account.VlessRouteFromAuth(test.auth); got != test.want {
				t.Fatalf("VlessRouteFromAuth(%q) = %d, want %d", test.auth, got, test.want)
			}
		})
	}
}

type testPolicyManager struct{}

func (*testPolicyManager) Type() interface{} {
	return policy.ManagerType()
}

func (*testPolicyManager) Start() error {
	return nil
}

func (*testPolicyManager) Close() error {
	return nil
}

func (*testPolicyManager) ForLevel(uint32) policy.Session {
	return policy.SessionDefault()
}

func (*testPolicyManager) ForSystem() policy.System {
	return policy.System{}
}

type testUserConn struct {
	user *protocol.MemoryUser
	auth string
}

func (c *testUserConn) User() *protocol.MemoryUser {
	return c.user
}

func (c *testUserConn) Auth() string {
	return c.auth
}

func (*testUserConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (*testUserConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (*testUserConn) Close() error {
	return nil
}

func (*testUserConn) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 443}
}

func (*testUserConn) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 12345}
}

func (*testUserConn) SetDeadline(time.Time) error {
	return nil
}

func (*testUserConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*testUserConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestServerProcessSetsVlessRouteFromHysteriaAuth(t *testing.T) {
	const serverAuth = "00000000-0000-1234-8000-000000000000"
	const clientAuth = "00000000-0000-0001-8000-000000000000"

	inbound := &session.Inbound{}
	user := &protocol.MemoryUser{
		Account: &account.MemoryAccount{Auth: serverAuth},
		Level:   1,
		Email:   "user@example.com",
	}
	server := &Server{
		policyManager: &testPolicyManager{},
	}

	err := server.Process(session.ContextWithInbound(context.Background(), inbound), net.Network_TCP, &testUserConn{user: user, auth: clientAuth}, nil)
	if err == nil {
		t.Fatal("Process unexpectedly succeeded with an empty test connection")
	}
	if inbound.User != user {
		t.Fatal("server did not use the authenticated Hysteria user from the connection")
	}
	if inbound.VlessRoute != 1 {
		t.Fatalf("inbound.VlessRoute = %d, want %d", inbound.VlessRoute, net.Port(1))
	}
}
