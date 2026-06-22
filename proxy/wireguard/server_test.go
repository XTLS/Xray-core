package wireguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// ---------------------------------------------------------------------------
// mockIpc implements wgIpcSetter without a real WireGuard device.
// ---------------------------------------------------------------------------

type mockIpc struct {
	calls []string
	err   error
}

func (m *mockIpc) IpcSet(cfg string) error {
	m.calls = append(m.calls, cfg)
	return m.err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestServer returns a *Server with ipcOverride set to mock and optionally
// pre-seeded with static peers. It bypasses NewServer (which requires a live
// xray.Instance) by directly populating the UserManager fields.
func newTestServer(mock *mockIpc, staticPeers ...*PeerConfig) *Server {
	s := &Server{ipcOverride: mock}
	for _, p := range staticPeers {
		if p.PublicKey == "" {
			continue
		}
		mu := &protocol.MemoryUser{
			Email: p.PublicKey,
			Account: &MemoryAccount{
				PublicKey:    p.PublicKey,
				PreSharedKey: p.PreSharedKey,
				AllowedIPs:   p.AllowedIps,
			},
		}
		s.peers.Store(p.PublicKey, mu)
		s.peerCount.Add(1)
		for _, cidr := range p.AllowedIps {
			if addr, err := parseFirstAddr(cidr); err == nil {
				s.peersByIP.Store(addr, mu)
			}
		}
	}
	return s
}

func memUser(email, pubkey, psk string, ips ...string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email: email,
		Account: &MemoryAccount{
			PublicKey:    pubkey,
			PreSharedKey: psk,
			AllowedIPs:   ips,
		},
	}
}

type wrongAccount struct{}

func (wrongAccount) Equals(protocol.Account) bool { return false }
func (wrongAccount) ToProto() proto.Message        { return nil }

// ---------------------------------------------------------------------------
// Static peer seeding
// ---------------------------------------------------------------------------

func TestStaticPeersSeededAtStartup(t *testing.T) {
	s := newTestServer(&mockIpc{},
		&PeerConfig{PublicKey: "pk1", AllowedIps: []string{"10.0.0.2/32"}},
		&PeerConfig{PublicKey: "pk2", AllowedIps: []string{"10.0.0.3/32"}},
	)

	assert.Equal(t, int64(2), s.GetUsersCount(context.Background()))

	u := s.GetUser(context.Background(), "pk1")
	require.NotNil(t, u)
	assert.Equal(t, "pk1", u.Account.(*MemoryAccount).PublicKey)

	addr, _ := netip.ParseAddr("10.0.0.2")
	v, ok := s.peersByIP.Load(addr)
	require.True(t, ok)
	assert.Equal(t, "pk1", v.(*protocol.MemoryUser).Account.(*MemoryAccount).PublicKey)
}

// ---------------------------------------------------------------------------
// AddUser
// ---------------------------------------------------------------------------

func TestAddUser(t *testing.T) {
	mock := &mockIpc{}
	s := newTestServer(mock)

	require.NoError(t, s.AddUser(context.Background(), memUser("alice", "pk-alice", "psk", "10.0.0.2/32")))

	require.Len(t, mock.calls, 1)
	assert.Contains(t, mock.calls[0], "public_key=pk-alice\n")
	assert.Contains(t, mock.calls[0], "preshared_key=psk\n")
	assert.Contains(t, mock.calls[0], "allowed_ip=10.0.0.2/32\n")

	got := s.GetUser(context.Background(), "alice")
	require.NotNil(t, got)
	assert.Equal(t, int64(1), s.GetUsersCount(context.Background()))

	addr, _ := netip.ParseAddr("10.0.0.2")
	v, ok := s.peersByIP.Load(addr)
	require.True(t, ok)
	assert.Equal(t, "alice", v.(*protocol.MemoryUser).Email)
}

func TestAddUserFallsBackToPubKeyWhenEmailEmpty(t *testing.T) {
	s := newTestServer(&mockIpc{})
	require.NoError(t, s.AddUser(context.Background(), memUser("", "pk-nomail", "", "10.0.0.5/32")))
	require.NotNil(t, s.GetUser(context.Background(), "pk-nomail"))
}

func TestAddUserDuplicate(t *testing.T) {
	s := newTestServer(&mockIpc{})
	u := memUser("alice", "pk-alice", "", "10.0.0.2/32")
	require.NoError(t, s.AddUser(context.Background(), u))
	assert.Error(t, s.AddUser(context.Background(), u))
}

func TestAddUserWrongAccountType(t *testing.T) {
	s := newTestServer(&mockIpc{})
	u := &protocol.MemoryUser{Email: "alice", Account: wrongAccount{}}
	assert.Error(t, s.AddUser(context.Background(), u))
}

func TestAddUserIpcError(t *testing.T) {
	mock := &mockIpc{err: errors.New("ipc fail")}
	s := newTestServer(mock)
	assert.Error(t, s.AddUser(context.Background(), memUser("alice", "pk", "", "10.0.0.2/32")))
	assert.Nil(t, s.GetUser(context.Background(), "alice"))
	assert.Equal(t, int64(0), s.GetUsersCount(context.Background()))
}

// ---------------------------------------------------------------------------
// RemoveUser
// ---------------------------------------------------------------------------

func TestRemoveUser(t *testing.T) {
	mock := &mockIpc{}
	s := newTestServer(mock)
	require.NoError(t, s.AddUser(context.Background(), memUser("alice", "pk-alice", "", "10.0.0.2/32")))
	mock.calls = nil

	require.NoError(t, s.RemoveUser(context.Background(), "alice"))

	require.Len(t, mock.calls, 1)
	assert.Equal(t, "public_key=pk-alice\nremove=true\n", mock.calls[0])
	assert.Nil(t, s.GetUser(context.Background(), "alice"))
	assert.Equal(t, int64(0), s.GetUsersCount(context.Background()))

	addr, _ := netip.ParseAddr("10.0.0.2")
	_, ok := s.peersByIP.Load(addr)
	assert.False(t, ok)
}

func TestRemoveUserNotFound(t *testing.T) {
	s := newTestServer(&mockIpc{})
	assert.Error(t, s.RemoveUser(context.Background(), "nobody"))
}

// ---------------------------------------------------------------------------
// GetUser / GetUsers / GetUsersCount
// ---------------------------------------------------------------------------

func TestGetUserNotFound(t *testing.T) {
	s := newTestServer(&mockIpc{})
	assert.Nil(t, s.GetUser(context.Background(), "nobody"))
}

func TestGetUsers(t *testing.T) {
	s := newTestServer(&mockIpc{})
	require.NoError(t, s.AddUser(context.Background(), memUser("alice", "pk1", "", "10.0.0.2/32")))
	require.NoError(t, s.AddUser(context.Background(), memUser("bob", "pk2", "", "10.0.0.3/32")))

	users := s.GetUsers(context.Background())
	assert.Len(t, users, 2)

	seen := map[string]bool{}
	for _, u := range users {
		seen[u.Email] = true
	}
	assert.True(t, seen["alice"])
	assert.True(t, seen["bob"])
}

func TestGetUsersCount(t *testing.T) {
	s := newTestServer(&mockIpc{})
	assert.Equal(t, int64(0), s.GetUsersCount(context.Background()))

	require.NoError(t, s.AddUser(context.Background(), memUser("a", "pk1", "", "10.0.0.2/32")))
	assert.Equal(t, int64(1), s.GetUsersCount(context.Background()))

	require.NoError(t, s.AddUser(context.Background(), memUser("b", "pk2", "", "10.0.0.3/32")))
	assert.Equal(t, int64(2), s.GetUsersCount(context.Background()))

	require.NoError(t, s.RemoveUser(context.Background(), "a"))
	assert.Equal(t, int64(1), s.GetUsersCount(context.Background()))
}

// ---------------------------------------------------------------------------
// peersByIP (used by HandleConnection to annotate sessions)
// ---------------------------------------------------------------------------

func TestPeersByIPPopulatedAndCleanedUp(t *testing.T) {
	s := newTestServer(&mockIpc{})
	require.NoError(t, s.AddUser(context.Background(), memUser("alice", "pk-alice", "", "10.0.0.2/32")))

	addr, _ := netip.ParseAddr("10.0.0.2")
	v, ok := s.peersByIP.Load(addr)
	require.True(t, ok)
	assert.Equal(t, "alice", v.(*protocol.MemoryUser).Email)

	require.NoError(t, s.RemoveUser(context.Background(), "alice"))
	_, ok = s.peersByIP.Load(addr)
	assert.False(t, ok)
}
