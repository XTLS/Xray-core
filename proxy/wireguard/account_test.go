package wireguard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerConfigAsAccount(t *testing.T) {
	pc := &PeerConfig{
		PublicKey:    "pubkey1",
		PreSharedKey: "psk1",
		AllowedIps:   []string{"10.0.0.2/32", "10.0.0.3/32"},
	}
	acc, err := pc.AsAccount()
	require.NoError(t, err)
	ma := acc.(*MemoryAccount)
	assert.Equal(t, "pubkey1", ma.PublicKey)
	assert.Equal(t, "psk1", ma.PreSharedKey)
	assert.Equal(t, []string{"10.0.0.2/32", "10.0.0.3/32"}, ma.AllowedIPs)
}

func TestMemoryAccountEquals(t *testing.T) {
	a := &MemoryAccount{PublicKey: "key1"}
	assert.True(t, a.Equals(&MemoryAccount{PublicKey: "key1"}))
	assert.False(t, a.Equals(&MemoryAccount{PublicKey: "key2"}))
	assert.False(t, a.Equals(nil))
}

func TestMemoryAccountToProto(t *testing.T) {
	orig := &MemoryAccount{PublicKey: "pk", PreSharedKey: "psk", AllowedIPs: []string{"192.168.0.1/24"}}
	pc, ok := orig.ToProto().(*PeerConfig)
	require.True(t, ok)
	assert.Equal(t, orig.PublicKey, pc.PublicKey)
	assert.Equal(t, orig.PreSharedKey, pc.PreSharedKey)
	assert.Equal(t, orig.AllowedIPs, pc.AllowedIps)
}

func TestBuildPeerIPC(t *testing.T) {
	a := &MemoryAccount{PublicKey: "pk1", PreSharedKey: "psk1", AllowedIPs: []string{"10.0.0.2/32", "10.0.0.3/32"}}
	ipc := buildPeerIPC(a)
	assert.Contains(t, ipc, "public_key=pk1\n")
	assert.Contains(t, ipc, "preshared_key=psk1\n")
	assert.Contains(t, ipc, "allowed_ip=10.0.0.2/32\n")

	// no psk
	a2 := &MemoryAccount{PublicKey: "pk2", AllowedIPs: []string{"10.0.0.4/32"}}
	ipc2 := buildPeerIPC(a2)
	assert.NotContains(t, ipc2, "preshared_key")
}

func TestBuildRemovePeerIPC(t *testing.T) {
	assert.Equal(t, "public_key=somekey\nremove=true\n", buildRemovePeerIPC("somekey"))
}

func TestParseFirstAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string; wantErr bool }{
		{"10.0.0.2/32", "10.0.0.2", false},
		{"10.0.0.5", "10.0.0.5", false},
		{"fd00::1/128", "fd00::1", false},
		{"not-an-ip", "", true},
	} {
		addr, err := parseFirstAddr(tc.in)
		if tc.wantErr {
			assert.Error(t, err, "input %q", tc.in)
		} else {
			require.NoError(t, err, "input %q", tc.in)
			assert.Equal(t, tc.want, addr.String())
		}
	}
}
