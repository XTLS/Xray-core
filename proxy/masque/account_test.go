package masque

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/common/protocol"
)

func TestValidator(t *testing.T) {
	v := newValidator()
	user := &protocol.MemoryUser{Email: "U@example.com", Account: &MemoryAccount{Password: "p"}}
	require.NoError(t, v.add(user))
	for _, u := range []*protocol.MemoryUser{
		{Email: "u@example.com", Account: &MemoryAccount{Password: "other"}},
		{Account: &MemoryAccount{Password: "p"}},
		{Email: "a:b", Account: &MemoryAccount{Password: "p"}},
		{Email: "b@example.com", Account: &MemoryAccount{}},
	} {
		require.Error(t, v.add(u), u.Email)
	}

	require.Equal(t, user, v.get("u@example.com", "p"))
	require.Equal(t, user, v.get("U@EXAMPLE.COM", "p"))
	require.Nil(t, v.get("u@example.com", "x"))
	require.Nil(t, v.get("x@example.com", "p"))
	require.Nil(t, v.get("", ""))
	require.Equal(t, user, v.getByEmail("u@example.com"))
	require.Equal(t, []*protocol.MemoryUser{user}, v.getAll())
	require.Equal(t, int64(1), v.count())

	require.True(t, v.contains(user))
	removed, err := v.delByEmail("u@EXAMPLE.com")
	require.NoError(t, err)
	require.Equal(t, user, removed)
	_, err = v.delByEmail("u@example.com")
	require.Error(t, err)
	require.False(t, v.contains(user))
	require.Nil(t, v.get("u@example.com", "p"))
	require.Zero(t, v.count())
}

func TestAccount(t *testing.T) {
	account, err := (&Account{Password: "p"}).AsAccount()
	require.NoError(t, err)
	require.True(t, account.Equals(&MemoryAccount{Password: "p"}))
	require.False(t, account.Equals(&MemoryAccount{Password: "x"}))
	require.Equal(t, &Account{Password: "p"}, account.ToProto())
}
