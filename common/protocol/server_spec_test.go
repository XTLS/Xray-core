package protocol_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/common/protocol"
)

func TestPickUser(t *testing.T) {
	spec := NewServerSpec(net.Destination{}, &MemoryUser{Email: "test1@example.com"})
	user := spec.PickUser()
	if !strings.HasSuffix(user.Email, "@example.com") {
		t.Error("user: ", user.Email)
	}
}
