package encoding_test

import (
	"io"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func toAccount(a *vless.Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func TestRequestSerialization(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "test@example.com",
	}
	id := uuid.New()
	account := &vless.Account{
		Id: id.String(),
	}
	user.Account = toAccount(account)

	expectedRequest := &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("www.example.com"),
		Port:    net.Port(443),
	}
	expectedAddons := &Addons{}

	buffer := buf.StackNew()
	common.Must(EncodeRequestHeader(&buffer, expectedRequest, expectedAddons))

	Validator := new(vless.MemoryValidator)
	Validator.Add(user)

	_, actualRequest, actualAddons, _, err := DecodeRequestHeader(false, nil, &buffer, Validator)
	common.Must(err)

	if r := cmp.Diff(actualRequest, expectedRequest, cmp.AllowUnexported(protocol.ID{})); r != "" {
		t.Error(r)
	}

	addonsComparer := func(x, y *Addons) bool {
		return (x.Flow == y.Flow) && cmp.Equal(x.Seed, y.Seed)
	}
	if r := cmp.Diff(actualAddons, expectedAddons, cmp.Comparer(addonsComparer)); r != "" {
		t.Error(r)
	}
}

func TestInvalidRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "test@example.com",
	}
	id := uuid.New()
	account := &vless.Account{
		Id: id.String(),
	}
	user.Account = toAccount(account)

	expectedRequest := &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommand(100),
		Address: net.DomainAddress("www.example.com"),
		Port:    net.Port(443),
	}
	expectedAddons := &Addons{}

	buffer := buf.StackNew()
	common.Must(EncodeRequestHeader(&buffer, expectedRequest, expectedAddons))

	Validator := new(vless.MemoryValidator)
	Validator.Add(user)

	_, _, _, _, err := DecodeRequestHeader(false, nil, &buffer, Validator)
	if err == nil {
		t.Error("nil error")
	}
}

func TestMuxRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Level: 0,
		Email: "test@example.com",
	}
	id := uuid.New()
	account := &vless.Account{
		Id: id.String(),
	}
	user.Account = toAccount(account)

	expectedRequest := &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommandMux,
		Address: net.DomainAddress("v1.mux.cool"),
	}
	expectedAddons := &Addons{}

	buffer := buf.StackNew()
	common.Must(EncodeRequestHeader(&buffer, expectedRequest, expectedAddons))

	Validator := new(vless.MemoryValidator)
	Validator.Add(user)

	_, actualRequest, actualAddons, _, err := DecodeRequestHeader(false, nil, &buffer, Validator)
	common.Must(err)

	if r := cmp.Diff(actualRequest, expectedRequest, cmp.AllowUnexported(protocol.ID{})); r != "" {
		t.Error(r)
	}

	addonsComparer := func(x, y *Addons) bool {
		return (x.Flow == y.Flow) && cmp.Equal(x.Seed, y.Seed)
	}
	if r := cmp.Diff(actualAddons, expectedAddons, cmp.Comparer(addonsComparer)); r != "" {
		t.Error(r)
	}
}

// XTLS Vision shapes the Buffers it sends, so buf.NewWriter must not join them for a connection that VLESS
// allows it on. One that gets JoinSize needs a Writer of its own for Vision.
func TestVisionBuffersNotJoined(t *testing.T) {
	for _, conn := range []stat.Connection{&tls.Conn{}, &tls.UConn{}, &reality.Conn{}, &reality.UConn{}, &encryption.CommonConn{}} {
		for _, writer := range []io.Writer{conn, &stat.CounterConnection{Connection: conn}} {
			w, ok := buf.NewWriter(writer).(*buf.SequentialWriter)
			if ok && !reflect.DeepEqual(w, &buf.SequentialWriter{Writer: writer}) {
				t.Errorf("%T in %T: its Buffers are joined", conn, writer)
			}
		}
	}
}
