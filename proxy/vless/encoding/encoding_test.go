package encoding_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
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

func TestRequestDeviceID(t *testing.T) {
	tests := []struct {
		name       string
		flow       string
		deviceID   string
		enforce    bool
		allowedIDs []string
		wantError  bool
		fallback   bool
	}{
		{name: "legacy request", wantError: false},
		{name: "allowed device", deviceID: "device-a", enforce: true, allowedIDs: []string{"device-a"}},
		{name: "allowed device with vision", flow: vless.XRV, deviceID: "device-a", enforce: true, allowedIDs: []string{"device-a"}},
		{name: "unknown device", deviceID: "device-b", enforce: true, allowedIDs: []string{"device-a"}, wantError: true},
		{name: "missing device", enforce: true, allowedIDs: []string{"device-a"}, wantError: true},
		{name: "empty allowlist", deviceID: "device-a", enforce: true, wantError: true},
		{name: "allowed with fallback", deviceID: "device-a", enforce: true, allowedIDs: []string{"device-a"}, fallback: true},
		{name: "rejected with fallback", deviceID: "device-b", enforce: true, allowedIDs: []string{"device-a"}, wantError: true, fallback: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generatedID := uuid.New()
			id := generatedID.String()
			client := &protocol.MemoryUser{Account: toAccount(&vless.Account{Id: id})}
			server := &protocol.MemoryUser{Account: toAccount(&vless.Account{
				Id:               id,
				EnforceDeviceId:  test.enforce,
				AllowedDeviceIds: test.allowedIDs,
			})}
			request := &protocol.RequestHeader{
				Version: Version,
				User:    client,
				Command: protocol.RequestCommandTCP,
				Address: net.DomainAddress("example.com"),
				Port:    443,
			}
			buffer := buf.StackNew()
			defer buffer.Release()
			if err := EncodeRequestHeader(&buffer, request, &Addons{Flow: test.flow, DeviceId: test.deviceID}); err != nil {
				t.Fatal(err)
			}
			validator := new(vless.MemoryValidator)
			if err := validator.Add(server); err != nil {
				t.Fatal(err)
			}
			_, decodedRequest, decodedAddons, useFallback, err := DecodeRequestHeader(test.fallback, &buffer, &buffer, validator)
			if useFallback {
				t.Fatal("authenticated device request must not be forwarded to fallback")
			}
			if test.wantError {
				if err == nil {
					t.Fatal("expected device ID to be rejected")
				}
				if !strings.Contains(err.Error(), "device ID is not allowed") {
					t.Fatalf("unexpected rejection: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if decodedRequest.User != server {
				t.Fatal("request was not authenticated as the configured user")
			}
			if decodedAddons.DeviceId != test.deviceID {
				t.Fatalf("device ID = %q, want %q", decodedAddons.DeviceId, test.deviceID)
			}
			if decodedAddons.Flow != test.flow {
				t.Fatalf("flow = %q, want %q", decodedAddons.Flow, test.flow)
			}
		})
	}
}

func TestDeviceIDAddonsLength(t *testing.T) {
	// The tag and two-byte protobuf length take three of the 255 available bytes.
	for _, length := range []int{252, 253} {
		addons := &Addons{DeviceId: strings.Repeat("a", length)}
		buffer := buf.StackNew()
		err := EncodeHeaderAddons(&buffer, addons)
		if length == 253 {
			if err == nil {
				t.Fatal("oversized addons were accepted")
			}
			buffer.Release()
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if buffer.Byte(0) != 255 {
			t.Fatalf("encoded addons length = %d, want 255", buffer.Byte(0))
		}
		scratch := buf.StackNew()
		decoded, err := DecodeHeaderAddons(&scratch, &buffer)
		buffer.Release()
		scratch.Release()
		if err != nil {
			t.Fatal(err)
		}
		if decoded.DeviceId != addons.DeviceId {
			t.Fatal("device ID was truncated at the maximum addons length")
		}
	}
}
