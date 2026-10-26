package vless_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
)

func TestDeviceIDAccount(t *testing.T) {
	for _, test := range []struct {
		name      string
		account   *vless.Account
		wantError bool
	}{
		{name: "legacy", account: &vless.Account{}},
		{name: "maximum length", account: &vless.Account{DeviceId: strings.Repeat("a", 128)}},
		{name: "too long", account: &vless.Account{DeviceId: strings.Repeat("a", 129)}, wantError: true},
		{name: "whitespace", account: &vless.Account{DeviceId: "device a"}, wantError: true},
		{name: "control character", account: &vless.Account{DeviceId: "device\na"}, wantError: true},
		{name: "non ASCII", account: &vless.Account{DeviceId: "устройство"}, wantError: true},
		{name: "disabled allowlist", account: &vless.Account{AllowedDeviceIds: []string{"device-a"}}, wantError: true},
		{name: "empty allowed ID", account: &vless.Account{EnforceDeviceId: true, AllowedDeviceIds: []string{""}}, wantError: true},
		{name: "deny all", account: &vless.Account{EnforceDeviceId: true}},
		{name: "allowlist", account: &vless.Account{EnforceDeviceId: true, AllowedDeviceIds: []string{"device-a", "device-b"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.account.Id = "27848739-7e62-4138-9fd3-098a63964b6b"
			account, err := test.account.AsAccount()
			if (err != nil) != test.wantError {
				t.Fatalf("AsAccount error = %v, want error = %v", err, test.wantError)
			}
			if err == nil && !proto.Equal(account.ToProto(), test.account) {
				t.Fatal("account conversion lost device settings")
			}
		})
	}
}
