package conf_test

import (
	"encoding/json"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	proxyssh "github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

func TestSSHClientConfigBuildPassword(t *testing.T) {
	creator := func() Buildable {
		return new(SSHClientConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"servers": [{
					"address": "127.0.0.1",
					"port": 22,
					"user": "root",
					"password": "secret",
					"hostKeySHA256": "SHA256:abc"
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &proxyssh.ClientConfig{
				Server: &protocol.ServerEndpoint{
					Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
					Port:    22,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&proxyssh.Account{
							Username:      "root",
							Password:      "secret",
							HostKeySha256: "SHA256:abc",
						}),
					},
				},
			},
		},
	})
}

func TestSSHClientConfigDefaultsPort(t *testing.T) {
	config := &SSHClientConfig{
		Servers: []*SSHRemoteConfig{{
			Address:  &Address{Address: xnet.ParseAddress("example.com")},
			User:     "root",
			Password: "secret",
		}},
	}
	msg, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	out := msg.(*proxyssh.ClientConfig)
	if out.Server.Port != 22 {
		t.Fatalf("expected port 22, got %d", out.Server.Port)
	}
}

func TestSSHClientConfigRejectsMissingAuth(t *testing.T) {
	config := &SSHClientConfig{
		Servers: []*SSHRemoteConfig{{
			Address: &Address{Address: xnet.ParseAddress("example.com")},
			Port:    22,
			User:    "root",
		}},
	}
	_, err := config.Build()
	if err == nil {
		t.Fatal("expected missing auth error")
	}
}

func TestSSHClientConfigRejectsMultipleServers(t *testing.T) {
	config := &SSHClientConfig{
		Servers: []*SSHRemoteConfig{
			{Address: &Address{Address: xnet.ParseAddress("one.example")}, User: "root", Password: "secret"},
			{Address: &Address{Address: xnet.ParseAddress("two.example")}, User: "root", Password: "secret"},
		},
	}
	_, err := config.Build()
	if err == nil {
		t.Fatal("expected multiple server error")
	}
}

func TestSSHOutboundDetourConfigLoadsProtocol(t *testing.T) {
	settings := json.RawMessage(`{
		"servers": [{
			"address": "127.0.0.1",
			"port": 22,
			"user": "root",
			"password": "secret"
		}]
	}`)
	config := &OutboundDetourConfig{
		Protocol: "ssh",
		Settings: &settings,
	}
	outbound, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*proxyssh.ClientConfig); !ok {
		t.Fatalf("expected SSH client config, got %T", msg)
	}
	if !proto.Equal(msg, (&proxyssh.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
			Port:    22,
			User: &protocol.User{
				Account: serial.ToTypedMessage(&proxyssh.Account{
					Username: "root",
					Password: "secret",
				}),
			},
		},
	})) {
		t.Fatalf("unexpected outbound proxy settings: %v", msg)
	}
}
