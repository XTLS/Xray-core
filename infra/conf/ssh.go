package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	proxyssh "github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

type SSHRemoteConfig struct {
	Address              *Address `json:"address"`
	Port                 uint16   `json:"port"`
	User                 string   `json:"user"`
	Password             string   `json:"password"`
	PrivateKey           string   `json:"privateKey"`
	PrivateKeyPassphrase string   `json:"privateKeyPassphrase"`
	HostKeySHA256        string   `json:"hostKeySHA256"`
}

type SSHClientConfig struct {
	Servers []*SSHRemoteConfig `json:"servers"`
}

func (v *SSHClientConfig) Build() (proto.Message, error) {
	if len(v.Servers) != 1 {
		return nil, errors.New(`SSH settings: "servers" should have one and only one member. Multiple endpoints in "servers" should use multiple SSH outbounds and routing balancer instead`)
	}
	serverConfig := v.Servers[0]
	if serverConfig.Address == nil {
		return nil, errors.New(`SSH server "address" is required`)
	}
	if serverConfig.User == "" {
		return nil, errors.New(`SSH server "user" is required`)
	}
	if serverConfig.Password == "" && serverConfig.PrivateKey == "" {
		return nil, errors.New(`SSH server requires "password" or "privateKey"`)
	}
	port := serverConfig.Port
	if port == 0 {
		port = 22
	}
	account := &proxyssh.Account{
		Username:             serverConfig.User,
		Password:             serverConfig.Password,
		PrivateKey:           serverConfig.PrivateKey,
		PrivateKeyPassphrase: serverConfig.PrivateKeyPassphrase,
		HostKeySha256:        serverConfig.HostKeySHA256,
	}
	return &proxyssh.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: serverConfig.Address.Build(),
			Port:    uint32(port),
			User: &protocol.User{
				Account: serial.ToTypedMessage(account),
			},
		},
	}, nil
}
