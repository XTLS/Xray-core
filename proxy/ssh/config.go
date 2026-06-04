package ssh

import (
	"fmt"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	xssh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func (a *Account) Equals(another protocol.Account) bool {
	account, ok := another.(*Account)
	return ok && a.Username == account.Username
}

func (a *Account) ToProto() proto.Message {
	return a
}

func (a *Account) AsAccount() (protocol.Account, error) {
	return a, nil
}

func (a *Account) BuildClientConfig(hostKeyCallback xssh.HostKeyCallback) (*xssh.ClientConfig, error) {
	if a == nil {
		return nil, errors.New("SSH account is missing")
	}
	if a.Username == "" {
		return nil, errors.New("SSH username is required")
	}
	auth, err := a.authMethods()
	if err != nil {
		return nil, err
	}
	callback := a.hostKeyCallback(hostKeyCallback)
	return &xssh.ClientConfig{
		User:            a.Username,
		Auth:            auth,
		HostKeyCallback: callback,
	}, nil
}

func (a *Account) authMethods() ([]xssh.AuthMethod, error) {
	auth := make([]xssh.AuthMethod, 0, 2)
	if a.Password != "" {
		auth = append(auth, xssh.Password(a.Password))
	}
	if a.PrivateKey != "" {
		signer, err := parsePrivateKey(a.PrivateKey, a.PrivateKeyPassphrase)
		if err != nil {
			return nil, errors.New("failed to parse SSH private key").Base(err)
		}
		auth = append(auth, xssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return nil, errors.New("SSH auth method is required")
	}
	return auth, nil
}

func parsePrivateKey(privateKey string, passphrase string) (xssh.Signer, error) {
	if passphrase != "" {
		return xssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	}
	return xssh.ParsePrivateKey([]byte(privateKey))
}

func (a *Account) hostKeyCallback(fallback xssh.HostKeyCallback) xssh.HostKeyCallback {
	if a.HostKeySha256 == "" {
		if fallback != nil {
			return fallback
		}
		return xssh.InsecureIgnoreHostKey()
	}
	return func(hostname string, remote net.Addr, key xssh.PublicKey) error {
		got := xssh.FingerprintSHA256(key)
		if got != a.HostKeySha256 {
			return fmt.Errorf("SSH host key fingerprint mismatch for %s: got %s, want %s", hostname, got, a.HostKeySha256)
		}
		return nil
	}
}
