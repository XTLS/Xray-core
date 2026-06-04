package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	xssh "golang.org/x/crypto/ssh"
)

func TestAccountImplementsProtocolAccount(t *testing.T) {
	var _ protocol.Account = (*Account)(nil)
}

func TestBuildClientConfigRejectsMissingUsername(t *testing.T) {
	account := &Account{Password: "secret"}
	_, err := account.BuildClientConfig(nil)
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("expected username error, got %v", err)
	}
}

func TestBuildClientConfigRejectsMissingAuth(t *testing.T) {
	account := &Account{Username: "root"}
	_, err := account.BuildClientConfig(nil)
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestBuildClientConfigAcceptsPassword(t *testing.T) {
	account := &Account{Username: "root", Password: "secret"}
	config, err := account.BuildClientConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.User != "root" || len(config.Auth) != 1 {
		t.Fatalf("unexpected ssh client config: user=%q auth=%d", config.User, len(config.Auth))
	}
}

func TestHostKeySHA256Callback(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pinned := xssh.FingerprintSHA256(signer.PublicKey())
	account := &Account{
		Username:      "root",
		Password:      "secret",
		HostKeySha256: pinned,
	}
	config, err := account.BuildClientConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.HostKeyCallback("example.com", nil, signer.PublicKey()); err != nil {
		t.Fatalf("expected pinned host key to pass: %v", err)
	}

	account.HostKeySha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	config, err = account.BuildClientConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.HostKeyCallback("example.com", nil, signer.PublicKey()); err == nil {
		t.Fatal("expected host key mismatch")
	}
}
