package ssh_test

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol/ssh"
)

func TestSniffSSH(t *testing.T) {
	pkt := []byte("SSH-2.0-OpenSSH_8.1")
	_, err := ssh.SniffSSH(pkt)
	if err != nil {
		t.Error("failed to parse SSH packet")
	}
}
