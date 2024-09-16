package ssh

import (
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "ssh"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotSSH = errors.New("not SSH header")

func SniffSSH(b []byte) (*SniffHeader, error) {
	if len(b) < 4 {
		return nil, common.ErrNoClue
	}

	buffer := buf.FromBytes(b)
	var idBuffer [4]byte
	if _, err := buffer.Read(idBuffer[:]); err != nil {
		return nil, common.ErrNoClue
	}

	if !strings.HasPrefix(string(idBuffer[:]), "SSH-") {
		return nil, errNotSSH
	}

	return &SniffHeader{}, nil
}
