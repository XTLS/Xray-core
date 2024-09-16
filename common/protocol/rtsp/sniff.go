package rtsp

import (
	"bytes"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
)

type version byte

const (
	RTSP1 version = iota
)

type SniffHeader struct {
	version version
	host    string
}

func (h *SniffHeader) Protocol() string {
	switch h.version {
	case RTSP1:
		return "rtsp1"
	default:
		return "unknown"
	}
}

func (h *SniffHeader) Domain() string {
	return h.host
}

var (
	methods = [...]string{
		"options", "describe", "setup", "play", "pause", "teardown", "get_parameter", "set_parameter", "announce", "record",
	}

	errNotRTSPMethod = errors.New("not an RTSP method")
)

func beginWithRTSPMethod(b []byte) error {
	for _, m := range &methods {
		if len(b) >= len(m) && strings.EqualFold(string(b[:len(m)]), m) {
			return nil
		}

		if len(b) < len(m) {
			return common.ErrNoClue
		}
	}

	return errNotRTSPMethod
}

func SniffRTSP(b []byte) (*SniffHeader, error) {
	if err := beginWithRTSPMethod(b); err != nil {
		return nil, err
	}

	sh := &SniffHeader{
		version: RTSP1,
	}

	headers := bytes.Split(b, []byte{'\n'})
	for i := 1; i < len(headers); i++ {
		header := headers[i]
		if len(header) == 0 {
			break
		}
		parts := bytes.SplitN(header, []byte{':'}, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(string(parts[0]))
		if key == "host" {
			rawHost := strings.ToLower(string(bytes.TrimSpace(parts[1])))
			dest, err := ParseHost(rawHost, net.Port(554))
			if err != nil {
				return nil, err
			}
			sh.host = dest.Address.String()
		}
	}

	if len(sh.host) > 0 {
		return sh, nil
	}

	return nil, common.ErrNoClue
}
