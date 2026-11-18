package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/tun"
)

func buildICMP(value string) (string, error) {
	switch value := strings.ToLower(value); value {
	case "", "fake":
		return "", nil
	case tun.ICMPDrop:
		return value, nil
	default:
		return "", errors.New("unknown icmp value: ", value)
	}
}
