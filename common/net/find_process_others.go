//go:build !windows && !linux && !android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	return 0, "", "", errors.New("process lookup is not supported on this platform")
}
