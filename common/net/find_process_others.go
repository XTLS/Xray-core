//go:build !windows && !linux && !android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

func FindProcess(src Destination, dest Destination) (int, string, string, error) {
	return 0, "", "", errors.New("process lookup is not supported on this platform")
}
