//go:build android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

var androidFindProcessFinder func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)

func RegisterAndroidFindProcessFinder(f func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)) {
	androidFindProcessFinder = f
}

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	if androidFindProcessFinder != nil {
		return androidFindProcessFinder(network, srcIP, srcPort, destIP, destPort)
	}
	return 0, "", "", errors.New("android process lookup must be registered before use")
}
