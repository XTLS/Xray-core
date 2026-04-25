//go:build android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

var androidProcessFinder func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)

func RegisterAndroidProcessFinder(f func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)) {
	androidProcessFinder = f
}

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	if androidProcessFinder != nil {
		return androidProcessFinder(network, srcIP, srcPort, destIP, destPort)
	}
	return 0, "", "", errors.New("android process lookup must be registered before use")
}
