//go:build android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

var AndroidFindProcessFinder func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)

func RegisterAndroidFindProcessFinder(f func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error)) {
	AndroidFindProcessFinder = f
}

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	if AndroidFindProcessFinder != nil {
		return AndroidFindProcessFinder(network, srcIP, srcPort, destIP, destPort)
	}
	return 0, "", "", errors.New("android process lookup must be registered before use")
}
