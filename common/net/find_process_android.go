//go:build android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

var AndroidFindProcessImpl func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) = func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	return 0, "", "", errors.New("stub: process lookup is not implemented")
}

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
	return AndroidFindProcessImpl(network, srcIP, srcPort, destIP, destPort)
}
