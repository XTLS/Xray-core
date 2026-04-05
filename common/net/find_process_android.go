//go:build android

package net

import (
	"github.com/xtls/xray-core/common/errors"
)

var AndroidFindProcessImpl func(src Destination, dest Destination) (int, string, string, error) = func(src Destination, dest Destination) (int, string, string, error) {
	return 0, "", "", errors.New("stub: process lookup is not implemented")
}

func FindProcess(src Destination, dest Destination) (int, string, string, error) {
	return AndroidFindProcessImpl(src, dest)
}
