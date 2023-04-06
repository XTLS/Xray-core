package tun

import "github.com/xtls/xray-core/features"

type Interface interface {
	features.Feature
}

func InterfaceType() interface{} {
	return (*Interface)(nil)
}
