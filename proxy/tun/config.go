package tun

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type InterfaceUpdater struct {
	sync.Mutex

	tunIndex  int
	fixedName string
	iface     *net.Interface
}

var updater *InterfaceUpdater

func (updater *InterfaceUpdater) Get() *net.Interface {
	updater.Lock()
	defer updater.Unlock()

	return updater.iface
}

func (updater *InterfaceUpdater) Update() {
	updater.Lock()
	defer updater.Unlock()

	if updater.iface != nil {
		iface, err := net.InterfaceByIndex(updater.iface.Index)
		if err == nil && iface.Name == updater.iface.Name {
			return
		}
	}

	updater.iface = nil

	interfaces, err := net.Interfaces()
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "[tun] failed to update interface")
		return
	}

	var got *net.Interface
	for _, iface := range interfaces {
		if iface.Index == updater.tunIndex {
			continue
		}
		if updater.fixedName != "" {
			if iface.Name == updater.fixedName {
				got = &iface
				break
			}
		} else {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			if (iface.Flags&net.FlagUp != 0) &&
				(iface.Flags&net.FlagLoopback == 0) &&
				len(addrs) > 0 {
				got = &iface
				break
			}
		}
	}

	if got == nil {
		errors.LogInfo(context.Background(), "[tun] failed to update interface > got == nil")
		return
	}

	updater.iface = got
	errors.LogInfo(context.Background(), "[tun] update interface ", got.Name, " ", got.Index)
}
