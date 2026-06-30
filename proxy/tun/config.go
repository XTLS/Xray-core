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

	got, err := findOutboundInterface(updater.tunIndex, updater.fixedName)
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "[tun] failed to update interface")
		updater.iface = nil
		return
	}

	if got == nil {
		errors.LogInfo(context.Background(), "[tun] failed to update interface > got == nil")
		updater.iface = nil
		return
	}

	if updater.iface != nil && updater.iface.Index == got.Index && updater.iface.Name == got.Name {
		return
	}

	updater.iface = got
	errors.LogInfo(context.Background(), "[tun] update interface ", got.Name, " ", got.Index)
}
