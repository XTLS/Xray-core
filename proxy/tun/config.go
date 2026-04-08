package tun

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type InterfaceUpdater struct {
	sync.Mutex

	tunIndex int
	iface    *net.Interface
}

var updater *InterfaceUpdater

func (updater *InterfaceUpdater) Get() *int {
	updater.Lock()
	defer updater.Unlock()

	if updater.iface == nil {
		return nil
	}

	index := updater.iface.Index
	return &index
}

func (updater *InterfaceUpdater) Update() {
	updater.Lock()
	defer updater.Unlock()

	if updater.iface != nil {
		_, err := net.InterfaceByIndex(updater.iface.Index)
		if err == nil {
			return
		}
	}

	updater.iface = nil

	interfaces, err := net.Interfaces()
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to update default interface")
		return
	}

	var got *net.Interface
	for _, iface := range interfaces {
		if iface.Index == updater.tunIndex {
			continue
		}
		if iface.Flags&net.FlagLoopback == 0 {
			got = &iface
			break
		}
	}

	if got == nil {
		errors.LogInfo(context.Background(), "failed to update default interface > got == nil")
		return
	}

	updater.iface = got
	errors.LogInfo(context.Background(), "update default interface ", got.Name, " ", got.Index)
}
