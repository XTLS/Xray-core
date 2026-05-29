package tun

import (
	"context"
	"net"
	"sort"
	"strings"
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
	if updater.fixedName != "" {
		for _, iface := range interfaces {
			if iface.Index == updater.tunIndex {
				continue
			}
			if iface.Name == updater.fixedName {
				got = &iface
				break
			}
		}
	} else {
		var ifs []struct {
			index int
			score int
		}
		for i, iface := range interfaces {
			if iface.Index == updater.tunIndex {
				continue
			}
			if strings.Contains(iface.Name, "vEthernet") {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
			ifs = append(ifs, struct {
				index int
				score int
			}{i, score(&iface, addrs)})
		}
		sort.Slice(ifs, func(i, j int) bool {
			if ifs[i].score != ifs[j].score {
				return ifs[i].score > ifs[j].score
			}

			return interfaces[ifs[i].index].Name < interfaces[ifs[j].index].Name
		})
		if len(ifs) > 0 {
			iface := interfaces[ifs[0].index]
			got = &iface
		}
	}

	if got == nil {
		errors.LogInfo(context.Background(), "[tun] failed to update interface > got == nil")
		return
	}

	updater.iface = got
	errors.LogInfo(context.Background(), "[tun] update interface ", got.Name, " ", got.Index)
}

func score(iface *net.Interface, addrs []net.Addr) int {
	score := 0

	name := strings.ToLower(iface.Name)
	if strings.Contains(name, "wlan") || strings.Contains(name, "wi-fi") {
		score += 2
	}

	for _, addr := range addrs {
		if strings.HasPrefix(addr.String(), "192.168.") {
			score += 1
			break
		}
	}

	return score
}
