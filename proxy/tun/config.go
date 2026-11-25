package tun

import (
	"context"
	"net"
	"sync"

	"github.com/google/uuid"
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

// ParseGUID parses a canonical textual GUID, as in
// "00000000-0000-0000-0000-000000000000", into the 16 bytes it denotes.
// The form is all that is accepted, not the other ones uuid.Parse takes,
// such as one without hyphens; the length check is what rules those out.
func ParseGUID(s string) ([16]byte, error) {
	if len(s) != 36 {
		return [16]byte{}, errors.New("invalid guid: ", s, ", want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return [16]byte{}, errors.New("invalid guid: ", s, ", want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").Base(err)
	}
	return id, nil
}
