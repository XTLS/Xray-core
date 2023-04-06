package tun

import (
	"net"

	"github.com/sagernet/sing/common/control"
)

var _ control.InterfaceFinder = (*myInterfaceFinder)(nil)

type myInterfaceFinder struct {
	ifs []net.Interface
}

func (f *myInterfaceFinder) update() error {
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	f.ifs = ifs
	return nil
}

func (f *myInterfaceFinder) InterfaceIndexByName(name string) (interfaceIndex int, err error) {
	for _, netInterface := range f.ifs {
		if netInterface.Name == name {
			return netInterface.Index, nil
		}
	}
	netInterface, err := net.InterfaceByName(name)
	if err != nil {
		return
	}
	f.update()
	return netInterface.Index, nil
}

func (f *myInterfaceFinder) InterfaceNameByIndex(index int) (interfaceName string, err error) {
	for _, netInterface := range f.ifs {
		if netInterface.Index == index {
			return netInterface.Name, nil
		}
	}
	netInterface, err := net.InterfaceByIndex(index)
	if err != nil {
		return
	}
	f.update()
	return netInterface.Name, nil
}
