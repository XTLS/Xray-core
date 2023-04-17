package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/log"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Tunnel interface {
	BuildDevice(ipc string, bind conn.Bind) error
	DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error)
	Close() error
}

type tunnel struct {
	tun    tun.Device
	device *device.Device
	rw     sync.Mutex
}

func (t *tunnel) BuildDevice(ipc string, bind conn.Bind) (err error) {
	t.rw.Lock()
	defer t.rw.Unlock()

	if t.device != nil {
		return errors.New("device is already initialized")
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  fmt.Sprintf(format, args...),
			})
		},
		Errorf: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf(format, args...),
			})
		},
	}

	t.device = device.NewDevice(t.tun, bind, logger)
	if err = t.device.IpcSet(ipc); err != nil {
		return err
	}
	if err = t.device.Up(); err != nil {
		return err
	}
	return nil
}

func (t *tunnel) Close() (err error) {
	t.rw.Lock()
	defer t.rw.Unlock()

	if t.device == nil {
		return nil
	}

	t.device.Close()
	t.device = nil
	err = t.tun.Close()
	t.tun = nil
	return nil
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = fmt.Sprintf("%s%d", tunName, tunIndex)
	return
}
