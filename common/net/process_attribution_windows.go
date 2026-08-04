//go:build windows

package net

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xtls/xray-core/common/errors"
)

const (
	windivertLayerFlow = 2

	windivertEventFlowEstablished = 1

	windivertFlagSniff    = 0x0001
	windivertFlagRecvOnly = 0x0004

	windivertProtocolTCP = 6
	windivertProtocolUDP = 17
)

var processAttributionOnce sync.Once

type windivertAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Flow      windivertDataFlow
}

type windivertDataFlow struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte
}

var (
	_ [80 - unsafe.Sizeof(windivertAddress{})]byte
	_ [unsafe.Sizeof(windivertAddress{}) - 80]byte
	_ [64 - unsafe.Sizeof(windivertDataFlow{})]byte
	_ [unsafe.Sizeof(windivertDataFlow{}) - 64]byte
)

type windivertFlowAttributor struct {
	handle     windows.Handle
	dll        *windows.DLL
	recv       *windows.Proc
	formatIPv6 *windows.Proc
}

func startProcessAttribution() {
	processAttributionOnce.Do(func() {
		attributor, err := newWinDivertFlowAttributor()
		if err != nil {
			errors.LogDebugInner(context.Background(), err, "WinDivert process attribution unavailable")
			return
		}
		go attributor.run()
	})
}

func newWinDivertFlowAttributor() (*windivertFlowAttributor, error) {
	dll, err := windows.LoadDLL("WinDivert.dll")
	if err != nil {
		return nil, err
	}

	open, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return nil, err
	}
	recv, err := dll.FindProc("WinDivertRecv")
	if err != nil {
		return nil, err
	}
	formatIPv6, err := dll.FindProc("WinDivertHelperFormatIPv6Address")
	if err != nil {
		return nil, err
	}

	filter, err := windows.BytePtrFromString("true")
	if err != nil {
		return nil, err
	}

	handle, err := windivertOpen(open, filter, windivertFlagSniff|windivertFlagRecvOnly)
	if err != nil {
		handle, err = windivertOpen(open, filter, windivertFlagRecvOnly)
	}
	if err != nil {
		return nil, err
	}

	setProcessAttributionActive()
	return &windivertFlowAttributor{
		handle:     handle,
		dll:        dll,
		recv:       recv,
		formatIPv6: formatIPv6,
	}, nil
}

func windivertOpen(open *windows.Proc, filter *byte, flags uint64) (windows.Handle, error) {
	r0, _, e1 := open.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(windivertLayerFlow),
		0,
		uintptr(flags),
	)
	handle := windows.Handle(r0)
	if handle == 0 || handle == windows.InvalidHandle {
		if e1 != windows.ERROR_SUCCESS {
			return 0, e1
		}
		return 0, windows.ERROR_INVALID_HANDLE
	}
	return handle, nil
}

func (a *windivertFlowAttributor) run() {
	for {
		var addr windivertAddress
		r0, _, e1 := a.recv.Call(
			uintptr(a.handle),
			0,
			0,
			0,
			uintptr(unsafe.Pointer(&addr)),
		)
		if r0 == 0 {
			if e1 != windows.ERROR_SUCCESS {
				errors.LogDebugInner(context.Background(), e1, "WinDivert process attribution stopped")
			}
			return
		}
		a.handleFlow(addr)
	}
}

func (a *windivertFlowAttributor) handleFlow(addr windivertAddress) {
	if windivertEvent(addr.Flags) != windivertEventFlowEstablished || addr.Flow.ProcessID == 0 {
		return
	}

	network := ""
	switch addr.Flow.Protocol {
	case windivertProtocolTCP:
		network = "tcp"
	case windivertProtocolUDP:
		network = "udp"
	default:
		return
	}

	localIP, ok := a.formatAddr(addr.Flow.LocalAddr)
	if !ok {
		return
	}
	remoteIP, ok := a.formatAddr(addr.Flow.RemoteAddr)
	if !ok {
		return
	}

	pid, name, absolutePath, ok := processIdentityFromPID(addr.Flow.ProcessID)
	if !ok {
		return
	}

	storeProcessAttribution(network, localIP, addr.Flow.LocalPort, remoteIP, addr.Flow.RemotePort, pid, name, absolutePath)
}

func windivertEvent(flags uint32) uint8 {
	return uint8((flags >> 8) & 0xff)
}

func (a *windivertFlowAttributor) formatAddr(raw [4]uint32) (string, bool) {
	var buf [64]byte
	r0, _, _ := a.formatIPv6.Call(
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r0 == 0 {
		return "", false
	}
	addr := windows.BytePtrToString(&buf[0])
	return canonicalProcessAttributionIP(addr), true
}

func processIdentityFromPID(pid uint32) (int, string, string, bool) {
	absolutePath, err := getExecPathFromPID(pid)
	if err != nil {
		return 0, "", "", false
	}
	absolutePath = filepath.ToSlash(absolutePath)

	nameSplit := strings.Split(absolutePath, "/")
	name := nameSplit[len(nameSplit)-1]
	name = strings.TrimSuffix(name, ".exe")
	return int(pid), name, absolutePath, true
}
