//go:build windows

package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Handle owns a WinDivert kernel device handle plus a private event for
// overlapped I/O. Methods on *Handle are not safe for concurrent use
// across goroutines (there is a single shared event per Handle).
//
// addr is a per-Handle Address buffer the IOCTL struct embeds a pointer
// to. It lives on the heap (as a field of a heap-allocated Handle) so
// the pointer value stored as bytes in the ioctl buffer remains valid
// across stack growth between buildIoctl* and the DeviceIoControl
// syscall — stack-local Address values are not safe for this pattern
// because Go's escape analysis does not see the pointer through the
// unsafe.Pointer → uintptr → bytes conversion.
type Handle struct {
	device   windows.Handle
	event    windows.Handle
	closing  sync.Once
	closeErr error
	addr     Address
}

// Filter may be nil for "reject all", suitable for send-only handles.
// Requires Administrator on first call per process (installs the kernel
// driver via SCM); subsequent calls reuse the running driver.
func Open(filter *Filter, layer Layer, priority int16, flags Flag) (*Handle, error) {
	err := validateOpenArgs(layer, priority, flags)
	if err != nil {
		return nil, err
	}
	if filter == nil {
		filter = reject()
	}
	filterBin, filterFlags, err := filter.encode()
	if err != nil {
		return nil, err
	}
	device, err := openDevice()
	if err != nil {
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) &&
			!errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				return nil, fmt.Errorf("windivert: open device (administrator required): %w", err)
			}
			return nil, fmt.Errorf("windivert: open device: %w", err)
		}
		// Device node missing: kernel driver not loaded. Install + retry.
		// Matches WinDivertOpen's lazy-install path; avoids racing StartService
		// against a still-loaded driver whose SCM record is marked for deletion.
		err = ensureDriver()
		if err != nil {
			return nil, err
		}
		device, err = openDevice()
		if err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				return nil, fmt.Errorf("windivert: open device (administrator required): %w", err)
			}
			return nil, fmt.Errorf("windivert: open device: %w", err)
		}
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil) // manual reset, unsignaled
	if err != nil {
		windows.CloseHandle(device)
		return nil, fmt.Errorf("windivert: create event: %w", err)
	}
	h := &Handle{device: device, event: event}

	err = h.initialize(layer, priority, flags)
	if err != nil {
		h.Close()
		return nil, err
	}
	err = h.startup(filterBin, filterFlags)
	if err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func openDevice() (windows.Handle, error) {
	return windows.CreateFile(
		driverDevName,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
}

func validateOpenArgs(layer Layer, priority int16, flags Flag) error {
	if layer != LayerNetwork {
		return fmt.Errorf("windivert: invalid layer %d", uint32(layer))
	}
	if priority < PriorityLowest || priority > PriorityHighest {
		return errors.New("windivert: priority out of range")
	}
	const supportedFlags = FlagSniff | FlagSendOnly
	if flags&^supportedFlags != 0 {
		return errors.New("windivert: unknown flag bits")
	}
	if flags&FlagSniff != 0 && flags&FlagSendOnly != 0 {
		return errors.New("windivert: FlagSniff and FlagSendOnly are mutually exclusive")
	}
	return nil
}

func (h *Handle) initialize(layer Layer, priority int16, flags Flag) error {
	in := buildIoctlInitialize(layer, priority, flags)
	// WINDIVERT_VERSION is a 64-byte packed struct; only the first 20
	// bytes (magic, major, minor, bits) carry data, the rest is reserved.
	var outBuf [versionStructSize]byte
	binary.LittleEndian.PutUint64(outBuf[0:8], magicDLL)
	binary.LittleEndian.PutUint32(outBuf[8:12], versionMajor)
	binary.LittleEndian.PutUint32(outBuf[12:16], versionMinor)
	binary.LittleEndian.PutUint32(outBuf[16:20], uint32(unsafe.Sizeof(uintptr(0))*8))
	_, err := doIoctl(h.device, ioctlInitialize, in[:], outBuf[:], h.event)
	if err != nil {
		return fmt.Errorf("windivert: initialize ioctl: %w", err)
	}
	gotMagic := binary.LittleEndian.Uint64(outBuf[0:8])
	if gotMagic != magicSYS {
		return fmt.Errorf("windivert: driver magic mismatch (got %d)", gotMagic)
	}
	gotMajor := binary.LittleEndian.Uint32(outBuf[8:12])
	if gotMajor < versionMajor {
		gotMinor := binary.LittleEndian.Uint32(outBuf[12:16])
		return fmt.Errorf("windivert: driver version too old: %d.%d", gotMajor, gotMinor)
	}
	return nil
}

func (h *Handle) startup(filterBin []byte, filterFlags uint64) error {
	in := buildIoctlStartup(filterFlags)
	_, err := doIoctl(h.device, ioctlStartup, in[:], filterBin, h.event)
	if err != nil {
		return fmt.Errorf("windivert: startup ioctl: %w", err)
	}
	return nil
}

// If the handle is closed mid-Recv the error wraps ERROR_OPERATION_ABORTED.
func (h *Handle) Recv(buf []byte) (int, Address, error) {
	if len(buf) == 0 {
		return 0, Address{}, errors.New("windivert: recv: zero-length buffer")
	}
	h.addr = Address{}
	in := buildIoctlRecv(&h.addr)
	n, err := doIoctl(h.device, ioctlRecv, in[:], buf, h.event)
	runtime.KeepAlive(h)
	if err != nil {
		return 0, Address{}, err
	}
	return int(n), h.addr, nil
}

// The address's Outbound flag controls whether the packet is sent toward
// the wire (outbound=true) or delivered up the stack (outbound=false).
// IfIdx and SubIfIdx can stay zero — the driver uses the routing table
// when IfIdx=0.
func (h *Handle) Send(packet []byte, addr *Address) (int, error) {
	if len(packet) == 0 {
		return 0, errors.New("windivert: send: empty packet")
	}
	if addr == nil {
		return 0, errors.New("windivert: send: nil address")
	}
	h.addr = *addr
	in := buildIoctlSend(&h.addr)
	n, err := doIoctl(h.device, ioctlSend, in[:], packet, h.event)
	runtime.KeepAlive(h)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// Idempotent. Aborts any in-flight I/O on the handle.
func (h *Handle) Close() error {
	h.closing.Do(func() {
		var errs []error
		if h.device != 0 {
			err := windows.CloseHandle(h.device)
			if err != nil {
				errs = append(errs, err)
			}
			h.device = 0
		}
		if h.event != 0 {
			err := windows.CloseHandle(h.event)
			if err != nil {
				errs = append(errs, err)
			}
			h.event = 0
		}
		h.closeErr = errors.Join(errs...)
	})
	return h.closeErr
}

// IOCTL codes from windivert_device.h. CTL_CODE macro layout:
//
//	(DeviceType << 16) | (Access << 14) | (Function << 2) | Method
const (
	fileDeviceNetwork uint32 = 0x12
	accessReadWrite   uint32 = 3 // FILE_READ_DATA | FILE_WRITE_DATA
	accessRead        uint32 = 1

	methodInDirect  uint32 = 1
	methodOutDirect uint32 = 2
)

func ctlCode(deviceType, access, function, method uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

var (
	ioctlInitialize = ctlCode(fileDeviceNetwork, accessReadWrite, 0x921, methodOutDirect)
	ioctlStartup    = ctlCode(fileDeviceNetwork, accessReadWrite, 0x922, methodInDirect)
	ioctlRecv       = ctlCode(fileDeviceNetwork, accessRead, 0x923, methodOutDirect)
	ioctlSend       = ctlCode(fileDeviceNetwork, accessReadWrite, 0x924, methodInDirect)
)

// Magic numbers exchanged during INITIALIZE. DLL sends magicDLL in the
// version struct; driver returns magicSYS on success.
const (
	magicDLL uint64 = 0x4C4C447669645724 // "$WdivDLL" in LE bytes
	magicSYS uint64 = 0x5359537669645723 // "#WdivSYS" in LE bytes
)

const (
	versionMajor uint32 = 2
	versionMinor uint32 = 2
)

// Size of the WINDIVERT_IOCTL union on wire (packed).
const ioctlSize = 16

// Size of WINDIVERT_VERSION on wire (packed). Only the first 20 bytes
// carry data; the rest is reserved zero padding.
const versionStructSize = 64

// doIoctl performs a single synchronous (blocking) overlapped
// DeviceIoControl. The handle is opened with FILE_FLAG_OVERLAPPED so
// DeviceIoControl returns ERROR_IO_PENDING; we then wait for completion
// via GetOverlappedResult. Event is passed in so callers can reuse it
// across calls on the same handle (avoids per-call CreateEvent).
func doIoctl(handle windows.Handle, code uint32, in []byte, out []byte, event windows.Handle) (uint32, error) {
	var overlapped windows.Overlapped
	overlapped.HEvent = event
	_ = windows.ResetEvent(event)

	var inPtr *byte
	var inLen uint32
	if len(in) > 0 {
		inPtr = &in[0]
		inLen = uint32(len(in))
	}
	var outPtr *byte
	var outLen uint32
	if len(out) > 0 {
		outPtr = &out[0]
		outLen = uint32(len(out))
	}
	var returned uint32
	err := windows.DeviceIoControl(handle, code, inPtr, inLen, outPtr, outLen, &returned, &overlapped)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	err = windows.GetOverlappedResult(handle, &overlapped, &returned, true)
	if err != nil {
		return 0, err
	}
	return returned, nil
}

func buildIoctlInitialize(layer Layer, priority int16, flags Flag) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint32(buf[0:4], uint32(layer))
	// The driver expects priority + WINDIVERT_PRIORITY_HIGHEST (30000) so
	// the low range maps to non-negative integers.
	binary.LittleEndian.PutUint32(buf[4:8], uint32(int32(priority)+int32(PriorityHighest)))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(flags))
	return buf
}

func buildIoctlStartup(filterFlags uint64) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], filterFlags)
	return buf
}

// buildIoctlRecv packs a user-space pointer to a WINDIVERT_ADDRESS into
// the ioctl struct. The driver dereferences it to write the address for
// the received packet. Caller must keep the Address alive via
// runtime.KeepAlive.
func buildIoctlRecv(addr *Address) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(uintptr(unsafe.Pointer(addr))))
	binary.LittleEndian.PutUint64(buf[8:16], 0)
	return buf
}

func buildIoctlSend(addr *Address) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(uintptr(unsafe.Pointer(addr))))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(unsafe.Sizeof(Address{})))
	return buf
}
