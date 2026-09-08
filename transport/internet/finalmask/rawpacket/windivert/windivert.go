// Package windivert provides a pure-Go binding to the WinDivert kernel
// driver on Windows (amd64 and 386). User-mode WinDivert calls are
// reimplemented in Go; only the signed kernel driver is embedded as an
// asset, since SCM-installed drivers must live on disk and their
// Authenticode signature forbids modification.
//
// Administrator is required for the first Open in a process so SCM can
// load the driver. Upstream: https://github.com/basil00/WinDivert v2.2.2,
// redistributed under its LGPL v3 option; see assets/LICENSE.txt.
package windivert

import "unsafe"

const AssetVersion = "2.2.2"

// MTUMax is WINDIVERT_MTU_MAX from windivert.h (40 + 0xFFFF). Suitable as
// a single-packet receive buffer size.
const MTUMax = 40 + 0xFFFF

type Layer uint32

const LayerNetwork Layer = 0

type Flag uint64

const (
	// FlagSniff opens a passive observer: the driver copies matching packets
	// to userspace without removing them from the network stack. Send is not
	// required (and not allowed) on a sniffing handle.
	FlagSniff Flag = 0x0001
	// FlagSendOnly opens a write-only injection handle; Recv is not allowed.
	FlagSendOnly Flag = 0x0008
)

const (
	PriorityHighest int16 = 30000
	PriorityLowest  int16 = -30000
)

// Address mirrors WINDIVERT_ADDRESS from windivert.h (80 bytes,
// little-endian on both amd64 and 386):
//
//	 0: INT64  Timestamp
//	 8: UINT32 bitfield: Layer:8 | Event:8 | flags | Reserved1:8
//	12: UINT32 Reserved2
//	16: 64 bytes union (WINDIVERT_DATA_NETWORK / FLOW / SOCKET / REFLECT)
type Address struct {
	Timestamp int64
	bits      uint32
	Reserved2 uint32
	union     [64]byte
}

var _ [80]byte = [unsafe.Sizeof(Address{})]byte{}

// Bit positions inside the Address's packed flags word.
const (
	addrBitIPv6        = 20
	addrBitIPChecksum  = 21
	addrBitTCPChecksum = 22
)

func getFlagBit(bits uint32, pos uint) bool { return bits&(1<<pos) != 0 }
func setFlagBit(bits uint32, pos uint, v bool) uint32 {
	if v {
		return bits | (1 << pos)
	}
	return bits &^ (1 << pos)
}

func (a *Address) IPv6() bool { return getFlagBit(a.bits, addrBitIPv6) }
func (a *Address) SetIPChecksum(v bool) {
	a.bits = setFlagBit(a.bits, addrBitIPChecksum, v)
}

func (a *Address) SetTCPChecksum(v bool) {
	a.bits = setFlagBit(a.bits, addrBitTCPChecksum, v)
}
