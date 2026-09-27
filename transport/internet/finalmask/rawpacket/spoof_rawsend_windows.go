//go:build windows && (amd64 || 386)

package rawpacket

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/xtls/xray-core/transport/internet/finalmask/rawpacket/windivert"
)

type rawSendFD struct {
	h *windivert.Handle
	// sendFn, when set, replaces the real send path (used by tests).
	sendFn func(pkt []byte, dstIP netip.Addr) error
	mu     sync.Mutex
	closed bool
}

func openRawSender(dstIP netip.Addr) (*rawSendFD, error) {
	return openRawSenderAny()
}

// openRawSenderAny opens a WinDivert send handle. WinDivert injects
// packets from the header contents, so no destination binding is needed.
func openRawSenderAny() (*rawSendFD, error) {
	h, err := windivert.Open(windivert.AcceptAll(), windivert.LayerNetwork, windivert.PriorityLowest, windivert.FlagSendOnly)
	if err != nil {
		return nil, fmt.Errorf("rawpacket: WinDivert open: %w", err)
	}
	return &rawSendFD{h: h}, nil
}

func (r *rawSendFD) send(packet []byte) error {
	return r.sendTo(packet, netip.Addr{})
}

// sendTo sends packet via WinDivert; the destination is read from the
// packet itself.
func (r *rawSendFD) sendTo(packet []byte, dstIP netip.Addr) error {
	if r.sendFn != nil {
		return r.sendFn(packet, dstIP)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("rawpacket: WinDivert sender closed")
	}
	var addr windivert.Address
	addr.SetIPChecksum(true)
	addr.SetTCPChecksum(true)
	_, err := r.h.Send(packet, &addr)
	if err != nil {
		return fmt.Errorf("rawpacket: WinDivert send: %w", err)
	}
	return nil
}

func (r *rawSendFD) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.h.Close()
}
