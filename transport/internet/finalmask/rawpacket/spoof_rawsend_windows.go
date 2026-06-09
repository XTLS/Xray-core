//go:build windows && (amd64 || 386)

package rawpacket

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/xtls/xray-core/transport/internet/finalmask/rawpacket/windivert"
)

type rawSendFD struct {
	h      *windivert.Handle
	mu     sync.Mutex
	closed bool
}

func openRawSender(dstIP netip.Addr) (*rawSendFD, error) {
	filter := fmt.Sprintf("outbound and ip.DstAddr == %s", dstIP.String())
	h, err := windivert.Open(filter, windivert.LayerNetwork, windivert.PriorityLowest, uint64(windivert.FlagSendOnly))
	if err != nil {
		return nil, fmt.Errorf("rawpacket: WinDivert open: %w", err)
	}
	return &rawSendFD{h: h}, nil
}

func (r *rawSendFD) send(packet []byte) error {
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
