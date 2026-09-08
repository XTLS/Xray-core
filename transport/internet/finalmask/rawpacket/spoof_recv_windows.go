//go:build windows && (amd64 || 386)

package rawpacket

import (
	"fmt"
	"sync"

	"github.com/xtls/xray-core/transport/internet/finalmask/rawpacket/windivert"
)

type rawRecvSocket struct {
	h          *windivert.Handle
	buf        []byte
	mu         sync.Mutex
	closedFlag bool
	proto      uint8
}

func newRawRecvSocket(proto uint8, bufSize int) (*rawRecvSocket, error) {
	h, err := windivert.Open(windivert.AcceptAll(), windivert.LayerNetwork, windivert.PriorityLowest, windivert.FlagSniff)
	if err != nil {
		return nil, fmt.Errorf("rawpacket: WinDivert open: %w", err)
	}
	return &rawRecvSocket{h: h, buf: make([]byte, windivert.MTUMax), proto: proto}, nil
}

func (r *rawRecvSocket) recv() ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closedFlag {
		return nil, false
	}
	n, _, err := r.h.Recv(r.buf)
	if err != nil {
		return nil, false
	}
	if n == 0 {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	return out, true
}

func (r *rawRecvSocket) closed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closedFlag
}

func (r *rawRecvSocket) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closedFlag {
		r.closedFlag = true
		_ = r.h.Close()
	}
}
