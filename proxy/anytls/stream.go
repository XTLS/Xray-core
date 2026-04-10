package anytls

import (
	"sync"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

type stream struct {
	sid  uint32
	link *transport.Link

	done     chan struct{}
	doneOnce sync.Once
	errMu    sync.Mutex
	err      error
	dieHook  func()

	isUDP     bool
	udpTarget *xnet.Destination
}

func newStream(sid uint32, link *transport.Link) *stream {
	return &stream{
		sid:  sid,
		link: link,
		done: make(chan struct{}),
	}
}

func (st *stream) close(err error) {
	if st.done == nil {
		if st.link != nil {
			common.Close(st.link.Reader)
			common.Close(st.link.Writer)
		}
		return
	}
	st.doneOnce.Do(func() {
		st.errMu.Lock()
		st.err = err
		st.errMu.Unlock()
		if st.link != nil {
			common.Close(st.link.Reader)
			common.Close(st.link.Writer)
		}
		close(st.done)
		if st.dieHook != nil {
			st.dieHook()
		}
	})
}

func (st *stream) result() error {
	st.errMu.Lock()
	defer st.errMu.Unlock()
	return st.err
}
