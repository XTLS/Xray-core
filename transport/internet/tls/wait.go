package tls

import (
	"bytes"
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
)

// rawInputs has what the rawInput of the connections that wait for data would hold, as *[]byte.
var rawInputs sync.Pool

var logUnknownFields sync.Once

// unknownFields tells, once, that a connection is not laid out as it was and keeps what it could release.
func unknownFields(conn any) {
	logUnknownFields.Do(func() {
		errors.LogWarning(context.Background(), "unexpected fields in ", reflect.TypeOf(conn), ", such connections keep more memory than they need")
	})
}

// ReadWaiter waits for a connection to have something to read, so that its reader holds nothing meanwhile.
type ReadWaiter struct {
	rawConn syscall.RawConn
	readyFn func(fd uintptr) bool
	waited  bool

	// of a TLS connection
	complete *atomic.Bool
	input    *bytes.Reader
	rawInput *bytes.Buffer
	hand     *bytes.Buffer
	spare    *[]byte
}

// Wait is for the only reader of conn, before a read and not after a read has failed. It waits if conn is
// a *net.TCPConn or a *tls.Conn, *utls.Conn or *reality.Conn over one.
func (w *ReadWaiter) Wait(conn net.Conn) {
	// one of ours, which looks into the connection it wraps
	if c, ok := conn.(interface{ WaitRead() }); ok {
		c.WaitRead()
		return
	}
	if w.readyFn == nil {
		w.readyFn = w.ready
		if c, ok := conn.(interface{ NetConn() net.Conn }); ok {
			w.complete = utils.TryAccessField[atomic.Bool](conn, "isHandshakeComplete")
			w.input = utils.TryAccessField[bytes.Reader](conn, "input")
			w.rawInput = utils.TryAccessField[bytes.Buffer](conn, "rawInput")
			w.hand = utils.TryAccessField[bytes.Buffer](conn, "hand")
			if w.complete == nil || w.input == nil || w.rawInput == nil || w.hand == nil {
				unknownFields(conn)
				return
			}
			conn = c.NetConn()
		}
		// anything else may have bytes buffered in front of the socket
		if c, ok := conn.(*net.TCPConn); ok {
			w.rawConn, _ = c.SyscallConn()
		}
	}
	// only Read touches them once the handshake is complete
	if w.rawConn == nil || w.complete != nil && (!w.complete.Load() || w.input.Len() > 0 || w.rawInput.Len() > 0) {
		return
	}
	w.waited = false
	w.rawConn.Read(w.readyFn) // whatever ends the wait, Read reports it
	if w.waited && w.complete != nil {
		if spare, _ := rawInputs.Get().(*[]byte); spare != nil {
			*w.rawInput = *bytes.NewBuffer(*spare)
			*spare = nil // rawInput may grow out of it or be dropped, as XTLS Vision does
			w.spare = spare
		}
	}
}

func (w *ReadWaiter) ready(fd uintptr) bool {
	if w.waited || readable(fd) {
		return true
	}
	w.waited = true
	if w.complete != nil {
		*w.input = bytes.Reader{} // it refers to the bytes of rawInput
		w.rawInput.Reset()
		if b := w.rawInput.AvailableBuffer(); cap(b) > 0 {
			if w.spare == nil {
				w.spare = new([]byte)
			}
			*w.spare = b
			rawInputs.Put(w.spare)
			w.spare = nil
		}
		*w.rawInput = bytes.Buffer{}
		if w.hand.Len() == 0 {
			*w.hand = bytes.Buffer{}
		}
	}
	return false
}
