// Package vp8channel provides byte transport over VP8 video frames using KCP.
/*
ЯНДЕКС РАБ ИЛИ КТО ТЫ НАУЙ СУКА КАРОЧЕ ХУЙЛО КЕБАНОГЕ ИЗ ЯНДЕКС ЧИТАЮЩИЙ ЭТО
МЫ ОСЕМЕНИМ ВТОЮ МАМАШКУ МЕРТВУЮ
*/
package vp8channel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	kcp "github.com/xtaci/kcp-go/v5"
)

// Both peers establish a KCP session with the same convid. KCP does not
// require a handshake - packets are matched by conv field, so a static
// constant gives us a symmetrical P2P setup.
const kcpConvID = 0xC0FFEE01

// KCP tuning targets a lossy, bursty carrier (VP8 over an SFU). The defaults
// are TCP-like and recover slowly after burst losses.
const (
	// kcp-go hardcodes mtuLimit=1500, so SetMtu() above this is silently
	// clamped. Stay below that with headroom for KCP overhead (24 bytes).
	kcpMTU = 1400

	// Send/receive window in segments. Bulk data runs on its own KCP session,
	// isolated from the control plane (ping/pong has a separate startKCP and is
	// drained with priority by writerLoop), so a large data window no longer
	// starves control liveness the way it did before that split (issue #95).
	// One VP8 frame can carry many KCP segments and ACKs only trickle back at
	// frame cadence, so a generous window is what keeps the policed path full
	// and lets throughput reach the SFU's real ceiling (~10 Mbit on Telemost)
	// instead of being clamped to a fraction of it.
	kcpSndWnd = 4096
	kcpRcvWnd = 4096

	// Length prefix for our message framing on top of KCP stream mode.
	// We use stream mode because UDPSession.Write fragments messages > MSS
	// outside of kcp.Send, which destroys the frg field that message mode
	// relies on for boundary preservation. Adding our own length-prefix
	// framing sidesteps that bug entirely.
	kcpLenPrefix = 4

	// Hard cap on a single message. Anything larger would require an
	// unbounded reassembly buffer on the receiver and is almost certainly
	// a protocol error upstream.
	kcpMaxMessage = 8 * 1024 * 1024
)

// ErrKCPMessageTooLarge is returned by send when the message exceeds
// kcpMaxMessage.
var ErrKCPMessageTooLarge = errors.New("vp8channel: kcp message exceeds maximum size")

// kcpRuntime owns the KCP session and the goroutine that pumps reassembled
// messages from KCP up to cfg.OnData.
type kcpRuntime struct {
	conn      *kcpConn
	sess      *kcp.UDPSession
	readDone  chan struct{}
	writeMu   sync.Mutex // serializes length-prefix + payload writes
	closeOnce sync.Once
}

func startKCP(out chan<- []byte, onData func([]byte), epochHdr [epochHdrLen]byte) (*kcpRuntime, error) {
	c := newKCPConn(out, inboundQueueSize, epochHdr)

	sess, err := kcp.NewConn3(kcpConvID, fakeUDPAddr(), nil, 0, 0, c)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("kcp new conn: %w", err)
	}

	// nodelay=1, interval=5ms, fast resend=2, congestion control OFF (nc=1).
	// The frame ticker already paces emission at the VP8 frame cadence, so the
	// 5ms KCP tick just keeps scheduling latency low; a slower tick only adds
	// dead time before retransmits and ACKs. nc=1 disables KCP's loss-based
	// congestion control because the carrier is a hard policer, not a fair
	// queue: with nc=0 the unavoidable ~4% drops collapsed cwnd and starved
	// the wire. With nc=1 KCP keeps the window full and retransmits the few
	// losses, letting throughput reach the SFU's real ceiling.
	sess.SetNoDelay(1, 5, 2, 1)
	sess.SetWindowSize(kcpSndWnd, kcpRcvWnd)
	sess.SetMtu(kcpMTU)
	// Upstream marked SetStreamMode deprecated without providing a replacement;
	// stream framing is still required for our wire format.
	sess.SetStreamMode(true) //nolint:staticcheck // SA1019: no replacement upstream.
	sess.SetACKNoDelay(true)
	sess.SetWriteDelay(false)

	rt := &kcpRuntime{
		conn:     c,
		sess:     sess,
		readDone: make(chan struct{}),
	}

	go rt.readLoop(onData)

	return rt, nil
}

func (r *kcpRuntime) readLoop(onData func([]byte)) {
	defer close(r.readDone)

	var hdr [kcpLenPrefix]byte
	for {
		if _, err := io.ReadFull(r.sess, hdr[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(hdr[:])
		if size == 0 {
			continue
		}
		if size > kcpMaxMessage {
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r.sess, payload); err != nil {
			return
		}
		if onData != nil {
			onData(payload)
		}
	}
}

// deliver hands a wire payload (already reassembled out of VP8 RTP) to KCP.
func (r *kcpRuntime) deliver(payload []byte) {
	r.conn.deliver(payload)
}

// setHeader re-points the outgoing frame header so subsequent KCP packets are
// addressed to a specific destination epoch (see kcpConn.setHeader).
func (r *kcpRuntime) setHeader(hdr [epochHdrLen]byte) {
	r.conn.setHeader(hdr)
}

// send queues an application message for reliable delivery. The length
// prefix + payload pair is written under a mutex so that interleaved
// concurrent senders cannot tear the framing.
func (r *kcpRuntime) send(msg []byte) error {
	if len(msg) > kcpMaxMessage {
		return ErrKCPMessageTooLarge
	}
	var hdr [kcpLenPrefix]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg))) //nolint:gosec,lll // G115: bounded conversion verified by surrounding logic

	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if _, err := r.sess.Write(hdr[:]); err != nil {
		return fmt.Errorf("kcp write header: %w", err)
	}
	if _, err := r.sess.Write(msg); err != nil {
		return fmt.Errorf("kcp write payload: %w", err)
	}
	return nil
}

func (r *kcpRuntime) close() {
	r.closeOnce.Do(func() {
		_ = r.sess.Close()
		_ = r.conn.Close()
	})
}
