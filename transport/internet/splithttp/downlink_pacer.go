package splithttp

import (
	"io"
	"net/http"
	"time"
)

// writeDownlinkPadding writes one padding frame of n random bytes (n == 0
// for the cheap periodic keepalive ping, n > 0 for an idle-triggered flush)
// -- see runDownlinkPacer for when this is called and why.
func (c *httpServerConn) writeDownlinkPadding(n int) error {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return io.ErrClosedPipe
	}
	if _, err := writeFrameHeader(c.ResponseWriter, n, true); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.ResponseWriter.Write(genPaddingBytes(n)); err != nil {
			return err
		}
	}
	c.ResponseWriter.(http.Flusher).Flush()
	return nil
}

// runDownlinkPacer is the idle-triggered padding algorithm:
//
//   - While real data keeps arriving, it does nothing at all. Every real
//     Write() sends on c.activity, which restarts the wait below from
//     scratch -- so padding is never written while the connection has real
//     data flowing or queued.
//   - The first time the downlink sits idle for flushDelay after a real
//     write, it sends exactly one padding frame sized from flushBytes --
//     large enough to cross a buffering intermediary's threshold -- to force
//     out whatever real data it was holding back. A flushDelay of exactly 0
//     still goes through the same wait below (time.After(0) fires as soon as
//     the runtime gets to it, but a real write racing in at that instant is
//     still picked up by the select, same as any other delay) -- idle is
//     judged by absence of further writes, not by a fixed clock, so it fires
//     right when it's needed and not before. A negative flushDelay leaves
//     this idle period's flush un-armed -- the wait falls back to the
//     keepAlive interval below, same as if flushBytes were nil.
//   - If the downlink stays idle past the flush (or the flush was left
//     un-armed), further ticks fall back to the cheap 0-byte keepalive at
//     the coarser keepAlive interval -- there's nothing left to un-stick, so
//     there's no reason to keep spending padding bytes on it. This only
//     runs at all when keepAlive > 0, i.e. the client actually negotiated
//     framing.
//   - Any subsequent real write clears the "already flushed this idle
//     period" state (via the activity signal), so the next idle period gets
//     its own flush.
//
// flushBytes == nil disables the flush behavior entirely (plain keepalive).
// flushDelay is never nil -- it carries a jittered default so the trigger
// isn't a fixed, fingerprintable timing even when unconfigured.
func (c *httpServerConn) runDownlinkPacer(keepAlive time.Duration, flushBytes, flushDelay *RangeConfig) {
	flushed := true // nothing real written yet -- nothing to protect on the first tick
	for {
		delay := keepAlive
		flushArmed := false
		if !flushed && flushBytes != nil {
			if d := time.Duration(flushDelay.rand()) * time.Millisecond; d >= 0 && (delay <= 0 || d < delay) {
				delay = d
				flushArmed = true
			}
		}
		if delay < 0 {
			return
		}
		select {
		case <-c.Wait():
			return
		case <-c.activity:
			flushed = false
			continue
		case <-time.After(delay):
		}
		if flushArmed {
			if c.writeDownlinkPadding(int(flushBytes.rand())) != nil {
				return
			}
			flushed = true
			continue
		}
		if keepAlive <= 0 || c.writeDownlinkPadding(0) != nil {
			return
		}
	}
}
