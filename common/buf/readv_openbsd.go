//go:build openbsd
// +build openbsd

package buf

import "syscall"

// openbsdRead is a function variable to allow deterministic syscall-path tests
// (for example, injecting EINTR/EAGAIN sequences) without changing production logic.
var openbsdRead = syscall.Read

// openbsdSeqReader implements multiReader using sequential read(2) calls.
//
// Background: readv(2) via syscall.Syscall on OpenBSD 7.5+ non-blocking
// sockets returns EAGAIN even when data is present (large arrays).
// unix.Readv is also unavailable for OpenBSD in x/sys v0.41.0.
//
// This implementation preserves ReadVReader's adaptive allocation strategy
// (1->8 buffers x 8KB) by satisfying the multiReader interface.
// syscall.Read requires no unsafe.Pointer and is GC-safe on OpenBSD.
type openbsdSeqReader struct {
	bs []*Buffer
}

func (r *openbsdSeqReader) Init(bs []*Buffer) {
	// Keep the caller-provided slice as-is; ownership stays with ReadVReader.
	r.bs = bs
}

func (r *openbsdSeqReader) Read(fd uintptr) int32 {
	var total int32
	for _, b := range r.bs {
		// Read directly into each pooled buffer in sequence.
		// This emulates readv's "fill iovecs in order" behavior without SYS_READV.
		var n int
		var err error
		for {
			n, err = openbsdRead(int(fd), b.v[:])
			if err != syscall.EINTR {
				break
			}
			// Interrupted syscall is transient; retry the same buffer.
		}
		if err != nil {
			if total > 0 {
				// Preserve already-received bytes and defer surfacing the hard error.
				// The next read call will observe socket state again.
				return total
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// rawConn.Read interprets -1 as "not ready yet" and re-arms polling.
				return -1
			}
			// Fatal error (ECONNRESET, EBADF, etc.) — also return -1.
			// This matches posixReader/windowsReader: all errors signal "not done"
			// so RawRead calls waitRead, which detects the error condition via
			// kqueue's pollEventErr bit and returns it to readMulti as a real
			// error instead of silently converting it to io.EOF.
			return -1
		}
		if n == 0 {
			if total > 0 {
				// Deliver partial data first; EOF will be observed on the next call.
				return total
			}
			// Clean EOF when no bytes were read in this round.
			return 0
		}
		total += int32(n)

		// Keep this short-read break in place.
		// readMulti() maps total bytes back to buffers by assuming every
		// fully consumed buffer has Size bytes and only the tail buffer is short.
		// Breaking here preserves that invariant for this sequential reader.
		if n < int(Size) {
			break
		}
	}
	return total
}

func (r *openbsdSeqReader) Clear() {
	// Match other reader implementations: drop length, keep backing array for reuse.
	r.bs = r.bs[:0]
}

func newMultiReader() multiReader {
	// Factory selected by build tags; OpenBSD always gets the sequential reader.
	return &openbsdSeqReader{}
}
