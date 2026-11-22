package fragment

import (
	"context"
	"net"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

// fakeOOBXor turns the boundary byte into the fake urgent marker; the real
// byte follows in the plain stream right after, so only DPI parsers that
// mishandle urgent data ever see the fake value.
const fakeOOBXor = 0x50

// graceDelayMs is the hold time for a dying segment when the configured
// delay is zero: the sleep keeps TTL=1 until the segment has left the
// socket buffer, closing the write-returns-before-the-wire race.
const graceDelayMs = 10

// GraceDelayMs exposes graceDelayMs for config-side diagnostics.
const GraceDelayMs = graceDelayMs

// segment is one piece of a split write: the bytes to send, the delay to
// sleep after sending them, and whether the piece must die on the first hop
// (TTL=1, disorder).
type segment struct {
	data     []byte
	delayMin int64
	delayMax int64
	dieFirst bool
}

type fragmentConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool

	raw    net.Conn
	defTTL int
}

// rawTCPConn unwraps mask wrappers down to the connection used for socket
// level operations. Wrappers that hide the fd (TLS and the like) stop the
// unwinding; the fragment mask sits directly on the dialer output, before
// TLS is applied.
func rawTCPConn(conn net.Conn) net.Conn {
	for {
		inner, ok := conn.(interface{ RawConn() net.Conn })
		if !ok {
			return conn
		}
		next := inner.RawConn()
		if next == nil {
			return conn
		}
		conn = next
	}
}

func NewConnClient(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	conn := &fragmentConn{
		Conn:   raw,
		config: c,
		server: server,
	}

	if !server && c.Mode != Config_NORMAL {
		conn.raw = rawTCPConn(raw)
		// Small writes must go out as separate TCP segments, otherwise the
		// TTL switch between them never reaches the wire.
		if err := enableNoDelay(conn.raw); err != nil {
			return nil, errors.New("fragment: failed to enable TCP_NODELAY").Base(err)
		}
		ttl, err := getTTL(conn.raw)
		if err != nil {
			return nil, errors.New("fragment: failed to read current TTL").Base(err)
		}
		conn.defTTL = ttl
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	return NewConnClient(c, raw, server)
}

func (c *fragmentConn) TcpMaskConn() {}

func (c *fragmentConn) RawConn() net.Conn {
	return c.Conn
}

func (c *fragmentConn) Splice() bool {
	if c.server {
		return false
	}
	if c.config.Mode != Config_NORMAL {
		// Splice would bypass Write() and the disorder/OOB logic entirely.
		return false
	}
	return true
}

// lengthForSegment returns the length range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) lengthForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.LengthsMin) {
		segIdx = len(c.config.LengthsMin) - 1
	}
	return c.config.LengthsMin[segIdx], c.config.LengthsMax[segIdx]
}

// delayForSegment returns the delay range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) delayForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.DelaysMin) {
		segIdx = len(c.config.DelaysMin) - 1
	}
	return c.config.DelaysMin[segIdx], c.config.DelaysMax[segIdx]
}

// mergeTlsHelloSegments returns true only when delays has exactly one zero entry.
func (c *fragmentConn) mergeTlsHelloSegments() bool {
	return len(c.config.DelaysMax) == 1 && c.config.DelaysMax[0] == 0
}

// splitClientHello cuts the TLS record carried in p into re-recorded
// segments. It returns the segments and the length covered by the record;
// anything beyond it belongs to following records and is never split.
func (c *fragmentConn) splitClientHello(p []byte, merge bool) ([]segment, int) {
	recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
	data := p[5:recordLen]
	var segments []segment
	var merged []byte
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	var splitNum int64
	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(crypto.RandBetween(lengthMin, lengthMax))
		if to > len(data) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(data)
		}
		l := to - from
		record := make([]byte, 5+l)
		copy(record[:3], p)
		record[3] = byte(l >> 8)
		record[4] = byte(l)
		copy(record[5:], data[from:to])
		if merge {
			merged = append(merged, record...)
		} else {
			seg := segment{data: record}
			seg.delayMin, seg.delayMax = c.delayForSegment(int(splitNum))
			segments = append(segments, seg)
		}
		from = to
		splitNum++
		if from == len(data) {
			if len(merged) > 0 {
				segments = append(segments, segment{data: merged})
			}
			return segments, recordLen
		}
	}
}

// splitRaw cuts an arbitrary payload into segments without re-recording.
func (c *fragmentConn) splitRaw(p []byte) []segment {
	var segments []segment
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	var splitNum int64
	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(crypto.RandBetween(lengthMin, lengthMax))
		if to > len(p) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(p)
		}
		seg := segment{data: p[from:to]}
		seg.delayMin, seg.delayMax = c.delayForSegment(int(splitNum))
		segments = append(segments, seg)
		from = to
		splitNum++
		if from >= len(p) {
			return segments
		}
	}
}

// markDisorder flags the odd-indexed segments (the 2nd, 4th, ... piece) to
// die on the first hop; the even ones go out normally. Killed pieces reach
// the DPI but not the server, which recovers them via RTO retransmission.
func markDisorder(segments []segment) {
	for i := range segments {
		if i%2 == 1 {
			segments[i].dieFirst = true
		}
	}
}

// writeSegment sends one segment. Dying segments flip TTL to 1 for exactly
// one send; the restore happens only after a hold time, because the write
// returns when the segment reached the kernel send buffer, not the wire.
// In DISOOB the first segment starts with an urgent send covering
// data[:pos] plus the fake byte at pos; the real byte at pos follows in the
// plain stream. Receivers with SO_OOBINLINE off skip the urgent byte and
// see the exact original stream, while DPI parsers that mishandle urgent
// data choke on the fake value.
func (c *fragmentConn) writeSegment(i int, seg segment) error {
	data := seg.data
	if c.config.Mode == Config_DISOOB && i == 0 && len(data) > 1 {
		pos := len(data) - 1
		fake := make([]byte, pos+1)
		copy(fake, data[:pos+1])
		fake[pos] ^= fakeOOBXor
		if _, err := sendOOB(c.Conn, fake); err != nil {
			return errors.New("fragment: failed to send urgent byte").Base(err)
		}
		data = data[pos:]
	}
	if seg.dieFirst {
		if err := setTTL(c.raw, 1); err != nil {
			return errors.New("fragment: failed to set TTL").Base(err)
		}
		_, err := c.Conn.Write(data)
		// Hold TTL=1 while sleeping, so the doomed segment is guaranteed
		// to leave the socket buffer before the default TTL is restored:
		// the write returns when the data reached the kernel, not the
		// wire. The configured delay serves as the hold time and falls
		// back to a short grace period when unset.
		min, max := seg.delayMin, seg.delayMax
		if max <= 0 {
			min, max = graceDelayMs, graceDelayMs
		}
		time.Sleep(time.Duration(crypto.RandBetween(min, max)) * time.Millisecond)
		if restoreErr := setTTL(c.raw, c.defTTL); restoreErr != nil {
			if err == nil {
				return errors.New("fragment: failed to restore TTL").Base(restoreErr)
			}
			errors.LogErrorInner(context.Background(), restoreErr, "fragment: failed to restore TTL")
		}
		return err
	}
	_, err := c.Conn.Write(data)
	if seg.delayMax > 0 {
		time.Sleep(time.Duration(crypto.RandBetween(seg.delayMin, seg.delayMax)) * time.Millisecond)
	}
	return err
}

// writeSegments sends all segments in order; inter-segment sleeps and the
// TTL hold happen inside writeSegment.
func (c *fragmentConn) writeSegments(segments []segment) (int, error) {
	sent := 0
	for i := range segments {
		if err := c.writeSegment(i, segments[i]); err != nil {
			return sent, err
		}
		sent += len(segments[i].data)
	}
	return sent, nil
}

func (c *fragmentConn) Write(p []byte) (n int, err error) {
	c.count++

	// The split applies on both sides, as upstream does; only the client
	// alternates TTL and sends urgent bytes.
	disorder := c.config.Mode != Config_NORMAL

	if c.config.PacketsFrom == 0 && c.config.PacketsTo == 1 {
		if c.count != 1 || len(p) <= 5 || p[0] != 22 {
			return c.Conn.Write(p)
		}
		recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
		if len(p) < recordLen {
			return c.Conn.Write(p)
		}
		// The merged single-write form only applies to normal mode;
		// disorder needs separate writes to alternate the TTL.
		segments, recordLen := c.splitClientHello(p, !disorder && c.mergeTlsHelloSegments())
		if disorder && !c.server {
			markDisorder(segments)
		}
		if _, err := c.writeSegments(segments); err != nil {
			return 0, err
		}
		if len(p) > recordLen {
			n, err := c.Conn.Write(p[recordLen:])
			if err != nil {
				return recordLen + n, err
			}
		}
		return len(p), nil
	}

	if c.config.PacketsFrom != 0 && (c.count < uint64(c.config.PacketsFrom) || c.count > uint64(c.config.PacketsTo)) {
		return c.Conn.Write(p)
	}
	segments := c.splitRaw(p)
	if disorder && !c.server {
		markDisorder(segments)
	}
	return c.writeSegments(segments)
}
