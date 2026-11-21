package splithttp

import (
	"bufio"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// packet-down runs in stream-down: the response body is cut into frames, and
// while the downlink is idle the server sends keep-alive padding frames, so a
// middlebox cannot kill the GET for inactivity while the uplink is the only
// side carrying traffic. See #4846 for the problem and the packet-down design
// in #6755: an omittable session id excerpt, an omittable packet seq, a
// mandatory type (data/padding), a mandatory length, then the payload. The
// seq and the excerpt keep the format ready for future multi-path-down and
// retransmission without changing the wire again.
const (
	pdRequestHeader  = "X-Packet-Down" // client -> server: run packet-down in this stream-down
	pdResponseHeader = "X-Packet-Down" // server -> client: confirmation, the body is framed

	pdTypeData    byte = 0x01
	pdTypePadding byte = 0x02

	pdFlagSessionID byte = 0x01
	pdFlagSeq       byte = 0x02

	pdSessionIDExcerptLen = 8
	pdMaxFramePayload     = 0xFFFF
)

type pdFrame struct {
	sessionIDExcerpt []byte
	seq              uint64
	hasSeq           bool
	typ              byte
	payload          []byte
}

func pdWriteFrame(w io.Writer, f pdFrame) error {
	if len(f.payload) > pdMaxFramePayload {
		return errors.New("packet-down frame payload is too large: ", len(f.payload))
	}

	flags := byte(0)
	if len(f.sessionIDExcerpt) > 0 {
		flags |= pdFlagSessionID
	}
	if f.hasSeq {
		flags |= pdFlagSeq
	}

	header := make([]byte, 4, 4+len(f.sessionIDExcerpt)+8+len(f.payload))
	header[0] = flags
	header[1] = f.typ
	binary.BigEndian.PutUint16(header[2:4], uint16(len(f.payload)))
	if len(f.sessionIDExcerpt) > 0 {
		header = append(header, f.sessionIDExcerpt...)
	}
	if f.hasSeq {
		var seq [8]byte
		binary.BigEndian.PutUint64(seq[:], f.seq)
		header = append(header, seq[:]...)
	}

	_, err := w.Write(append(header, f.payload...))
	return err
}

func pdReadFrame(r *bufio.Reader) (pdFrame, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		if err == io.EOF {
			return pdFrame{}, io.EOF
		}
		return pdFrame{}, errors.New("truncated packet-down frame header").Base(err)
	}

	flags := header[0]
	typ := header[1]
	length := binary.BigEndian.Uint16(header[2:4])

	if typ != pdTypeData && typ != pdTypePadding {
		return pdFrame{}, errors.New("unknown packet-down frame type: ", typ)
	}

	f := pdFrame{
		typ: typ,
	}

	if flags&pdFlagSessionID != 0 {
		excerpt := make([]byte, pdSessionIDExcerptLen)
		if _, err := io.ReadFull(r, excerpt); err != nil {
			return pdFrame{}, errors.New("truncated packet-down session id excerpt").Base(err)
		}
		f.sessionIDExcerpt = excerpt
	}

	if flags&pdFlagSeq != 0 {
		seq := make([]byte, 8)
		if _, err := io.ReadFull(r, seq); err != nil {
			return pdFrame{}, errors.New("truncated packet-down seq").Base(err)
		}
		f.seq = binary.BigEndian.Uint64(seq)
		f.hasSeq = true
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return pdFrame{}, errors.New("truncated packet-down frame payload").Base(err)
	}
	f.payload = payload

	return f, nil
}

func pdSessionIDExcerpt(sessionID string) []byte {
	if len(sessionID) < pdSessionIDExcerptLen {
		return nil
	}
	return []byte(sessionID[:pdSessionIDExcerptLen])
}

// packetDownWriter cuts everything the dispatcher sends into data frames, and
// a goroutine sends a keep-alive padding frame whenever the downlink has been
// idle for a whole period. the padding is base62, in the spirit of the
// tokenish x-padding, so the extra bytes look like ordinary SSE content.
type packetDownWriter struct {
	mu        sync.Mutex
	writer    io.Writer
	sessionID string
	pdConfig  *PacketDownConfig
	seq       uint64
	lastWrite time.Time
	stopped   atomic.Bool
}

func newPacketDownWriter(w io.Writer, sessionId string, pdConfig *PacketDownConfig) *packetDownWriter {
	d := &packetDownWriter{
		writer:    w,
		sessionID: sessionId,
		pdConfig:  pdConfig,
		lastWrite: time.Now(),
	}
	if pdConfig.GetKeepAlive() {
		go d.keepAliveLoop()
	}
	return d
}

func (d *packetDownWriter) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.lastWrite = time.Now()
	written := 0
	excerpt := pdSessionIDExcerpt(d.sessionID)
	seq := d.seq
	hasSeq := len(excerpt) > 0
	for len(b) > 0 {
		payloadLength := len(b)
		if payloadLength > pdMaxFramePayload {
			payloadLength = pdMaxFramePayload
		}
		err := pdWriteFrame(d.writer, pdFrame{
			sessionIDExcerpt: excerpt,
			seq:              seq,
			hasSeq:           hasSeq,
			typ:              pdTypeData,
			payload:          b[:payloadLength],
		})
		if err != nil {
			return written, err
		}
		d.seq++
		seq++
		b = b[payloadLength:]
		written += payloadLength
	}
	return written, nil
}

func (d *packetDownWriter) keepAliveLoop() {
	for {
		period := time.Duration(d.pdConfig.GetNormalizedKeepAlivePeriod().rand()) * time.Second
		time.Sleep(period)
		if d.stopped.Load() {
			return
		}

		d.mu.Lock()
		if time.Since(d.lastWrite) < period {
			// the dispatcher was active within this period, there is
			// nothing to keep alive
			d.mu.Unlock()
			continue
		}
		length := int(d.pdConfig.GetNormalizedKeepAliveLength().rand())
		padding, _ := randStringFromCharset(length, charsetBase62)
		if padding == "" {
			padding = "X"
		}
		excerpt := pdSessionIDExcerpt(d.sessionID)
		seq := d.seq
		hasSeq := len(excerpt) > 0
		d.seq++
		d.lastWrite = time.Now()
		err := pdWriteFrame(d.writer, pdFrame{
			sessionIDExcerpt: excerpt,
			seq:              seq,
			hasSeq:           hasSeq,
			typ:              pdTypePadding,
			payload:          []byte(padding),
		})
		d.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// Stop ends the goroutine; the writer keeps working until the underlying
// stream is closed.
func (d *packetDownWriter) Stop() {
	d.stopped.Store(true)
}

// Close passes through to the underlying stream, holding the lock so that a
// final data write cannot interleave with the connection teardown.
func (d *packetDownWriter) Close() error {
	d.stopped.Store(true)

	closeFunc, ok := d.writer.(io.Closer)
	if !ok {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return closeFunc.Close()
}

// packetDownReader demuxes a framed stream-down body: payload arrives the way
// it did before, padding frames are consumed and dropped.
type packetDownReader struct {
	reader   io.ReadCloser
	buffered *bufio.Reader
	pending  []byte
}

func newPacketDownReader(rc io.ReadCloser) *packetDownReader {
	return &packetDownReader{
		reader:   rc,
		buffered: bufio.NewReaderSize(rc, bufSizeForDown),
	}
}

const bufSizeForDown = 16384

func (d *packetDownReader) Read(b []byte) (int, error) {
	for len(d.pending) == 0 {
		frame, err := pdReadFrame(d.buffered)
		if err != nil {
			return 0, err
		}
		switch frame.typ {
		case pdTypeData:
			d.pending = frame.payload
		case pdTypePadding:
		default:
			return 0, errors.New("unknown packet-down frame type: ", frame.typ)
		}
	}
	n := copy(b, d.pending)
	d.pending = d.pending[n:]
	if len(d.pending) == 0 {
		d.pending = nil
	}
	return n, nil
}

func (d *packetDownReader) Close() error {
	return d.reader.Close()
}
