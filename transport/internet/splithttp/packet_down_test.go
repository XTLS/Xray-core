package splithttp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func pdTestConfig(period int32) *PacketDownConfig {
	return &PacketDownConfig{
		KeepAlive:       true,
		KeepAlivePeriod: &RangeConfig{From: period, To: period},
		KeepAliveLength: &RangeConfig{From: 32, To: 32},
	}
}

// newSlowReader feeds a reader out in fixed-size chunks, like a socket does,
// to make sure the frame reader does not assume whole frames per Read.
type pdChunkReader struct {
	r     io.Reader
	chunk int
}

func (r *pdChunkReader) Read(b []byte) (int, error) {
	if len(b) > r.chunk {
		b = b[:r.chunk]
	}
	return r.r.Read(b)
}

func newPDClosableReader(r io.Reader) io.ReadCloser {
	return io.NopCloser(r)
}

func newFrameBufReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

// a bytes.Buffer behind a mutex: the keep-alive goroutine may still be
// writing while the test reads
type pdLockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (t *pdLockedBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Write(p)
}

func (t *pdLockedBuffer) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Len()
}

func (t *pdLockedBuffer) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Bytes()
}

func Test_PacketDownFrameRoundTrip(t *testing.T) {
	payload := make([]byte, 3000)
	rand.Read(payload)

	sessionID := "session_test_SOMETHING_HIGH"
	var buf bytes.Buffer

	err := pdWriteFrame(&buf, pdFrame{
		sessionIDExcerpt: pdSessionIDExcerpt(sessionID),
		seq:              42,
		hasSeq:           true,
		typ:              pdTypeData,
		payload:          payload,
	})
	assert.NoError(t, err)

	frame, err := pdReadFrame(newFrameBufReader(buf.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, pdTypeData, frame.typ)
	assert.Equal(t, sessionID[:pdSessionIDExcerptLen], string(frame.sessionIDExcerpt))
	assert.Equal(t, uint64(42), frame.seq)
	assert.True(t, frame.hasSeq)
	assert.Equal(t, payload, frame.payload)
}

func Test_PacketDownKeepAliveRoundTrip(t *testing.T) {
	padding := bytes.Repeat([]byte{'A'}, 32)

	var buf bytes.Buffer
	err := pdWriteFrame(&buf, pdFrame{
		typ:     pdTypePadding,
		payload: padding,
	})
	assert.NoError(t, err)

	frame, err := pdReadFrame(newFrameBufReader(buf.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, pdTypePadding, frame.typ)
	assert.Empty(t, frame.sessionIDExcerpt)
	assert.False(t, frame.hasSeq)
	assert.Equal(t, padding, frame.payload)
}

func Test_PacketDownKeepAliveHasNoExcerptWithoutSession(t *testing.T) {
	// stream-one has an empty session id; the excerpt stays out of the frame
	var buf bytes.Buffer
	err := pdWriteFrame(&buf, pdFrame{
		sessionIDExcerpt: pdSessionIDExcerpt(""),
		seq:              0,
		hasSeq:           true,
		typ:              pdTypeData,
		payload:          []byte("x"),
	})
	assert.NoError(t, err)

	frame, err := pdReadFrame(newFrameBufReader(buf.Bytes()))
	assert.NoError(t, err)
	assert.Empty(t, frame.sessionIDExcerpt)
	assert.True(t, frame.hasSeq)
	assert.Equal(t, []byte("x"), frame.payload)
}

func Test_PacketDownWriterReaderEndToEnd(t *testing.T) {
	sessionID := "abcdef0123456789"
	fiBuffer := &pdLockedBuffer{}

	d := newPacketDownWriter(fiBuffer, sessionID, pdTestConfig(1000))
	d.Stop()

	payload := make([]byte, 70000)
	rand.Read(payload)
	_, err := d.Write(payload)
	assert.NoError(t, err)

	// feed the framed bytes back through the reader in 1 KiB steps
	pr := newPacketDownReader(newPDClosableReader(&pdChunkReader{r: bytes.NewReader(fiBuffer.Bytes()), chunk: 1024}))
	got, err := io.ReadAll(pr)
	assert.NoError(t, err)
	assert.Equal(t, payload, got)
}

func Test_PacketDownWriterSplitsLargePayload(t *testing.T) {
	fiBuffer := &pdLockedBuffer{}

	d := newPacketDownWriter(fiBuffer, "abcdefgh", pdTestConfig(1000))
	d.Stop()

	payload := make([]byte, pdMaxFramePayload+1234)
	rand.Read(payload)
	_, err := d.Write(payload)
	assert.NoError(t, err)

	// 65536 + 1234 payload cut into two frames; walk the wire and check
	// the frames line up
	r := newFrameBufReader(fiBuffer.Bytes())
	var payloads []byte
	seq := uint64(0)
	for {
		frame, err := pdReadFrame(r)
		if err != nil {
			break
		}
		assert.Equal(t, pdTypeData, frame.typ)
		assert.Equal(t, seq, frame.seq)
		assert.Equal(t, "abcdefgh", string(frame.sessionIDExcerpt))
		payloads = append(payloads, frame.payload...)
		seq++
	}
	assert.Equal(t, uint64(2), seq)
	assert.Equal(t, payload, payloads)
}

func Test_PacketsDownReaderSkipsPadding(t *testing.T) {
	fiBuffer := &bytes.Buffer{}

	assert.NoError(t, pdWriteFrame(fiBuffer, pdFrame{typ: pdTypePadding, payload: []byte("padding-padding-padding")}))
	assert.NoError(t, pdWriteFrame(fiBuffer, pdFrame{typ: pdTypeData, hasSeq: true, seq: 0, payload: []byte("hello")}))
	assert.NoError(t, pdWriteFrame(fiBuffer, pdFrame{typ: pdTypePadding, payload: []byte("more-padding-more-padding")}))
	assert.NoError(t, pdWriteFrame(fiBuffer, pdFrame{typ: pdTypeData, hasSeq: true, seq: 1, payload: []byte("world")}))

	pr := newPacketDownReader(newPDClosableReader(fiBuffer))
	out, err := io.ReadAll(pr)
	assert.NoError(t, err)
	assert.Equal(t, "helloworld", string(out))
}

func Test_PacketDownReaderMalformedFrame(t *testing.T) {
	pr := newPacketDownReader(newPDClosableReader(bytes.NewReader([]byte{0x00, 0x09, 0x00})))
	_, err := pr.Read(make([]byte, 16))
	assert.Error(t, err)
}

func Test_PacketDownEOF(t *testing.T) {
	pr := newPacketDownReader(newPDClosableReader(bytes.NewReader(nil)))
	_, err := pr.Read(make([]byte, 16))
	assert.Equal(t, io.EOF, err)
}

func Test_PacketDownKeepAliveWritesWhenIdle(t *testing.T) {
	fiBuffer := &pdLockedBuffer{}

	d := newPacketDownWriter(fiBuffer, "wantpaddingxx", pdTestConfig(1))
	defer d.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for fiBuffer.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no keep-alive frame was written within 5 s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	frame, err := pdReadFrame(newFrameBufReader(fiBuffer.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, pdTypePadding, frame.typ)
	assert.Equal(t, "wantpadd", string(frame.sessionIDExcerpt))
	assert.True(t, frame.hasSeq)
	assert.Equal(t, 32, len(frame.payload))
}

func Test_PacketDownKeepAliveSkippedWhenActive(t *testing.T) {
	fiBuffer := &pdLockedBuffer{}

	d := newPacketDownWriter(fiBuffer, "active", pdTestConfig(1))
	defer d.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := d.Write([]byte("whee"))
		assert.NoError(t, err)
		time.Sleep(200 * time.Millisecond)
	}

	// walk every frame on the wire: all of them must be data, none padding
	r := newFrameBufReader(fiBuffer.Bytes())
	for {
		frame, err := pdReadFrame(r)
		if err != nil {
			break
		}
		assert.Equal(t, pdTypeData, frame.typ, "writer was active, so no padding frame should have been written")
		assert.Equal(t, []byte("whee"), frame.payload)
	}
}

func Test_ConfigPDKeepAliveNormalization(t *testing.T) {
	pd := &PacketDownConfig{}
	assert.Equal(t, int32(10), pd.GetNormalizedKeepAlivePeriod().From)
	assert.Equal(t, int32(30), pd.GetNormalizedKeepAlivePeriod().To)
	assert.Equal(t, int32(24), pd.GetNormalizedKeepAliveLength().From)
	assert.Equal(t, int32(64), pd.GetNormalizedKeepAliveLength().To)

	pd.KeepAliveLength = &RangeConfig{From: 60000, To: 90000}
	assert.Equal(t, int32(60000), pd.GetNormalizedKeepAliveLength().From)
	assert.Equal(t, int32(pdMaxFramePayload), pd.GetNormalizedKeepAliveLength().To)
}
