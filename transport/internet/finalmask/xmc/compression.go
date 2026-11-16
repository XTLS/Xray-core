// Minecraft compression framing, negotiated by the login Set Compression packet.
package xmc

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

const (
	// Packet Length is a VarInt, so one frame cannot exceed 2^21-1 bytes.
	maxCompressedFrameLength = (1 << 21) - 1
	// Vanilla caps serverbound uncompressed packet bodies at 2^23 bytes.
	maxUncompressedFrameBody = 1 << 23
)

// compressionReader converts the post-Set Compression framing
// (Packet Length, Data Length, optional zlib body) back into the plain
// (VarInt body length, body) frame that readPacket expects.
//
// A zero Data Length means the body was sent uncompressed, which vanilla
// servers accept even when the body exceeds the negotiated threshold.
type compressionReader struct {
	r     io.Reader
	frame bytes.Buffer
}

func newCompressionReader(r io.Reader) io.Reader {
	return &compressionReader{r: r}
}

func (c *compressionReader) Read(p []byte) (int, error) {
	if c.frame.Len() == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
	return c.frame.Read(p)
}

func (c *compressionReader) readFrame() error {
	packetLength, _, err := readVarintWithLength(c.r)
	if err != nil {
		return fmt.Errorf("read compressed packet length: %w", err)
	}
	if packetLength < 1 || int(packetLength) > maxCompressedFrameLength {
		return fmt.Errorf("read compressed packet: bad length: %d", packetLength)
	}

	dataLength, dataLengthSize, err := readVarintWithLength(c.r)
	if err != nil {
		return fmt.Errorf("read compressed data length: %w", err)
	}
	if dataLength < 0 || int(dataLength) > maxUncompressedFrameBody {
		return fmt.Errorf("read compressed packet: bad uncompressed length: %d", dataLength)
	}

	payloadLength := int(packetLength) - dataLengthSize
	if payloadLength < 0 {
		return fmt.Errorf("read compressed packet: bad length: %d", packetLength)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return fmt.Errorf("read compressed packet data: %w", err)
	}

	body := payload
	if dataLength > 0 {
		zr, err := zlib.NewReader(bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("open compressed packet: %w", err)
		}
		body = make([]byte, int(dataLength))
		_, readErr := io.ReadFull(zr, body)
		closeErr := zr.Close()
		if readErr != nil {
			return fmt.Errorf("decompress packet: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close decompressor: %w", closeErr)
		}
	}
	if len(body) < 1 {
		return fmt.Errorf("read compressed packet: empty body")
	}

	var frame bytes.Buffer
	frame.Grow(varintSize(Varint(len(body))) + len(body))
	bodyLength := Varint(len(body))
	if err := bodyLength.writeTo(&frame); err != nil {
		return err
	}
	frame.Write(body)
	c.frame = frame
	return nil
}

// compressionWriter converts a plain frame (VarInt body length, body) into the
// post-Set Compression framing. Frames are buffered until complete, because a
// caller may split one frame across several Write calls.
type compressionWriter struct {
	w         io.Writer
	threshold int32
	pending   []byte
}

func newCompressionWriter(w io.Writer, threshold int32) io.Writer {
	return &compressionWriter{w: w, threshold: threshold}
}

func (c *compressionWriter) Write(p []byte) (int, error) {
	c.pending = append(c.pending, p...)
	for {
		body, ok, err := c.nextFrame()
		if err != nil {
			return 0, err
		}
		if !ok {
			return len(p), nil
		}
		if err := c.writeFrame(body); err != nil {
			return 0, err
		}
	}
}

// nextFrame returns one complete frame body from the pending bytes. It only
// waits for more bytes while the length prefix or the body is still
// incomplete; a complete but invalid prefix is an error.
func (c *compressionWriter) nextFrame() ([]byte, bool, error) {
	limit := len(c.pending)
	if limit > 5 {
		limit = 5
	}
	bodyLength, prefixLength, err := readVarintWithLength(bytes.NewReader(c.pending[:limit]))
	if err != nil {
		if len(c.pending) < 5 {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read frame length: %w", err)
	}
	if bodyLength < 1 {
		return nil, false, fmt.Errorf("read frame: bad length: %d", bodyLength)
	}
	end := prefixLength + int(bodyLength)
	if end > len(c.pending) {
		return nil, false, nil
	}

	// The body stays valid after the reslice: appends only write past the
	// remaining pending length and writeFrame consumes it immediately.
	body := c.pending[prefixLength:end]
	c.pending = c.pending[end:]
	return body, true, nil
}

func (c *compressionWriter) writeFrame(body []byte) error {
	if len(body) >= int(c.threshold) {
		var compressed bytes.Buffer
		zw := zlib.NewWriter(&compressed)
		if _, err := zw.Write(body); err != nil {
			_ = zw.Close()
			return fmt.Errorf("compress packet: %w", err)
		}
		if err := zw.Close(); err != nil {
			return fmt.Errorf("close compressor: %w", err)
		}

		var frame bytes.Buffer
		packetLength := varintSize(Varint(len(body))) + compressed.Len()
		frame.Grow(varintSize(Varint(packetLength)) + packetLength)
		packetLengthVarint := Varint(packetLength)
		if err := packetLengthVarint.writeTo(&frame); err != nil {
			return err
		}
		bodyLength := Varint(len(body))
		if err := bodyLength.writeTo(&frame); err != nil {
			return err
		}
		frame.Write(compressed.Bytes())
		return writeFull(c.w, frame.Bytes())
	}

	var frame bytes.Buffer
	frame.Grow(varintSize(Varint(1+len(body))) + 1 + len(body))
	frameLength := Varint(1 + len(body))
	if err := frameLength.writeTo(&frame); err != nil {
		return err
	}
	frame.WriteByte(0)
	frame.Write(body)
	return writeFull(c.w, frame.Bytes())
}
