// Minecraft compression framing, negotiated by the login Set Compression packet.
// The reader decodes whatever the peer sends, including deflated bodies; the
// writer always sends the uncompressed variant.
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
//
// It never compresses, whatever the negotiated threshold is. What XMC writes is
// padding and proxied bytes: the padding exists for its size on the wire, so
// deflating it would shrink a padded turn from tens of kilobytes to a hundred
// bytes and erase the shape it is there for, and proxied bytes are already
// encrypted or compressed by whoever produced them. Vanilla accepts an
// uncompressed body of any size when Data Length is zero, so the framing alone
// is enough to stay inside the protocol.
type compressionWriter struct {
	w       io.Writer
	pending []byte
}

func newCompressionWriter(w io.Writer) io.Writer {
	return &compressionWriter{w: w}
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
	// Packet Length covers the Data Length varint and the body; a zero Data
	// Length is the uncompressed variant.
	packetLength := 1 + len(body)
	var frame bytes.Buffer
	frame.Grow(varintSize(Varint(packetLength)) + packetLength)
	packetLengthVarint := Varint(packetLength)
	if err := packetLengthVarint.writeTo(&frame); err != nil {
		return err
	}
	frame.WriteByte(0)
	frame.Write(body)
	return writeFull(c.w, frame.Bytes())
}
