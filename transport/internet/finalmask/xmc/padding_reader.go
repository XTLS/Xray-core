package xmc

import (
	"bytes"
	"io"
)

type paddingReadResult struct {
	frame []byte
	err   error
}

type paddingReader struct {
	reader io.Reader
	first  <-chan paddingReadResult
}

// newPaddingReader drains startup padding while the local padding schedule is
// writing. Buffer only the first non-padding packet, then let the caller resume
// reading the underlying stream. This keeps memory bounded without requiring
// matching padding lengths or an extra end-of-padding packet on the wire.
func newPaddingReader(reader io.Reader, isClient bool) io.Reader {
	first := make(chan paddingReadResult, 1)
	go func() {
		frame, err := readPastPadding(reader, paddingFramePacketID(!isClient))
		first <- paddingReadResult{frame: frame, err: err}
	}()
	return &paddingReader{reader: reader, first: first}
}

func readPastPadding(reader io.Reader, packetID int) ([]byte, error) {
	for {
		packet, err := readPacket(reader)
		if err != nil {
			return nil, err
		}
		if packet.packetID == packetID {
			var channel String
			if err := channel.readFrom(bytes.NewReader(packet.data)); err == nil && channel == paddingFrameChannel {
				continue
			}
		}
		payload := RestBytes(packet.data)
		return encodePacket(packet.packetID, &payload)
	}
}

func (r *paddingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.first != nil {
		result := <-r.first
		r.first = nil
		if result.err != nil {
			return 0, result.err
		}
		r.reader = io.MultiReader(bytes.NewReader(result.frame), r.reader)
	}
	return r.reader.Read(p)
}
