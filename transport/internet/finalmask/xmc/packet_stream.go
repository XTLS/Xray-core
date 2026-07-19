package xmc

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	configurationClientboundCustomPayload = 0x01
	configurationServerboundCustomPayload = 0x02
	configurationKeepAlive                = 0x04

	packetChannel   = "xmc:data"
	maxPacketData   = 24 * 1024
	keepAlivePeriod = 15 * time.Second
)

// packetStream carries the raw proxy byte stream in Minecraft configuration
// custom payload packets. The configuration state provides bidirectional
// payload packets and keep-alives without requiring version-specific world data.
type packetStream struct {
	reader   io.Reader
	writer   io.Writer
	isClient bool

	readMu  sync.Mutex
	writeMu sync.Mutex
	pending []byte

	keepAliveID atomic.Int64
	done        chan struct{}
	stopOnce    sync.Once
}

func newPacketStream(reader io.Reader, writer io.Writer, isClient bool) *packetStream {
	s := &packetStream{
		reader:   reader,
		writer:   writer,
		isClient: isClient,
		done:     make(chan struct{}),
	}
	if !isClient {
		go s.keepAliveLoop()
	}
	return s
}

func (s *packetStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}

	for {
		packet, err := readPacket(s.reader)
		if err != nil {
			return 0, fmt.Errorf("read minecraft packet stream: %w", err)
		}

		if packet.packetID == s.remoteCustomPayloadID() {
			payload, ok, err := parseCustomPayload(packet)
			if err != nil {
				return 0, err
			}
			if !ok || len(payload) == 0 {
				continue
			}

			n := copy(p, payload)
			if n < len(payload) {
				s.pending = append(s.pending[:0], payload[n:]...)
			}
			return n, nil
		}

		if packet.packetID == configurationKeepAlive {
			var id Long
			if err := packet.readFields(&id); err != nil {
				return 0, fmt.Errorf("read minecraft keep-alive: %w", err)
			}
			if s.isClient {
				if err := s.writeKeepAlive(id); err != nil {
					return 0, err
				}
			}
		}
	}
}

func (s *packetStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	written := 0
	for written < len(p) {
		end := written + maxPacketData
		if end > len(p) {
			end = len(p)
		}
		channel := String(packetChannel)
		payload := RestBytes(p[written:end])
		if err := writePacket(s.writer, s.localCustomPayloadID(), &channel, &payload); err != nil {
			return written, fmt.Errorf("write minecraft custom payload: %w", err)
		}
		written = end
	}

	return written, nil
}

func (s *packetStream) Stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

func (s *packetStream) localCustomPayloadID() int {
	if s.isClient {
		return configurationServerboundCustomPayload
	}
	return configurationClientboundCustomPayload
}

func (s *packetStream) remoteCustomPayloadID() int {
	if s.isClient {
		return configurationClientboundCustomPayload
	}
	return configurationServerboundCustomPayload
}

func parseCustomPayload(packet *mcPacket) ([]byte, bool, error) {
	r := bytes.NewReader(packet.data)
	var channel String
	if err := channel.readFrom(r); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload channel: %w", err)
	}
	if string(channel) != packetChannel {
		return nil, false, nil
	}
	payload := make([]byte, r.Len())
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload data: %w", err)
	}
	return payload, true, nil
}

func (s *packetStream) writeKeepAlive(id Long) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := writePacket(s.writer, configurationKeepAlive, &id); err != nil {
		return fmt.Errorf("write minecraft keep-alive: %w", err)
	}
	return nil
}

func (s *packetStream) keepAliveLoop() {
	ticker := time.NewTicker(keepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			id := Long(s.keepAliveID.Add(1))
			if err := s.writeKeepAlive(id); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}
