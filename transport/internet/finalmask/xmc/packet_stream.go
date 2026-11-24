package xmc

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	configurationClientboundCustomPayload = 0x01
	configurationServerboundCustomPayload = 0x02
	configurationKeepAlive                = 0x04

	maxPacketData   = 24 * 1024
	keepAlivePeriod = 15 * time.Second

	// tickInterval is one Minecraft game tick. After the handshake the proxy
	// stream is emitted in one batch per tick so that the connection keeps the
	// 20 Hz shape of a real client instead of turning into a bulk TCP stream.
	tickInterval = 50 * time.Millisecond
	// maxQueuedData bounds proxy data waiting for the next tick. Write blocks
	// once the queue is full, so a slow peer pushes back to the proxy instead
	// of growing memory without bound.
	maxQueuedData = 4 * 1024 * 1024
	// tickPaddingSize keeps every tick non-empty in both directions, like the
	// small per-tick packets a real client and server keep sending while idle.
	tickPaddingSize = 1
)

// tickStream carries the raw proxy byte stream in Minecraft configuration
// custom payload packets. The configuration state provides bidirectional
// payload packets and keep-alives without requiring version-specific world data.
//
// Proxy writes are queued and flushed once per game tick (50 ms). Each tick
// always emits at least one small padding frame, so an idle connection keeps
// the same 20 Hz cadence as a real client. Data that does not fit in one
// payload is split over several payloads in the same tick, which keeps the
// per-tick burst shape without an artificial bandwidth cap.
type tickStream struct {
	reader   io.Reader
	writer   io.Writer
	isClient bool

	// Configured custom payload channels: the data one carries proxy bytes, the
	// padding one keeps an idle tick non-empty. Both ends must use the same pair.
	dataChannel    string
	paddingChannel string

	readMu  sync.Mutex
	pending []byte

	writeMu sync.Mutex

	queueMu   sync.Mutex
	queueCond *sync.Cond
	queue     []byte
	closed    bool

	keepAliveID atomic.Int64
	done        chan struct{}
	stopOnce    sync.Once
}

func newTickStream(reader io.Reader, writer io.Writer, isClient bool, dataChannel, paddingChannel string) *tickStream {
	s := &tickStream{
		reader:         reader,
		writer:         writer,
		isClient:       isClient,
		dataChannel:    dataChannel,
		paddingChannel: paddingChannel,
		done:           make(chan struct{}),
	}
	s.queueCond = sync.NewCond(&s.queueMu)
	go s.tickLoop()
	if !isClient {
		go s.keepAliveLoop()
	}
	return s
}

func (s *tickStream) tickLoop() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.flushTick(); err != nil {
				s.Stop()
				return
			}
		case <-s.done:
			return
		}
	}
}

// flushTick writes one game tick worth of packets in a single network write:
// queued proxy data first, then one small padding frame. Data is split into
// payloads of at most maxPacketData bytes, but every payload stays in this
// tick's batch, so a busy connection looks like Minecraft chunk bursts rather
// than a continuous stream.
func (s *tickStream) flushTick() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	data := s.takeQueue()

	var batch bytes.Buffer
	if err := s.writeDataPackets(&batch, data); err != nil {
		return err
	}
	if err := writeCustomPayload(&batch, s.localCustomPayloadID(), s.paddingChannel, make([]byte, tickPaddingSize)); err != nil {
		return err
	}

	if _, err := s.writer.Write(batch.Bytes()); err != nil {
		return fmt.Errorf("write minecraft tick: %w", err)
	}
	return nil
}

// Flush writes queued proxy data immediately instead of waiting for the next
// tick. Close uses it so the last bytes are not dropped after Write returned.
func (s *tickStream) Flush() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	data := s.takeQueue()
	if len(data) == 0 {
		return nil
	}

	var batch bytes.Buffer
	if err := s.writeDataPackets(&batch, data); err != nil {
		return err
	}
	_, err := s.writer.Write(batch.Bytes())
	return err
}

func (s *tickStream) takeQueue() []byte {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	data := s.queue
	s.queue = nil
	s.queueCond.Broadcast()
	return data
}

func (s *tickStream) writeDataPackets(batch *bytes.Buffer, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), maxPacketData)
		if err := writeCustomPayload(batch, s.localCustomPayloadID(), s.dataChannel, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func writeCustomPayload(w io.Writer, packetID int, channel string, payload []byte) error {
	name := String(channel)
	data := RestBytes(payload)
	return writePacket(w, packetID, &name, &data)
}

func (s *tickStream) Read(p []byte) (int, error) {
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
			payload, ok, err := parseCustomPayload(packet, s.dataChannel)
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

func (s *tickStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.queueMu.Lock()
	for len(s.queue) >= maxQueuedData && !s.closed {
		s.queueCond.Wait()
	}
	if s.closed {
		s.queueMu.Unlock()
		return 0, net.ErrClosed
	}
	s.queue = append(s.queue, p...)
	s.queueMu.Unlock()

	return len(p), nil
}

func (s *tickStream) Stop() {
	s.stopOnce.Do(func() {
		s.queueMu.Lock()
		s.closed = true
		s.queue = nil
		s.queueCond.Broadcast()
		s.queueMu.Unlock()
		close(s.done)
	})
}

func (s *tickStream) localCustomPayloadID() int {
	if s.isClient {
		return configurationServerboundCustomPayload
	}
	return configurationClientboundCustomPayload
}

func (s *tickStream) remoteCustomPayloadID() int {
	if s.isClient {
		return configurationClientboundCustomPayload
	}
	return configurationServerboundCustomPayload
}

func parseCustomPayload(packet *mcPacket, dataChannel string) ([]byte, bool, error) {
	r := bytes.NewReader(packet.data)
	var channel String
	if err := channel.readFrom(r); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload channel: %w", err)
	}
	if string(channel) != dataChannel {
		return nil, false, nil
	}
	payload := make([]byte, r.Len())
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload data: %w", err)
	}
	return payload, true, nil
}

func (s *tickStream) writeKeepAlive(id Long) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := writePacket(s.writer, configurationKeepAlive, &id); err != nil {
		return fmt.Errorf("write minecraft keep-alive: %w", err)
	}
	return nil
}

func (s *tickStream) keepAliveLoop() {
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
