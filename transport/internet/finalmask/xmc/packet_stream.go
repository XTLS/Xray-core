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

	// packetIDs are the configuration-state ids of the negotiated version: the
	// custom payload pair that carries the tunnel plus the keep-alives, pings,
	// cookies and disconnects a peer may send before the tunnel starts.
	packetIDs configurationPacketIDs

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

func newTickStream(reader io.Reader, writer io.Writer, isClient bool, packetIDs configurationPacketIDs, dataChannel, paddingChannel string) *tickStream {
	s := &tickStream{
		reader:         reader,
		writer:         writer,
		isClient:       isClient,
		packetIDs:      packetIDs,
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

		// Everything else in this state is server chatter: the client answers
		// what a vanilla client answers and skips the rest (registry data, tags,
		// dialogs...), which is what keeps it working across releases. The server
		// side only reads tunnel data, so it skips all of it.
		if !s.isClient {
			continue
		}

		switch packet.packetID {
		case s.packetIDs.clientboundKeepAlive:
			var id Long
			if err := packet.readFields(&id); err != nil {
				return 0, fmt.Errorf("read minecraft keep-alive: %w", err)
			}
			if err := s.writeKeepAlive(s.packetIDs.serverboundKeepAlive, id); err != nil {
				return 0, err
			}

		case s.packetIDs.clientboundPing:
			// Configuration Ping is answered with Pong, like a real client. The
			// id is a plain 32-bit integer here, not a varint.
			var id Int
			if err := packet.readFields(&id); err != nil {
				return 0, fmt.Errorf("read minecraft ping: %w", err)
			}
			if err := s.writePong(id); err != nil {
				return 0, err
			}

		case s.packetIDs.clientboundCookieRequest:
			if err := s.writeCookieResponse(packet); err != nil {
				return 0, err
			}

		case s.packetIDs.clientboundDisconnect:
			var reason String
			_ = packet.readFields(&reason)
			return 0, fmt.Errorf("minecraft disconnected: %s", string(reason))
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
		return s.packetIDs.serverboundCustomPayload
	}
	return s.packetIDs.clientboundCustomPayload
}

func (s *tickStream) remoteCustomPayloadID() int {
	if s.isClient {
		return s.packetIDs.clientboundCustomPayload
	}
	return s.packetIDs.serverboundCustomPayload
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

func (s *tickStream) writeKeepAlive(packetID int, id Long) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := writePacket(s.writer, packetID, &id); err != nil {
		return fmt.Errorf("write minecraft keep-alive: %w", err)
	}
	return nil
}

// writePong answers a configuration Ping, which a vanilla client always does.
func (s *tickStream) writePong(id Int) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := writePacket(s.writer, s.packetIDs.serverboundPong, &id); err != nil {
		return fmt.Errorf("write minecraft pong: %w", err)
	}
	return nil
}

// writeCookieResponse answers a cookie request with an absent cookie, which is
// what a client that never received one sends.
func (s *tickStream) writeCookieResponse(request *mcPacket) error {
	var key String
	if err := request.readFields(&key); err != nil {
		return fmt.Errorf("read minecraft cookie request: %w", err)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	answered := Boolean(false)
	if err := writePacket(s.writer, s.packetIDs.serverboundCookieResponse, &key, &answered); err != nil {
		return fmt.Errorf("write minecraft cookie response: %w", err)
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
			if err := s.writeKeepAlive(s.packetIDs.clientboundKeepAlive, id); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}
