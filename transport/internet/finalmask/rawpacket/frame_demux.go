package rawpacket

import (
	"net/netip"
	"sync"
)

// frameDemux demultiplexes decrypted relay->client frames to per-conn
// consumers. Multiple SpoofConns on the same host share one raw receiver
// per (protocol, listen port); a raw socket delivers a copy of every
// matching packet to every socket, so the receiver must be shared or
// frames would be duplicated across connections.
type frameDemux struct {
	proto  string
	port   uint16
	peerIP netip.Addr

	mu       sync.Mutex
	sessions map[[8]byte]*demuxSession
	recver   SpoofReceiver
	refs     int
	running  bool
	gen      uint64
}

type demuxSession struct {
	crypto *frameCrypto
	ch     chan demuxData
}

// demuxData is one decrypted relay->client payload with the originating
// TCP header metadata (for sequence/ack state tracking).
type demuxData struct {
	payload []byte
	tcp     *TCPMeta
}

type demuxKey struct {
	proto string
	port  uint16
}

var demuxRegistry sync.Map // demuxKey -> *frameDemux

func getFrameDemux(proto string, port uint16, peerIP netip.Addr) *frameDemux {
	key := demuxKey{proto: proto, port: port}
	if d, ok := demuxRegistry.Load(key); ok {
		return d.(*frameDemux)
	}
	d := &frameDemux{
		proto:    proto,
		port:     port,
		peerIP:   peerIP,
		sessions: make(map[[8]byte]*demuxSession),
	}
	actual, _ := demuxRegistry.LoadOrStore(key, d)
	return actual.(*frameDemux)
}

// register subscribes sid to the demux, starting the shared receiver and
// demux goroutine on first use.
func (d *frameDemux) register(sid [8]byte, crypto *frameCrypto, ch chan demuxData) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions[sid] = &demuxSession{crypto: crypto, ch: ch}
	d.refs++
	if d.running {
		return nil
	}
	recver, err := NewReceiver(d.proto, &SpoofReceiverConfig{
		ListenPort:  d.port,
		PeerSpoofIP: d.peerIP,
		BufferSize:  4 * 1024 * 1024,
	})
	if err != nil {
		delete(d.sessions, sid)
		d.refs--
		return err
	}
	d.recver = recver
	d.running = true
	d.gen++
	go d.run(d.gen)
	return nil
}

func (d *frameDemux) unregister(sid [8]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, sid)
	d.refs--
	if d.refs > 0 || !d.running {
		return
	}
	d.running = false
	d.recver.Close()
	d.recver = nil
	demuxRegistry.Delete(demuxKey{proto: d.proto, port: d.port})
}

func (d *frameDemux) run(gen uint64) {
	for {
		pkt, _, _, tcp, err := d.recver.Receive()
		if err != nil {
			d.mu.Lock()
			if d.gen != gen {
				// Superseded by a newer generation (the demux was torn
				// down and restarted): leave the new sessions alone.
				d.mu.Unlock()
				return
			}
			// Receiver died unexpectedly (or the demux was torn down):
			// unblock every consumer.
			for _, s := range d.sessions {
				close(s.ch)
			}
			d.sessions = make(map[[8]byte]*demuxSession)
			d.running = false
			d.mu.Unlock()
			return
		}
		sid, ok := frameSessionID(pkt)
		if !ok {
			continue
		}
		d.mu.Lock()
		s := d.sessions[sid]
		d.mu.Unlock()
		if s == nil {
			continue
		}
		payload, flags, err := s.crypto.open(pkt, true)
		if err != nil || flags&frameFlagKeepalive != 0 || len(payload) == 0 {
			continue
		}
		select {
		case s.ch <- demuxData{payload: payload, tcp: tcp}:
		default: // consumer is slow: drop rather than stall the demux
		}
	}
}
