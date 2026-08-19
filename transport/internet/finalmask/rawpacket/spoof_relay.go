package rawpacket

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Relay struct {
	cfg            *RelayConfig
	psk            []byte
	recver         SpoofReceiver
	sender         SpoofSender
	done           chan struct{}
	closeOnce      sync.Once
	icmpSuppressed bool
	maxPayload     int
	sessionTimeout time.Duration
	rstManaged     bool
	masq           *masquerade

	man *SessionManager

	recentSIDs map[[8]byte]time.Time
	recentMu   sync.Mutex
}

const (
	relaySessionTimeout = 120 * time.Second
	relaySIDRemember    = 10 * time.Minute
)

func NewRelay(cfg *RelayConfig) (*Relay, error) {
	if cfg.SendTransport == "" {
		cfg.SendTransport = "udp"
	}
	if cfg.RecvTransport == "" {
		cfg.RecvTransport = "tcp"
	}
	if len(cfg.Auth) == 0 {
		return nil, errors.New("rawpacket: auth (PSK) required in remote mode")
	}

	if cfg.RecvTransport == "icmp" || cfg.RecvTransport == "icmpv6" {
		if suppressICMPEchoReply() {
			cfg.icmpSuppressed = true
		}
	}

	var spoofIPs []netip.Addr
	if len(cfg.SpoofIPs) > 0 {
		spoofIPs, _ = ParseIPs(cfg.SpoofIPs)
	}
	if len(spoofIPs) == 0 && cfg.SpoofIP.IsValid() {
		spoofIPs = []netip.Addr{cfg.SpoofIP}
	}
	if len(spoofIPs) == 0 {
		spoofIPs = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}

	recver, err := NewReceiver(cfg.RecvTransport, &SpoofReceiverConfig{
		ListenPort:  cfg.ListenPort,
		PeerSpoofIP: cfg.PeerSpoofIP,
		BufferSize:  4 * 1024 * 1024,
	})
	if err != nil {
		if cfg.icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	sender, err := NewSender(cfg.SendTransport, &SpoofSenderConfig{
		SourceIPs:  spoofIPs,
		SourcePort: cfg.SpoofPort,
		TTL:        64,
		Server:     true,
	})
	if err != nil {
		recver.Close()
		if cfg.icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	r := &Relay{
		cfg:            cfg,
		psk:            []byte(cfg.Auth),
		recver:         recver,
		sender:         sender,
		done:           make(chan struct{}),
		icmpSuppressed: cfg.icmpSuppressed,
		maxPayload:     maxPayloadForMTU(cfg.Mtu),
		sessionTimeout: relaySessionTimeout,
		man:            NewSessionManager(),
		recentSIDs:     make(map[[8]byte]time.Time),
	}
	if cfg.SuppressRst {
		r.rstManaged = suppressKernelRST(cfg.ListenPort)
	}
	masq, masqErr := newMasquerade(cfg.Masquerade, cfg.ListenPort)
	if masqErr != nil {
		r.Close()
		return nil, masqErr
	}
	r.masq = masq
	return r, nil
}

func (r *Relay) Run() {
	go r.uplinkLoop()
	go r.janitorLoop()
	<-r.done
}

func (r *Relay) dialTarget() (net.Conn, error) {
	return net.DialTimeout(r.cfg.ForwardTransport, r.cfg.ForwardAddr, 10*time.Second)
}

func (r *Relay) uplinkLoop() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		pkt, srcIP, srcPort, tcp, err := r.recver.Receive()
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			// A TCP segment without payload is never a tunnel frame:
			// bare SYNs are handshake probes from scanners.
			if r.masq != nil && tcp != nil && tcp.Flags&TCPFlagSyn != 0 && tcp.Flags&TCPFlagAck == 0 {
				r.masq.onTCPSYN(tcp.DstIP, tcp.DstPort, srcIP, srcPort, tcp.Seq)
			}
			continue
		}
		r.handleFrame(pkt, srcIP, srcPort, tcp)
	}
}

func (r *Relay) handleFrame(pkt []byte, srcIP netip.Addr, srcPort uint16, tcp *TCPMeta) {
	sid, ok := frameSessionID(pkt)
	if !ok {
		r.masqueradeProbe(pkt, srcIP, srcPort, tcp)
		return
	}
	s := r.man.Get(sid)
	if s == nil {
		if !r.handleNewSession(sid, pkt, srcIP, srcPort) {
			r.masqueradeProbe(pkt, srcIP, srcPort, tcp)
		}
		return
	}
	if !r.deliverToSession(s, pkt, tcp) {
		r.masqueradeProbe(pkt, srcIP, srcPort, tcp)
	}
}

// masqueradeProbe answers packets that do not belong to any tunnel
// session (failed frame parse or decryption) with fake service traffic.
func (r *Relay) masqueradeProbe(pkt []byte, srcIP netip.Addr, srcPort uint16, tcp *TCPMeta) {
	if r.masq == nil || tcp == nil {
		return
	}
	if tcp.Flags != 0 {
		r.masq.onTCPData(tcp.DstIP, tcp.DstPort, srcIP, srcPort, tcp.Seq, pkt)
	} else {
		r.masq.onUDP(tcp.DstIP, tcp.DstPort, srcIP, srcPort, pkt)
	}
}

func (r *Relay) handleNewSession(sid [8]byte, pkt []byte, srcIP netip.Addr, srcPort uint16) bool {
	if r.recentSIDSeen(sid) {
		// Replay of a session that was already torn down: drop.
		return false
	}
	crypto, err := newFrameCrypto(r.psk, sid)
	if err != nil {
		return false
	}
	payload, flags, err := crypto.open(pkt, false)
	if err != nil {
		return false
	}
	if flags&frameFlagKeepalive != 0 {
		// A keepalive for a session that no longer exists: ignore.
		return false
	}
	targetConn, err := r.dialTarget()
	if err != nil {
		return false
	}
	s := r.man.Add(sid, srcIP, srcPort, targetConn, crypto, newTCPSimState())
	r.rememberSID(sid)
	go r.forwardSession(s)
	if len(payload) > 0 {
		writeTarget(s, payload)
	}
	return true
}

func (r *Relay) deliverToSession(s *RelaySession, pkt []byte, tcp *TCPMeta) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()

	payload, _, err := s.crypto.open(pkt, false)
	if err != nil {
		return false
	}
	if tcp != nil && tcp.Flags != 0 {
		s.tcp.observeClientSeq(tcp.Seq)
	}
	s.mu.Lock()
	s.LastSeen = time.Now()
	s.mu.Unlock()

	if len(payload) > 0 {
		if !writeTarget(s, payload) {
			r.man.Remove(s.ID)
			return false
		}
	}
	return true
}

// writeTarget writes the whole payload to the target connection, handling
// partial writes. Returns false if the write failed (caller should remove
// the session).
func writeTarget(s *RelaySession, data []byte) bool {
	if s.TargetConn == nil {
		return false
	}
	_ = s.TargetConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	n := 0
	for n < len(data) {
		m, err := s.TargetConn.Write(data[n:])
		if err != nil {
			return false
		}
		if m == 0 {
			return false
		}
		n += m
	}
	return true
}

// forwardSession pumps target->client data for one session. It exits on
// read error or EOF and removes the session.
func (r *Relay) forwardSession(s *RelaySession) {
	buf := make([]byte, 64*1024)
	for {
		n, err := s.TargetConn.Read(buf)
		if err != nil {
			r.man.Remove(s.ID)
			return
		}
		if n == 0 {
			continue
		}
		frames, ferr := s.crypto.sealSplit(true, buf[:n], r.maxPayload, false)
		if ferr != nil {
			continue
		}
		ok := true
		for _, f := range frames {
			if serr := r.sender.Send(f, s.ClientIP, s.ClientPort, s.tcp); serr != nil {
				ok = false
				break
			}
		}
		if ok {
			s.mu.Lock()
			s.LastSeen = time.Now()
			s.mu.Unlock()
		} else {
			r.man.Remove(s.ID)
			return
		}
	}
}

// janitorLoop reaps sessions idle for longer than sessionTimeout and
// prunes the recent-session-ID anti-replay set.
func (r *Relay) janitorLoop() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			now := time.Now()
			for _, s := range r.man.All() {
				s.mu.Lock()
				idle := now.Sub(s.LastSeen)
				s.mu.Unlock()
				if idle > r.sessionTimeout {
					r.man.Remove(s.ID)
				}
			}
			r.pruneRecentSIDs(now)
		}
	}
}

func (r *Relay) rememberSID(sid [8]byte) {
	r.recentMu.Lock()
	r.recentSIDs[sid] = time.Now()
	r.recentMu.Unlock()
}

func (r *Relay) recentSIDSeen(sid [8]byte) bool {
	r.recentMu.Lock()
	defer r.recentMu.Unlock()
	_, ok := r.recentSIDs[sid]
	return ok
}

func (r *Relay) pruneRecentSIDs(now time.Time) {
	r.recentMu.Lock()
	defer r.recentMu.Unlock()
	for sid, t := range r.recentSIDs {
		if now.Sub(t) > relaySIDRemember {
			delete(r.recentSIDs, sid)
		}
	}
}

func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		close(r.done)
		r.recver.Close()
		r.sender.Close()
		r.man.Close()
		if r.icmpSuppressed {
			restoreICMPEchoReply()
		}
		if r.rstManaged {
			restoreKernelRST(r.cfg.ListenPort, true)
		}
	})
}
