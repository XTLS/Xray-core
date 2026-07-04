package rawpacket

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Relay struct {
	cfg            *RelayConfig
	recver         SpoofReceiver
	sender         SpoofSender
	done           chan struct{}
	closeOnce      sync.Once
	icmpSuppressed bool

	// UDP forwarding (reference mode)
	targetUDPConn *net.UDPConn
	fwdUDPAddr    *net.UDPAddr

	// TCP forwarding (Xray mode)
	man *SessionManager
}

func NewRelay(cfg *RelayConfig) (*Relay, error) {
	if cfg.SendTransport == "" {
		cfg.SendTransport = "udp"
	}
	if cfg.RecvTransport == "" {
		cfg.RecvTransport = "tcp"
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
		recver:         recver,
		sender:         sender,
		done:           make(chan struct{}),
		icmpSuppressed: cfg.icmpSuppressed,
	}

	if cfg.ForwardTransport == "tcp" {
		// TCP mode: create session manager for Xray integration
		r.man = NewSessionManager()
	} else {
		// UDP mode: match reference behavior
		fwdAddr, err := net.ResolveUDPAddr("udp4", cfg.ForwardAddr)
		if err != nil {
			recver.Close()
			sender.Close()
			if cfg.icmpSuppressed {
				restoreICMPEchoReply()
			}
			return nil, err
		}
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			recver.Close()
			sender.Close()
			if cfg.icmpSuppressed {
				restoreICMPEchoReply()
			}
			return nil, err
		}
		r.targetUDPConn = udpConn
		r.fwdUDPAddr = fwdAddr
	}

	return r, nil
}

func (r *Relay) Run() {
	go r.uplinkLoop()
	if r.man != nil {
		go r.forwardResponses()
	} else {
		go r.downlinkLoop()
	}
	<-r.done
}

func (r *Relay) uplinkLoop() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		data, srcIP, srcPort, err := r.recver.Receive()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		if r.man != nil {
			// TCP mode: forward to target via TCP with session
			r.handleTCPForward(data, srcIP, srcPort)
		} else {
			// UDP mode: forward to target via UDP (reference behavior)
			if _, err := r.targetUDPConn.WriteToUDP(data, r.fwdUDPAddr); err != nil {
				continue
			}
		}
	}
}

func (r *Relay) handleTCPForward(data []byte, srcIP netip.Addr, srcPort uint16) {
	session := r.man.Get(srcIP, srcPort)
	if session == nil {
		targetConn, err := net.DialTimeout("tcp", r.cfg.ForwardAddr, 10*time.Second)
		if err != nil {
			return
		}
		session = r.man.Add(srcIP, srcPort, targetConn, r.cfg.ClientIP)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.closed {
		session.TargetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = session.TargetConn.Write(data)
	}
}

func (r *Relay) downlinkLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-r.done:
			return
		default:
		}

		n, _, err := r.targetUDPConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}
		_ = r.sender.Send(buf[:n], r.cfg.ClientIP, r.cfg.ClientPort)
	}
}

func (r *Relay) forwardResponses() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		for _, s := range r.man.All() {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				continue
			}
			buf := make([]byte, 65536)
			s.TargetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := s.TargetConn.Read(buf)
			if err != nil {
				if err == io.EOF {
					s.closed = true
					s.TargetConn.Close()
				}
				s.mu.Unlock()
				continue
			}
			s.mu.Unlock()
			if n > 0 {
				_ = r.sender.Send(buf[:n], s.ClientIP, s.ClientPort)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		close(r.done)
		r.recver.Close()
		r.sender.Close()
		if r.targetUDPConn != nil {
			r.targetUDPConn.Close()
		}
		if r.man != nil {
			r.man.Close()
		}
		if r.icmpSuppressed {
			restoreICMPEchoReply()
		}
	})
}
