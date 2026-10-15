package xdns

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type DOHResolver struct {
	ctx    context.Context
	cancel func()
	client *http.Client
	url    string
	time   time.Time

	udpAddr *net.UDPAddr
	readCh  chan []byte
	sendCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewDOHResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	if config.Worker < 1 {
		return nil, errors.New("invalid worker")
	}
	if config.TlsConfig == nil {
		return nil, errors.New("empty tls config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var tr http.RoundTripper
	var setaddr func(addr net.Addr)
	switch {
	case len(config.TlsConfig.NextProtocol) == 1 && config.TlsConfig.NextProtocol[0] == "h3":
		quicParams := config.QuicConfig
		if quicParams == nil {
			quicParams = &internet.QuicParams{}
		}
		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
			MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
			MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
			MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
			KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
			ChromeParrot:                   !quicParams.DisableChromeParrot,
		}
		tr = &http3.Transport{
			TLSClientConfig: config.TlsConfig.GetTLSConfig(),
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				dest, err := net.ParseDestination("udp:" + addr)
				if err != nil {
					return nil, err
				}
				conn, err := dialer.DialUDP(dest)
				if err != nil {
					return nil, err
				}
				setaddr(conn.RemoteAddr())
				tr := &quic.Transport{Conn: conn.(*net.PacketConnWrapper).PacketConn, DisableGSO: quicParams.DisableGSO}
				if !quicParams.DisableChromeParrot {
					tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
					tlsCfg.GetCertificate = nil
				}
				qc, err := tr.Dial(ctx, conn.RemoteAddr(), tlsCfg, cfg)
				if err != nil {
					return nil, err
				}
				context.AfterFunc(qc.Context(), func() { tr.Close(); conn.Close() })
				switch quicParams.Congestion {
				case "", "reno":
				case "bbr":
					congestion.UseBBR(qc, bbr.Profile(quicParams.BbrProfile))
				case "force-brutal":
					congestion.UseBrutal(qc, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
				default:
					panic(quicParams.Congestion)
				}
				return qc, nil
			},
		}
	default:
		tlsConfig := config.TlsConfig.GetTLSConfig()
		tr = &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := net.ParseDestination("tcp:" + addr)
				if err != nil {
					return nil, err
				}
				conn, err := dialer.DialTCP(dest)
				if err != nil {
					return nil, err
				}
				setaddr(conn.RemoteAddr())
				var tlsConn net.Conn
				if fingerprint := tls.GetFingerprint(config.TlsConfig.Fingerprint); fingerprint != nil {
					tlsConn = tls.UClient(conn, tlsConfig, fingerprint)
					err = tlsConn.(*tls.UConn).HandshakeContext(ctx)
				} else {
					tlsConn = gotls.Client(conn, tlsConfig)
					err = tlsConn.(*gotls.Conn).HandshakeContext(ctx)
				}
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}
	}
	client := &http.Client{
		Transport: tr,
	}
	r := &DOHResolver{
		ctx:    ctx,
		cancel: cancel,
		client: client,
		url:    config.Addr,

		udpAddr: &net.UDPAddr{IP: []byte{0, 0, 0, 0}},
		readCh:  make(chan []byte),
		sendCh:  make(chan []byte),
		closeCh: make(chan struct{}),
	}
	for range config.Worker {
		r.wg.Add(1)
		go r.worker()
	}
	setaddr = r.setaddr
	return r, nil
}

func (r *DOHResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *DOHResolver) setaddr(addr net.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch v := addr.(type) {
	case *net.TCPAddr:
		r.udpAddr = &net.UDPAddr{IP: v.IP, Port: v.Port}
	case *net.UDPAddr:
		r.udpAddr = v
	default:
		panic(v)
	}
}

func (r *DOHResolver) cooldown(t time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t == (time.Time{}) {
		return time.Now().Before(r.time)
	}
	if t.After(r.time) {
		r.time = t
	}
	return true
}

func (r *DOHResolver) do(p []byte) error {
	req := common.Must2(http.NewRequestWithContext(r.ctx, "POST", r.url, bytes.NewReader(p)))
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		p := pool4K.Get().([]byte)
		off := 0
		for {
			n, err := resp.Body.Read(p[off:])
			if n > 0 {
				off += n
			}
			if off == len(p) || err != nil {
				if err != io.EOF {
					pool4K.Put(p[:cap(p)])
					return err
				}
				break
			}
		}
		select {
		case <-r.closeCh:
			pool4K.Put(p[:cap(p)])
		case r.readCh <- p[:off]:
		}
		return nil
	case http.StatusTooManyRequests:
		if value := resp.Header.Get("Retry-After"); value != "" {
			if t, err := http.ParseTime(value); err == nil {
				r.cooldown(t)
			} else if i, err := strconv.ParseUint(value, 10, 32); err == nil {
				r.cooldown(time.Now().Add(time.Duration(i) * time.Second))
			}
		}
	}
	return errors.New("code ", resp.StatusCode, " header ", resp.Header)
}

func (r *DOHResolver) worker() {
	defer r.wg.Done()

	var p []byte
	for {
		select {
		case <-r.closeCh:
			return
		default:
			select {
			case <-r.closeCh:
				return
			case p = <-r.sendCh:
			}
		}
		if r.cooldown(time.Time{}) {
			continue
		}
		if err := r.do(p); err != nil {
			errors.LogErrorInner(context.Background(), err, "do err")
		}
	}
}

func (r *DOHResolver) Addr() *net.UDPAddr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.udpAddr
}

func (r *DOHResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *DOHResolver) Send(p []byte) {
	select {
	case <-r.closeCh:
		return
	default:
		b := make([]byte, len(p))
		copy(b, p)
		select {
		case <-r.closeCh:
			return
		case r.sendCh <- b:
		}
	}
}

func (r *DOHResolver) Close() {
	r.mu.Lock()
	if r.closed() {
		r.mu.Unlock()
		return
	}
	close(r.closeCh)
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
	r.client.CloseIdleConnections()
	close(r.readCh)
	// close(r.sendCh)
}
