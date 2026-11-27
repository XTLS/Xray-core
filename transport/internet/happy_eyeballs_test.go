package internet

import (
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/features/dns"
)

const raceTestDomain = "race.example.com"

type raceTestDNS struct {
	ips []net.IP
}

func (*raceTestDNS) Type() interface{} { return dns.ClientType() }
func (*raceTestDNS) Start() error      { return nil }
func (*raceTestDNS) Close() error      { return nil }
func (d *raceTestDNS) LookupIP(domain string, _ dns.IPOption) ([]net.IP, uint32, error) {
	if domain != raceTestDomain {
		return nil, 0, dns.ErrEmptyResponse
	}
	return d.ips, 0, nil
}

// raceTestDialer sends each IP to its own local listener.
type raceTestDialer struct {
	mu      sync.Mutex
	targets map[string]string
	dialed  []string
	conns   []*raceTestConn
}

// raceTestConn records whether the client has closed the connection.
type raceTestConn struct {
	net.Conn
	ip     string
	closed atomic.Bool
}

func (c *raceTestConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (d *raceTestDialer) Dial(ctx context.Context, _ net.Address, dest net.Destination, _ *SocketConfig) (net.Conn, error) {
	ip := dest.Address.String()
	d.mu.Lock()
	d.dialed = append(d.dialed, ip)
	target := d.targets[ip]
	d.mu.Unlock()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	c := &raceTestConn{Conn: conn, ip: ip}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

func (*raceTestDialer) DestIpAddress() net.IP { return nil }

func (d *raceTestDialer) dialedIPs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// openIPs returns the IPs of the connections the client has not closed.
func (d *raceTestDialer) openIPs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var ips []string
	for _, c := range d.conns {
		if !c.closed.Load() {
			ips = append(ips, c.ip)
		}
	}
	return ips
}

type raceTestServer struct {
	listener net.Listener
	// closed receives once for every accepted connection the client closes.
	closed chan struct{}
}

// startRaceTestServer accepts TCP connections and, unless stall is set,
// completes TLS handshakes with the given certificate. A stalled server reads
// the ClientHello and never answers it.
func startRaceTestServer(t *testing.T, certificate gotls.Certificate, stall bool) *raceTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &raceTestServer{listener: listener, closed: make(chan struct{}, 16)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if !stall {
					tlsConn := gotls.Server(conn, &gotls.Config{Certificates: []gotls.Certificate{certificate}})
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					conn = tlsConn
				}
				io.Copy(io.Discard, conn)
				s.closed <- struct{}{}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return s
}

func raceTestCertificate(t *testing.T, name string) (gotls.Certificate, *x509.CertPool) {
	t.Helper()
	c, _ := cert.MustGenerate(nil, cert.DNSNames(name), cert.CommonName(name))
	certPEM, keyPEM := c.ToPEM()
	certificate, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return certificate, pool
}

// setupHandshakeRace routes the given IPs of raceTestDomain to the servers.
func setupHandshakeRace(t *testing.T, servers map[string]*raceTestServer, order []string) *raceTestDialer {
	t.Helper()
	ips := make([]net.IP, 0, len(order))
	dialer := &raceTestDialer{targets: map[string]string{}}
	for _, ip := range order {
		ips = append(ips, net.ParseIP(ip))
		dialer.targets[ip] = servers[ip].listener.Addr().String()
	}
	oldDNS, oldDialer := dnsClient, effectiveSystemDialer
	dnsClient = &raceTestDNS{ips: ips}
	effectiveSystemDialer = dialer
	t.Cleanup(func() {
		dnsClient, effectiveSystemDialer = oldDNS, oldDialer
	})
	return dialer
}

func raceTestStreamSettings(successDefinition HappyEyeballsConfig_SuccessDefinition, maxConcurrentTry uint32) *MemoryStreamConfig {
	return &MemoryStreamConfig{
		SocketSettings: &SocketConfig{
			DomainStrategy: DomainStrategy_USE_IP,
			HappyEyeballs: &HappyEyeballsConfig{
				Interleave:        1,
				TryDelayMs:        50,
				MaxConcurrentTry:  maxConcurrentTry,
				SuccessDefinition: successDefinition,
			},
		},
	}
}

// raceTestHandshake builds TLS from the logical destination, as transports do.
func raceTestHandshake(dest net.Destination, pool *x509.CertPool, dialedAddrs chan<- string) func(context.Context, net.Conn) (net.Conn, error) {
	return func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		if dialedAddrs != nil {
			dialedAddrs <- conn.RemoteAddr().String()
		}
		tlsConn := gotls.Client(conn, &gotls.Config{ServerName: dest.Address.String(), RootCAs: pool})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

func waitClosed(t *testing.T, s *raceTestServer) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the losing connection was not closed")
	}
}

func TestHandshakeRaceSkipsStalledHandshake(t *testing.T) {
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, certificate, true),
		"192.0.2.2": startRaceTestServer(t, certificate, false),
	}
	setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), raceTestHandshake(dest, pool, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, want := conn.RemoteAddr().String(), servers["192.0.2.2"].listener.Addr().String(); got != want {
		t.Fatalf("won by %s, want %s", got, want)
	}
	if state := conn.(*gotls.Conn).ConnectionState(); !state.HandshakeComplete || state.ServerName != raceTestDomain {
		t.Fatalf("unexpected TLS state: complete=%v serverName=%q", state.HandshakeComplete, state.ServerName)
	}
	waitClosed(t, servers["192.0.2.1"])
}

func TestHandshakeRaceFirstHandshakeWins(t *testing.T) {
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, certificate, false),
		"192.0.2.2": startRaceTestServer(t, certificate, true),
	}
	setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), raceTestHandshake(dest, pool, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, want := conn.RemoteAddr().String(), servers["192.0.2.1"].listener.Addr().String(); got != want {
		t.Fatalf("won by %s, want %s", got, want)
	}
}

func TestHandshakeRaceRejectsFailedVerification(t *testing.T) {
	wrongCertificate, _ := raceTestCertificate(t, "other.example.com")
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, wrongCertificate, false),
		"192.0.2.2": startRaceTestServer(t, certificate, false),
	}
	setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), raceTestHandshake(dest, pool, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, want := conn.RemoteAddr().String(), servers["192.0.2.2"].listener.Addr().String(); got != want {
		t.Fatalf("won by %s, want %s", got, want)
	}
}

func TestHandshakeRaceAllFail(t *testing.T) {
	wrongCertificate, pool := raceTestCertificate(t, "other.example.com")
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, wrongCertificate, false),
		"192.0.2.2": startRaceTestServer(t, wrongCertificate, false),
	}
	setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), raceTestHandshake(dest, pool, nil))
	if err == nil {
		conn.Close()
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "failed to complete handshake") {
		t.Fatalf("the error does not tell a handshake failure: %v", err)
	}
}

func TestHandshakeRaceParentCancel(t *testing.T) {
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, certificate, true),
		"192.0.2.2": startRaceTestServer(t, certificate, true),
	}
	setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), raceTestHandshake(dest, pool, nil))
	if err == nil {
		conn.Close()
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("returned %v after the context was done", elapsed)
	}
	waitClosed(t, servers["192.0.2.1"])
	waitClosed(t, servers["192.0.2.2"])
}

func TestHandshakeRaceMaxConcurrentTryCoversHandshake(t *testing.T) {
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, certificate, true),
		"192.0.2.2": startRaceTestServer(t, certificate, false),
	}
	dialer := setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	// With one slot, a TCP connection whose handshake hangs keeps the slot.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 1), raceTestHandshake(dest, pool, nil))
	if err == nil {
		conn.Close()
		t.Fatal("expected an error")
	}
	if dialed := dialer.dialedIPs(); len(dialed) != 1 || dialed[0] != "192.0.2.1" {
		t.Fatalf("dialed %v, want only 192.0.2.1", dialed)
	}
}

func TestHandshakeRaceFinishesLazyHandshake(t *testing.T) {
	wrongCertificate, _ := raceTestCertificate(t, "other.example.com")
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, wrongCertificate, false),
		"192.0.2.2": startRaceTestServer(t, certificate, false),
	}
	dialer := setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	// As gRPC does, and HTTPUpgrade and XHTTP with Go TLS, the handshake is
	// left to the first write.
	lazyHandshake := func(_ context.Context, conn net.Conn) (net.Conn, error) {
		return gotls.Client(conn, &gotls.Config{ServerName: dest.Address.String(), RootCAs: pool}), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), lazyHandshake)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := conn.RemoteAddr().String(), servers["192.0.2.2"].listener.Addr().String(); got != want {
		t.Fatalf("won by %s, want %s", got, want)
	}
	if !conn.(*gotls.Conn).ConnectionState().HandshakeComplete {
		t.Fatal("the race did not finish the handshake")
	}
	conn.Close()
	// The connection whose certificate was rejected is closed as well.
	if open := dialer.openIPs(); len(open) != 0 {
		t.Fatalf("the connections to %v were left open", open)
	}
}

func TestHandshakeRaceTcpConnectedKeepsTcpRace(t *testing.T) {
	certificate, pool := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, certificate, true),
		"192.0.2.2": startRaceTestServer(t, certificate, false),
	}
	setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	// The TCP race picks the first IP, whose handshake then hangs.
	addrs := make(chan string, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TcpConnected, 4), raceTestHandshake(dest, pool, addrs))
	if err == nil {
		conn.Close()
		t.Fatal("expected an error")
	}
	if len(addrs) != 1 {
		t.Fatalf("handshake ran %d times, want 1", len(addrs))
	}
	if got, want := <-addrs, servers["192.0.2.1"].listener.Addr().String(); got != want {
		t.Fatalf("handshake ran on %s, want %s", got, want)
	}
}

func TestHandshakeRaceWithoutHandshake(t *testing.T) {
	certificate, _ := raceTestCertificate(t, raceTestDomain)
	servers := map[string]*raceTestServer{
		"192.0.2.1": startRaceTestServer(t, certificate, true),
		"192.0.2.2": startRaceTestServer(t, certificate, true),
	}
	dialer := setupHandshakeRace(t, servers, []string{"192.0.2.1", "192.0.2.2"})
	dest := net.TCPDestination(net.DomainAddress(raceTestDomain), 443)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialTCPWithHandshake(ctx, dest, raceTestStreamSettings(HappyEyeballsConfig_TlsHandshakeComplete, 4), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*gotls.Conn); ok {
		t.Fatal("got a TLS connection without a handshake")
	}
	if dialed := dialer.dialedIPs(); len(dialed) == 0 || dialed[0] != "192.0.2.1" {
		t.Fatalf("dialed %v, want the TCP race to start with 192.0.2.1", dialed)
	}
}
