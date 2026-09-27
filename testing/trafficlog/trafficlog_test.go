// Package trafficlog contains end-to-end tests for the uplink/downlink byte
// counts of the access log. They run real xray instances as child processes
// against local targets, and assert that each connection produces exactly one
// record whose counts match the bytes seen by the target at the same
// boundary. On Linux, the downlink of the plain chains takes the splice fast
// path of the freedom outbound.
//
// The xray binary is taken from XRAY_TRAFFICLOG_BIN, or built from the module
// when unset. Instance logs and access logs are written to XRAY_TRAFFICLOG_OUT
// when set, so that they can be kept as evidence.
package trafficlog

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	httpin "github.com/xtls/xray-core/proxy/http"
	vless "github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

var xrayBinary string

func TestMain(m *testing.M) {
	if bin := os.Getenv("XRAY_TRAFFICLOG_BIN"); bin != "" {
		xrayBinary = bin
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "xray-trafficlog")
	if err != nil {
		fmt.Println("failed to create temp dir:", err)
		os.Exit(1)
	}
	xrayBinary = filepath.Join(dir, "xray")
	if runtime.GOOS == "windows" {
		xrayBinary += ".exe"
	}
	build := exec.Command("go", "build", "-o="+xrayBinary, "github.com/xtls/xray-core/main")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Println("failed to build xray:", err)
		os.Remove(xrayBinary)
		os.Remove(dir)
		os.Exit(1)
	}
	code := m.Run()
	// Clean up only the resources this test created: the binary file and,
	// when empty, the directory. The exit code of the run is preserved.
	os.Remove(xrayBinary)
	os.Remove(dir)
	os.Exit(code)
}

func outputDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("XRAY_TRAFFICLOG_OUT"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	return t.TempDir()
}

func startInstance(t *testing.T, name string, config *core.Config) {
	t.Helper()
	config.App = append(config.App,
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	)
	data, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(outputDir(t), name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	// Registered before process cleanup so it runs after cmd.Wait, including
	// when cmd.Start fails. Windows cannot remove the log while it is open.
	t.Cleanup(func() { logFile.Close() })
	cmd := exec.Command(xrayBinary, "-config=stdin:", "-format=pb")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	})
}

// accessLogConfig returns an app log config that writes the access log to the
// given path.
func accessLogConfig(path string) *xlog.Config {
	return &xlog.Config{
		ErrorLogLevel: clog.Severity_Warning,
		ErrorLogType:  xlog.LogType_Console,
		AccessLogType: xlog.LogType_File,
		AccessLogPath: path,
	}
}

// accessLogPath returns the path of a fresh access log file for the test.
func accessLogPath(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(outputDir(t), name)
	os.Remove(path)
	return path
}

func pickPort(t *testing.T) xnet.Port {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := xnet.Port(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	return port
}

func dialRetry(t *testing.T, port xnet.Port) net.Conn {
	t.Helper()
	var lastErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("failed to dial 127.0.0.1:", port, ": ", lastErr)
	return nil
}

// countingTarget is an echo server that counts the raw bytes it reads and
// writes. When closeAfter is positive, it closes each connection once that
// many bytes were read on it, like a server that responds and closes.
type countingTarget struct {
	listener   net.Listener
	closeAfter int64
	read       atomic.Int64
	written    atomic.Int64
}

func startCountingTarget(t *testing.T, closeAfter int64, tlsConfig *tls.Config) (*countingTarget, xnet.Destination) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := &countingTarget{listener: listener, closeAfter: closeAfter}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				var conn net.Conn = &countingConn{Conn: raw, target: target}
				if tlsConfig != nil {
					conn = tls.Server(conn, tlsConfig)
				}
				serveEcho(conn, closeAfter)
			}(conn)
		}
	}()
	t.Cleanup(func() { listener.Close() })
	addr := listener.Addr().(*net.TCPAddr)
	return target, xnet.TCPDestination(xnet.IPAddress(addr.IP), xnet.Port(addr.Port))
}

func serveEcho(conn net.Conn, closeAfter int64) {
	buffer := make([]byte, 16*1024)
	var total int64
	for {
		n, err := conn.Read(buffer)
		total += int64(n)
		if n > 0 {
			if _, werr := conn.Write(buffer[:n]); werr != nil {
				conn.Close()
				return
			}
		}
		if err != nil {
			// The peer finished sending (e.g. a TLS close_notify); close this
			// side too, so that the connection ends on both directions.
			conn.Close()
			return
		}
		if closeAfter > 0 && total >= closeAfter {
			conn.Close()
			return
		}
	}
}

type countingConn struct {
	net.Conn
	target *countingTarget
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.target.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.target.written.Add(int64(n))
	return n, err
}

// stableCounts waits until the counters stop changing and returns them.
func (t *countingTarget) stableCounts() (int64, int64) {
	read, written := t.read.Load(), t.written.Load()
	for range 50 {
		time.Sleep(20 * time.Millisecond)
		r, w := t.read.Load(), t.written.Load()
		if r == read && w == written {
			break
		}
		read, written = r, w
	}
	return read, written
}

type accessRecord struct {
	from, to, detour string
	uplink, downlink int64
}

var accessRecordRe = regexp.MustCompile(`from (\S+) accepted (\S+)(?: \[(\S+)\])? uplink=(\d+) downlink=(\d+)`)

func readAccessRecords(path string) []accessRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var records []accessRecord
	for _, line := range strings.Split(string(data), "\n") {
		m := accessRecordRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		uplink, _ := strconv.ParseInt(m[4], 10, 64)
		downlink, _ := strconv.ParseInt(m[5], 10, 64)
		records = append(records, accessRecord{from: m[1], to: m[2], detour: m[3], uplink: uplink, downlink: downlink})
	}
	return records
}

func waitAccessRecords(t *testing.T, path string, want int) []accessRecord {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if records := readAccessRecords(path); len(records) >= want {
			return records
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d access records in %s, got %v", want, path, readAccessRecords(path))
	return nil
}

// assertNoMoreRecords waits briefly and checks that no further records were
// written, so that one connection is not recorded more than once.
func assertNoMoreRecords(t *testing.T, path string, want int) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if got := len(readAccessRecords(path)); got != want {
		t.Error("unexpected number of access records. want ", want, ", but got ", got)
	}
}

func httpConnect(t *testing.T, port xnet.Port, target xnet.Destination) net.Conn {
	t.Helper()
	conn := dialRetry(t, port)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.NetAddr(), target.NetAddr())
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatal("unexpected CONNECT status: ", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	return conn
}

func writeAll(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, conn net.Conn, length int) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func randomPayload(size int) []byte {
	payload := make([]byte, size)
	crand.Read(payload)
	return payload
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// plainServerConfig returns a config with an HTTP proxy inbound and a freedom
// outbound, whose access log goes to the given path.
func plainServerConfig(t *testing.T, port xnet.Port, accessLog string) *core.Config {
	t.Helper()
	return &core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(accessLogConfig(accessLog))},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(port)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&httpin.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}
}

// TestPlainTCPTraffic verifies the record of one plain proxied TCP connection
// with bidirectional traffic of a known size: one record, with the uplink and
// downlink equal to the bytes the target read and wrote at the same boundary.
// On Linux the downlink of this chain is served by the splice fast path.
func TestPlainTCPTraffic(t *testing.T) {
	const payloadSize = 256 * 1024
	target, dest := startCountingTarget(t, payloadSize, nil)
	accessLog := accessLogPath(t, "plain-access.log")
	port := pickPort(t)
	startInstance(t, "plain-server", plainServerConfig(t, port, accessLog))

	conn := httpConnect(t, port, dest)
	writeAll(t, conn, randomPayload(payloadSize))
	readAll(t, conn, payloadSize)
	conn.Close()

	records := waitAccessRecords(t, accessLog, 1)
	read, written := target.stableCounts()
	if read != payloadSize || written != payloadSize {
		t.Error("unexpected target traffic. want ", payloadSize, "/", payloadSize, ", but got ", read, "/", written)
	}
	record := records[0]
	if record.uplink != read || record.downlink != written {
		t.Error("record does not match the target boundary. target ", read, "/", written, ", record ", record.uplink, "/", record.downlink)
	}
	if record.detour != "freedom" {
		t.Error("unexpected detour: ", record.detour)
	}
	assertNoMoreRecords(t, accessLog, 1)
}

// TestMultiConnectionIsolation verifies that concurrent connections produce
// one record each, with the counts of their own connection only.
func TestMultiConnectionIsolation(t *testing.T) {
	sizes := []int{1111, 33333, 777777}
	target, dest := startCountingTarget(t, 0, nil)
	accessLog := accessLogPath(t, "multi-access.log")
	port := pickPort(t)
	startInstance(t, "multi-server", plainServerConfig(t, port, accessLog))

	var wg sync.WaitGroup
	locals := make([]string, len(sizes))
	for i, size := range sizes {
		wg.Add(1)
		go func(i, size int) {
			defer wg.Done()
			conn := httpConnect(t, port, dest)
			defer conn.Close()
			locals[i] = conn.LocalAddr().String()
			writeAll(t, conn, randomPayload(size))
			readAll(t, conn, size)
		}(i, size)
	}
	wg.Wait()

	records := waitAccessRecords(t, accessLog, len(sizes))
	byFrom := make(map[string]accessRecord, len(sizes))
	for _, record := range records {
		byFrom[record.from] = record
	}
	for i, size := range sizes {
		record, found := byFrom[locals[i]]
		if !found {
			t.Error("no record for connection ", locals[i])
			continue
		}
		if record.uplink != int64(size) || record.downlink != int64(size) {
			t.Error("unexpected counts for ", locals[i], ". want ", size, "/", size, ", but got ", record.uplink, "/", record.downlink)
		}
	}
	read, written := target.stableCounts()
	var want int64
	for _, size := range sizes {
		want += int64(size)
	}
	if read != want || written != want {
		t.Error("unexpected target traffic. want ", want, "/", want, ", but got ", read, "/", written)
	}
	assertNoMoreRecords(t, accessLog, len(sizes))
}

// TestHalfClose verifies the record of a connection whose client closes its
// write side after sending, and reads the response until EOF.
func TestHalfClose(t *testing.T) {
	const payloadSize = 64 * 1024
	target, dest := startCountingTarget(t, payloadSize, nil)
	accessLog := accessLogPath(t, "half-access.log")
	port := pickPort(t)
	startInstance(t, "half-server", plainServerConfig(t, port, accessLog))

	conn := httpConnect(t, port, dest)
	writeAll(t, conn, randomPayload(payloadSize))
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	readAll(t, conn, payloadSize)
	// The server closes the connection after the downlink ended.
	one := make([]byte, 1)
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(one); n != 0 || err != io.EOF {
		t.Error("expected EOF after the response, got ", n, " bytes, err ", err)
	}
	conn.Close()

	records := waitAccessRecords(t, accessLog, 1)
	read, written := target.stableCounts()
	record := records[0]
	if record.uplink != read || record.downlink != written {
		t.Error("record does not match the target boundary. target ", read, "/", written, ", record ", record.uplink, "/", record.downlink)
	}
	if read != payloadSize || written != payloadSize {
		t.Error("unexpected target traffic. want ", payloadSize, "/", payloadSize, ", but got ", read, "/", written)
	}
	assertNoMoreRecords(t, accessLog, 1)
}

// TestAbnormalClose verifies that a connection closed mid-response still
// produces exactly one record, after its copies finished.
func TestAbnormalClose(t *testing.T) {
	const payloadSize = 128 * 1024
	_, dest := startCountingTarget(t, payloadSize, nil)
	accessLog := accessLogPath(t, "abnormal-access.log")
	port := pickPort(t)
	startInstance(t, "abnormal-server", plainServerConfig(t, port, accessLog))

	conn := httpConnect(t, port, dest)
	writeAll(t, conn, randomPayload(payloadSize))
	readAll(t, conn, 1024) // stop reading mid-response
	conn.Close()

	records := waitAccessRecords(t, accessLog, 1)
	record := records[0]
	if record.uplink != payloadSize {
		t.Error("unexpected uplink. want ", payloadSize, ", but got ", record.uplink)
	}
	if record.downlink < 0 || record.downlink > payloadSize {
		t.Error("unexpected downlink. want 0..", payloadSize, ", but got ", record.downlink)
	}
	assertNoMoreRecords(t, accessLog, 1)
}

// TestVisionTraffic verifies the record of a VLESS Vision chain: the client
// runs a TLS session to a local TLS target through the tunnel. The record's
// counts must match the raw TLS bytes the target saw — the inner TLS records
// are proxied bytes, not the plaintext payload.
func TestVisionTraffic(t *testing.T) {
	const payloadSize = 128 * 1024
	targetCert := selfSignedCertificate(t)
	// The TLS target echoes until the client closes the inner TLS session
	// (close_notify), so that both sides end at the same raw byte boundary.
	target, dest := startCountingTarget(t, 0, &tls.Config{Certificates: []tls.Certificate{targetCert}})

	accessLog := accessLogPath(t, "vision-access.log")
	debugLogs := os.Getenv("XRAY_TRAFFICLOG_DEBUG") != ""
	errorLevel := clog.Severity_Warning
	if debugLogs {
		errorLevel = clog.Severity_Debug
	}
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	userID := protocol.NewID(uuid.New())

	serverPort := pickPort(t)
	serverLog := accessLogConfig(accessLog)
	serverLog.ErrorLogLevel = errorLevel
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(serverLog)},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(serverPort)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						SecurityType: serial.GetMessageType(&xtls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&xtls.Config{
								Certificate: []*xtls.Certificate{xtls.ParseCertificate(ct)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&vlessin.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}
	startInstance(t, "vision-server", serverConfig)

	clientPort := pickPort(t)
	clientAccessLog := accessLogPath(t, "vision-client-access.log")
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(accessLogConfig(clientAccessLog))},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(clientPort)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  xnet.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []xnet.Network{xnet.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vlessout.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings:     serial.ToTypedMessage(&transtcp.Config{}),
							},
						},
						SecurityType: serial.GetMessageType(&xtls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&xtls.Config{
								PinnedPeerCertSha256: [][]byte{ctHash[:]},
							}),
						},
					},
				}),
			},
		},
	}
	startInstance(t, "vision-client", clientConfig)

	conn := dialRetry(t, clientPort)
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := tlsConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	payload := randomPayload(payloadSize)
	if _, err := tlsConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, payloadSize)
	if _, err := io.ReadFull(tlsConn, response); err != nil {
		t.Fatal(err)
	}
	if err := tlsConn.Close(); err != nil { // sends close_notify
		t.Fatal(err)
	}
	conn.Close()

	records := waitAccessRecords(t, accessLog, 1)
	clientRecords := waitAccessRecords(t, clientAccessLog, 1)
	read, written := target.stableCounts()
	if read == 0 || written == 0 {
		t.Error("no traffic reached the TLS target")
	}
	record := records[0]
	clientRecord := clientRecords[0]
	// The server-side downlink must match the target's written bytes exactly:
	// the bytes are moved by the splice fast path and its compensation, and
	// are counted before the protocol layer adds its own framing.
	if record.downlink != written {
		t.Error("server record downlink does not match the target boundary. target ", written, ", record ", record.downlink)
	}
	// During the teardown, a single trailing 24-byte TLS-record-shaped control
	// or protocol record may be counted on one side of a boundary and dropped
	// on the other (the proxy may count it after its write failed, or the
	// peer may discard it after it was written), so a difference of 0 or
	// exactly 24 bytes is accepted; anything else is a real mismatch. Summing
	// the strace syscalls of the server on the target socket gives a total
	// within the same bound of the server record's uplink.
	if diff := record.uplink - read; diff != 0 && diff != 24 {
		t.Error("server record uplink does not match the target boundary. target ", read, ", record ", record.uplink)
	}
	if diff := clientRecord.uplink - read; diff != 0 && diff != 24 {
		t.Error("client record uplink does not match the target boundary. target ", read, ", record ", clientRecord.uplink)
	}
	if diff := clientRecord.downlink - written; diff != 0 && diff != 24 {
		t.Error("client record downlink does not match the target boundary. target ", written, ", record ", clientRecord.downlink)
	}
	assertNoMoreRecords(t, accessLog, 1)
	assertNoMoreRecords(t, clientAccessLog, 1)
}
