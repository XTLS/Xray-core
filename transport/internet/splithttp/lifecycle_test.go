package splithttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestCloseReleasesConfigCache(t *testing.T) {
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	dest := net.TCPDestination(net.LocalHostIP, 18080)
	if _, _, err := getHTTPClient(context.Background(), dest, settings); err != nil {
		t.Fatal(err)
	}
	if err := settings.Close(); err != nil {
		t.Fatal(err)
	}
	globalDialerAccess.Lock()
	_, retained := globalDialerMap[dialerConf{dest, settings}]
	globalDialerAccess.Unlock()
	if retained {
		t.Fatal("closed stream settings still have an XHTTP cache entry")
	}
}

func TestDefaultClientCloseCancelsActiveRequest(t *testing.T) {
	canceled := make(chan struct{})
	started := make(chan struct{})
	stop := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-stop:
		}
	}))
	t.Cleanup(func() { close(stop); server.Close() })
	client := &DefaultDialerClient{transportConfig: &Config{}, client: server.Client(), httpVersion: "1.1"}
	body, _, _, err := client.OpenStream(context.Background(), server.URL, "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { body.Close() })
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the test server")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("closing the XHTTP client did not cancel its active request")
	}
}

func cacheEntriesFor(settings *internet.MemoryStreamConfig) int {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	var count int
	for key := range globalDialerMap {
		if key.MemoryStreamConfig == settings {
			count++
		}
	}
	return count
}

func TestCloseCacheIsolationAndDownloadSettings(t *testing.T) {
	config := &Config{}
	parent := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	other := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	download := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: config}
	parent.DownloadSettings = download
	t.Cleanup(func() { parent.Close(); other.Close() })
	for _, settings := range []*internet.MemoryStreamConfig{parent, other, download} {
		for _, port := range []net.Port{18081, 18082} {
			if _, _, err := getHTTPClient(context.Background(), net.TCPDestination(net.LocalHostIP, port), settings); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if cacheEntriesFor(parent) != 0 || cacheEntriesFor(download) != 0 || cacheEntriesFor(other) != 2 {
		t.Fatal("closing one config did not release only its upload and download destinations")
	}
	if !download.IsClosed() {
		t.Fatal("download config was not closed")
	}
	if _, _, err := getHTTPClient(context.Background(), net.TCPDestination(net.LocalHostIP, 18081), parent); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("closed config can recreate a cache entry: %v", err)
	}
}

func TestCloseCacheConcurrentDial(t *testing.T) {
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	dest := net.TCPDestination(net.LocalHostIP, 18083)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for range 20 {
		workers.Go(func() {
			<-start
			for range 20 {
				_, _, err := getHTTPClient(context.Background(), dest, settings)
				if err != nil && !errors.Is(err, stdnet.ErrClosed) {
					t.Errorf("unexpected acquisition error: %v", err)
				}
			}
		})
	}
	close(start)
	if err := settings.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if cacheEntriesFor(settings) != 0 {
		t.Fatal("a concurrent acquisition recreated the closed config's cache")
	}
}

type lifecycleXmuxConn struct{ closes atomic.Int32 }

func (c *lifecycleXmuxConn) IsClosed() bool { return c.closes.Load() != 0 }
func (c *lifecycleXmuxConn) Close() error   { c.closes.Add(1); return nil }

func TestCloseXmuxIncludesRetiredActiveClients(t *testing.T) {
	manager := NewXmuxManager(XmuxConfig{}, func() XmuxConn { return &lifecycleXmuxConn{} })
	retired := manager.GetXmuxClient(context.Background())
	retired.AddRunning()
	retired.LeftRequests.Store(0)
	current := manager.GetXmuxClient(context.Background())
	if current == retired || retired.XmuxConn.IsClosed() {
		t.Fatal("fixture did not retire an active client")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	retired.DoneRunning()
	manager.Close()
	for _, client := range []*XmuxClient{retired, current} {
		if client.XmuxConn.(*lifecycleXmuxConn).closes.Load() != 1 {
			t.Fatal("manager did not close a current or retired client exactly once")
		}
	}
	if manager.GetXmuxClient(context.Background()) != nil {
		t.Fatal("closed manager created another client")
	}
}

func TestClientCloseRawConnectionsAndLateReturn(t *testing.T) {
	client := &DefaultDialerClient{client: &http.Client{Transport: &http.Transport{}}}
	var peers []stdnet.Conn
	client.dialUploadConn = func(context.Context) (net.Conn, error) {
		conn, peer := stdnet.Pipe()
		peers = append(peers, peer)
		return client.ownConnection(conn)
	}
	first, _, err := client.takeUploadConnection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := client.takeUploadConnection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	client.returnUploadConnection(first)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	client.returnUploadConnection(second)
	for _, peer := range peers {
		defer peer.Close()
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("raw connection remained open: %v", err)
		}
	}
	client.access.Lock()
	defer client.access.Unlock()
	if len(client.connections) != 0 || len(client.uploadRawPool) != 0 {
		t.Fatal("closed client retained or re-pooled raw connections")
	}
}

func TestClientCloseRejectsLateDial(t *testing.T) {
	client := &DefaultDialerClient{client: &http.Client{Transport: &http.Transport{}}}
	started, release := make(chan struct{}), make(chan struct{})
	conn, peer := stdnet.Pipe()
	defer peer.Close()
	client.dialUploadConn = func(context.Context) (net.Conn, error) {
		close(started)
		<-release
		return client.ownConnection(conn)
	}
	result := make(chan error, 1)
	go func() { _, _, err := client.takeUploadConnection(context.Background()); result <- err }()
	<-started
	client.Close()
	close(release)
	if err := <-result; !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("late dial did not reject closed owner: %v", err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late dial connection remained open: %v", err)
	}
}

func TestDefaultClientCloseTLSRequests(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			started, canceled, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if protocol == "h2" && r.ProtoMajor != 2 {
					t.Errorf("expected H2, got %s", r.Proto)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(started)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-stopped:
				}
			}))
			server.EnableHTTP2 = protocol == "h2"
			server.StartTLS()
			t.Cleanup(func() { close(stopped); server.Close() })
			u, _ := url.Parse(server.URL)
			address, _ := stdnet.ResolveTCPAddr("tcp", u.Host)
			certificateHash := sha256.Sum256(server.Certificate().Raw)
			settings := &internet.MemoryStreamConfig{
				ProtocolName: protocolName, ProtocolSettings: &Config{}, SecurityType: "tls",
				SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}, NextProtocol: []string{protocol}, Fingerprint: "unsafe"},
			}
			client := createHTTPClient(net.TCPDestination(net.IPAddress(address.IP), net.Port(address.Port)), settings).(*DefaultDialerClient)
			t.Cleanup(func() { client.Close() })
			body, _, _, err := client.OpenStream(context.Background(), server.URL, "", nil, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { body.Close() })
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("TLS request did not reach server")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("TLS request remained active after Close")
			}
			client.access.Lock()
			defer client.access.Unlock()
			if len(client.connections) != 0 {
				t.Fatal("TLS TCP connection was retained")
			}
		})
	}
}

func TestDefaultClientCloseHTTP3Transport(t *testing.T) {
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName, ProtocolSettings: &Config{}, SecurityType: "tls",
		SecuritySettings: &tls.Config{NextProtocol: []string{"h3"}},
	}
	client := createHTTPClient(net.UDPDestination(net.LocalHostIP, 18084), settings).(*DefaultDialerClient)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://localhost/", nil)
	if _, err := client.client.Do(req); err == nil {
		t.Fatal("closed HTTP/3 transport accepted a request")
	}
}

func TestPacketUploadReservationSurvivesXmuxRotation(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan struct{}, 3)
			completed := make(chan struct{}, 3)
			canceled := make(chan struct{}, 3)
			release := make(chan struct{})
			var releaseOnce sync.Once
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				if _, err := io.ReadAll(r.Body); err != nil {
					return
				}
				started <- struct{}{}
				select {
				case <-release:
					w.WriteHeader(http.StatusOK)
					completed <- struct{}{}
				case <-r.Context().Done():
					canceled <- struct{}{}
				}
			}))
			server.EnableHTTP2 = protocol == "h2"
			server.StartTLS()
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); server.Close() })
			u, _ := url.Parse(server.URL)
			address, _ := stdnet.ResolveTCPAddr("tcp", u.Host)
			certificateHash := sha256.Sum256(server.Certificate().Raw)
			settings := &internet.MemoryStreamConfig{
				ProtocolName: protocolName,
				ProtocolSettings: &Config{
					Mode: "packet-up", ScMaxEachPostBytes: &RangeConfig{From: 10, To: 10},
					Xmux: &XmuxConfig{HMaxRequestTimes: &RangeConfig{From: 2, To: 2}},
				},
				SecurityType:     "tls",
				SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{certificateHash[:]}, NextProtocol: []string{protocol}, Fingerprint: "unsafe"},
			}
			t.Cleanup(func() { settings.Close() })
			conn, err := Dial(context.Background(), net.TCPDestination(net.IPAddress(address.IP), net.Port(address.Port)), settings)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			if _, err := conn.Write(bytes.Repeat([]byte("x"), 30)); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				select {
				case <-started:
				case <-canceled:
					t.Fatal("XMUX rotation canceled an outstanding upload")
				case <-time.After(3 * time.Second):
					t.Fatal("packet upload did not reach server")
				}
			}
			select {
			case <-canceled:
				t.Fatal("XMUX rotation canceled an outstanding upload")
			default:
			}
			releaseOnce.Do(func() { close(release) })
			for range 3 {
				select {
				case <-completed:
				case <-canceled:
					t.Fatal("XMUX rotation canceled an outstanding upload")
				case <-time.After(3 * time.Second):
					t.Fatal("packet upload did not complete")
				}
			}
		})
	}
}

func TestPacketUploadDiscardsInvalidHTTP1Response(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "non-200", true: "malformed"}[malformed], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				if malformed {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Write([]byte("not an HTTP response\r\n\r\n"))
					conn.Close()
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			address, _ := stdnet.ResolveTCPAddr("tcp", u.Host)
			settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
			client := createHTTPClient(net.TCPDestination(net.IPAddress(address.IP), net.Port(address.Port)), settings).(*DefaultDialerClient)
			defer client.Close()
			if err := client.PostPacket(context.Background(), server.URL, "session", "0", buf.MergeBytes(nil, []byte("payload"))); err == nil {
				t.Fatal("invalid upload response was accepted")
			}
			client.access.Lock()
			defer client.access.Unlock()
			if len(client.connections) != 0 || len(client.uploadRawPool) != 0 {
				t.Fatal("invalid response left a connection owned or reusable")
			}
		})
	}
}

type stagedLifecycleClient struct {
	open   func(io.Reader) (io.ReadCloser, error)
	closed atomic.Bool
}

func (c *stagedLifecycleClient) IsClosed() bool { return c.closed.Load() }
func (c *stagedLifecycleClient) Close() error   { c.closed.Store(true); return nil }
func (c *stagedLifecycleClient) OpenStream(_ context.Context, _, _ string, body io.Reader, _ bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	reader, err := c.open(body)
	return reader, nil, nil, err
}

func (c *stagedLifecycleClient) PostPacket(_ context.Context, _, _, _ string, payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	return nil
}

type lifecycleReadCloser struct{ closes atomic.Int32 }

func (c *lifecycleReadCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (c *lifecycleReadCloser) Close() error             { c.closes.Add(1); return nil }

func TestFailedStreamUpClosesOpenDownload(t *testing.T) {
	dest := net.TCPDestination(net.LocalHostIP, 18085)
	downloadDest := net.TCPDestination(net.LocalHostIP, 18086)
	download := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}, Destination: &downloadDest}
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName, ProtocolSettings: &Config{Mode: "stream-up", DownloadSettings: &internet.StreamConfig{}},
		DownloadSettings: download,
	}
	defer settings.Close()
	downBody := &lifecycleReadCloser{}
	var upBody io.Reader
	uploadClient := &stagedLifecycleClient{open: func(body io.Reader) (io.ReadCloser, error) { upBody = body; return nil, stdnet.ErrClosed }}
	downloadClient := &stagedLifecycleClient{open: func(io.Reader) (io.ReadCloser, error) { return downBody, nil }}
	uploadManager := NewXmuxManager(XmuxConfig{}, func() XmuxConn { return uploadClient })
	downloadManager := NewXmuxManager(XmuxConfig{}, func() XmuxConn { return downloadClient })
	globalDialerAccess.Lock()
	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}
	globalDialerMap[dialerConf{dest, settings}] = uploadManager
	globalDialerMap[dialerConf{downloadDest, download}] = downloadManager
	globalDialerAccess.Unlock()
	if _, err := Dial(context.Background(), dest, settings); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("fixture did not fail after opening download: %v", err)
	}
	if downBody.closes.Load() != 1 {
		t.Fatal("failed upload left its opened download alive")
	}
	if _, err := upBody.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed upload left its writer open")
	}
	for _, manager := range []*XmuxManager{uploadManager, downloadManager} {
		manager.access.Lock()
		for client := range manager.allClients {
			if client.Running.Load() != 0 {
				t.Errorf("failed Dial leaked %d request leases", client.Running.Load())
			}
		}
		manager.access.Unlock()
	}
}

func TestCallerCancellationKeepsOwnedRequestAlive(t *testing.T) {
	client := &DefaultDialerClient{client: &http.Client{Transport: &http.Transport{}}}
	ctx, cancelCaller := context.WithCancel(context.Background())
	requestCtx, release, err := client.requestContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cancelCaller()
	if err := requestCtx.Err(); err != nil {
		t.Fatalf("caller cancellation changed the existing transport lifetime: %v", err)
	}
	client.Close()
	select {
	case <-requestCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("owner Close did not cancel its request")
	}
}

func TestPacketUploadHonorsHTTP1ConnectionClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	address, _ := stdnet.ResolveTCPAddr("tcp", u.Host)
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	client := createHTTPClient(net.TCPDestination(net.IPAddress(address.IP), net.Port(address.Port)), settings).(*DefaultDialerClient)
	defer client.Close()
	for range 2 {
		if err := client.PostPacket(context.Background(), server.URL, "session", "0", buf.MergeBytes(nil, []byte("payload"))); err != nil {
			t.Fatal(err)
		}
		client.access.Lock()
		retained := len(client.connections) + len(client.uploadRawPool)
		client.access.Unlock()
		if retained != 0 {
			t.Fatal("Connection: close response was returned to the upload pool")
		}
	}
}

func TestXmuxSelectionReservesBeforeRetirement(t *testing.T) {
	manager := NewXmuxManager(XmuxConfig{CMaxReuseTimes: &RangeConfig{From: 1, To: 1}}, func() XmuxConn { return &lifecycleXmuxConn{} })
	defer manager.Close()
	first := manager.GetXmuxClientForRequest(context.Background())
	second := manager.GetXmuxClientForRequest(context.Background())
	if first == second || first.Running.Load() != 1 || first.XmuxConn.IsClosed() {
		t.Fatal("a selected request client was retired before its lease was held")
	}
	first.DoneRunning()
	if !first.XmuxConn.IsClosed() {
		t.Fatal("retired client did not close when its request completed")
	}
	second.DoneRunning()
}
