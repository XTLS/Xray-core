package dispatcher

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type sniffTestManager struct {
	outbound.Manager
	handler outbound.Handler
}

func (m *sniffTestManager) GetDefaultHandler() outbound.Handler { return m.handler }

type sniffTestHandler struct {
	outbound.Handler
	called   chan string
	finished chan []byte
}

func (h *sniffTestHandler) Tag() string { return "capture" }
func (h *sniffTestHandler) Dispatch(ctx context.Context, link *transport.Link) {
	ob := session.OutboundsFromContext(ctx)[0]
	target := ob.RouteTarget
	if !target.IsValid() {
		target = ob.Target
	}
	h.called <- target.Address.String()
	payload, _ := io.ReadAll(&buf.BufferedReader{Reader: link.Reader})
	h.finished <- payload
	common.Close(link.Writer)
}

func sniffTestContext(timeout time.Duration) context.Context {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	return session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled: true, RouteOnly: true, OverrideDestinationForProtocol: []string{"http", "tls"}, TLSSniffingTimeout: timeout,
	}})
}

func sniffFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../common/protocol/tls/testdata/" + name + ".bin")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func awaitSniffWorkers(t *testing.T, d *DefaultDispatcher) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for d.pendingTLSSniffs.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("pending sniffs leaked: %d", d.pendingTLSSniffs.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTLSRoutingBeforeDispatch(t *testing.T) {
	hello := sniffFixture(t, "clienthello")
	other := bytes.ReplaceAll(hello, []byte("www.youtube.com"), []byte("www.example.com"))
	noSNI := sniffFixture(t, "clienthello-no-sni")
	splitRecords := append([]byte{0x16, 3, 1, 0, 2}, hello[5:7]...)
	rest := len(hello) - 7
	splitRecords = append(splitRecords, 0x16, 3, 1, byte(rest>>8), byte(rest))
	splitRecords = append(splitRecords, hello[7:]...)
	for _, linkMode := range []bool{false, true} {
		mode := "Dispatch"
		if linkMode {
			mode = "DispatchLink"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				payload []byte
				delay   time.Duration
				chunk   int
				timeout time.Duration
				want    string
				cancel  bool
			}{
				{"immediate", hello, 0, 0, time.Second, "www.youtube.com", false},
				{"late", hello, 350 * time.Millisecond, 0, time.Second, "www.youtube.com", false},
				{"many reads", hello, 0, 1, time.Second, "www.youtube.com", false},
				{"multiple records", splitRecords, 0, 3, time.Second, "www.youtube.com", false},
				{"trailing bytes", append(bytes.Clone(hello), []byte("following application data")...), 0, 0, time.Second, "www.youtube.com", false},
				{"unselected", other, 0, 0, time.Second, "www.example.com", false},
				{"no SNI", noSNI, 0, 0, time.Second, "192.0.2.1", false},
				{"non TLS", []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"), 0, 0, time.Second, "www.example.com", false},
				{"EOF", nil, 0, 0, time.Second, "", false},
				{"partial EOF", hello[:10], 0, 0, time.Second, "", false},
				{"idle timeout", nil, 80 * time.Millisecond, 0, 30 * time.Millisecond, "", false},
				{"late beyond timeout", hello, 80 * time.Millisecond, 0, 30 * time.Millisecond, "", false},
				{"cancel", nil, 0, 0, time.Second, "", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					called := make(chan string, 1)
					finished := make(chan []byte, 1)
					manager := &sniffTestManager{handler: &sniffTestHandler{called: called, finished: finished}}
					d := &DefaultDispatcher{ohm: manager}
					ctx, cancel := context.WithCancel(sniffTestContext(tc.timeout))
					defer cancel()
					dest := net.TCPDestination(net.ParseAddress("192.0.2.1"), 443)
					var link *transport.Link
					if linkMode {
						upR, upW := pipe.New()
						downR, downW := pipe.New()
						link = &transport.Link{Reader: downR, Writer: upW}
						go func() {
							d.DispatchLink(ctx, dest, &transport.Link{Reader: upR, Writer: downW})
							// The inbound owns and closes its reader after DispatchLink returns.
							upR.Interrupt()
						}()
					} else {
						var err error
						link, err = d.Dispatch(ctx, dest)
						if err != nil {
							t.Fatal(err)
						}
					}
					defer common.Interrupt(link.Reader)
					defer common.Close(link.Writer)
					if tc.cancel {
						cancel()
					}
					if tc.delay > 0 {
						select {
						case tag := <-called:
							t.Fatalf("outbound %q opened before application data", tag)
						case <-time.After(tc.delay):
						}
					}
					chunk := tc.chunk
					if chunk == 0 {
						chunk = max(1, len(tc.payload))
					}
					for i := 0; i < len(tc.payload); i += chunk {
						err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, tc.payload[i:min(i+chunk, len(tc.payload))]))
						if err != nil && tc.want != "" {
							t.Fatal(err)
						}
					}
					common.Close(link.Writer)
					_, err := link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(2 * time.Second)
					if err == buf.ErrReadTimeout {
						t.Fatal("dispatcher did not finish")
					}
					if tc.want == "" {
						select {
						case tag := <-called:
							t.Fatalf("rejected flow dispatched to %q", tag)
						default:
						}
					} else {
						select {
						case result := <-finished:
							if target := <-called; target != tc.want || !bytes.Equal(result, tc.payload) {
								t.Fatalf("target=%s bytes=%d, want target=%s bytes=%d", target, len(result), tc.want, len(tc.payload))
							}
						case <-time.After(time.Second):
							t.Fatal("no outbound result")
						}
					}
					awaitSniffWorkers(t, d)
				})
			}
		})
	}
}

type sniffReadFunc func() (buf.MultiBuffer, error)

func (f sniffReadFunc) ReadMultiBuffer() (buf.MultiBuffer, error) { return f() }

func TestTLSReadOwnership(t *testing.T) {
	ctx := sniffTestContext(time.Second)
	dest := net.TCPDestination(net.ParseAddress("192.0.2.1"), 443)
	request := session.ContentFromContext(ctx).SniffingRequest
	t.Run("data and EOF", func(t *testing.T) {
		hello := sniffFixture(t, "clienthello")
		r := &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: sniffReadFunc(func() (buf.MultiBuffer, error) { return buf.MergeBytes(nil, hello), io.EOF })}}
		d := new(DefaultDispatcher)
		result, err := d.sniff(ctx, r, request, dest)
		if err != nil || result.Domain() != "www.youtube.com" {
			t.Fatalf("%v %v", result, err)
		}
		mb, err := r.ReadMultiBuffer()
		defer buf.ReleaseMulti(mb)
		got := make([]byte, mb.Len())
		mb.Copy(got)
		if err != nil || !bytes.Equal(got, hello) {
			t.Fatal("data returned with EOF was lost")
		}
		if _, err := r.ReadMultiBuffer(); err != io.EOF {
			t.Fatalf("terminal error lost: %v", err)
		}
		awaitSniffWorkers(t, d)
	})
	t.Run("cancel outstanding read", func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		late := buf.New()
		late.Write([]byte("late input"))
		r := &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: sniffReadFunc(func() (buf.MultiBuffer, error) { close(started); <-release; return buf.MultiBuffer{late}, nil })}}
		d := new(DefaultDispatcher)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := d.sniff(ctx, r, request, dest); done <- err }()
		<-started
		cancel()
		if err := <-done; errors.Cause(err) != errSniffingRejected {
			t.Fatalf("cancel: %v", err)
		}
		if d.pendingTLSSniffs.Load() != 1 {
			t.Fatal("outstanding reader no longer counts toward limit")
		}
		close(release)
		awaitSniffWorkers(t, d)
		if !late.IsEmpty() {
			t.Fatal("late read buffer not released")
		}
	})
	t.Run("overload", func(t *testing.T) {
		d := new(DefaultDispatcher)
		d.pendingTLSSniffs.Store(maxPendingTLSSniffs)
		_, err := d.sniff(ctx, nil, request, dest)
		if errors.Cause(err) != errSniffingRejected || d.pendingTLSSniffs.Load() != maxPendingTLSSniffs {
			t.Fatalf("overload: %v", err)
		}
	})
	t.Run("nil buffer on EOF", func(t *testing.T) {
		r := &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: sniffReadFunc(func() (buf.MultiBuffer, error) { return buf.MultiBuffer{nil}, io.EOF })}}
		d := new(DefaultDispatcher)
		_, err := d.sniff(ctx, r, request, dest)
		defer r.Interrupt()
		if errors.Cause(err) != errSniffingRejected {
			t.Fatalf("empty EOF: %v", err)
		}
		awaitSniffWorkers(t, d)
	})
	t.Run("prefix limit", func(t *testing.T) {
		// A valid record header repeatedly carries a ClientHello advertising a 16 MiB body.
		record := append([]byte{0x16, 3, 1, 0x40, 0}, make([]byte, 16384)...)
		copy(record[5:], []byte{1, 0xff, 0xff, 0xff})
		r := &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: sniffReadFunc(func() (buf.MultiBuffer, error) { return buf.MergeBytes(nil, record), nil })}}
		d := new(DefaultDispatcher)
		_, err := d.sniff(ctx, r, request, dest)
		defer r.Interrupt()
		if errors.Cause(err) != errSniffingRejected {
			t.Fatalf("oversized incomplete hello: %v", err)
		}
		awaitSniffWorkers(t, d)
	})
}

func TestTLSSniffScope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dest    net.Destination
		timeout time.Duration
	}{
		{"disabled", net.TCPDestination(net.ParseAddress("192.0.2.1"), 443), 0},
		{"other port", net.TCPDestination(net.ParseAddress("192.0.2.1"), 80), time.Second},
		{"known domain", net.TCPDestination(net.ParseAddress("www.example.com"), 443), time.Second},
		{"UDP", net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := sniffTestContext(tc.timeout)
			r := &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: sniffReadFunc(func() (buf.MultiBuffer, error) { return nil, io.EOF })}}
			d := new(DefaultDispatcher)
			_, err := d.sniff(ctx, r, session.ContentFromContext(ctx).SniffingRequest, tc.dest)
			if errors.Cause(err) == errSniffingRejected {
				t.Fatalf("strict policy escaped its scope: %v", err)
			}
			if d.pendingTLSSniffs.Load() != 0 {
				t.Fatal("non-strict flow used a pending slot")
			}
		})
	}
}

type sniffTestFakeDNS struct{ dns.FakeDNSEngine }

func (sniffTestFakeDNS) Type() interface{}                       { return (*dns.FakeDNSEngine)(nil) }
func (sniffTestFakeDNS) GetDomainFromFakeDNS(net.Address) string { return "www.youtube.com" }

func TestTLSSniffKnownFakeDNS(t *testing.T) {
	for _, useFakeDNS := range []bool{false, true} {
		ctx := sniffTestContext(time.Millisecond)
		dest := net.TCPDestination(net.ParseAddress("198.18.0.1"), 443)
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
		fakeDNS := sniffTestFakeDNS{}
		if err := core.MustFromContext(ctx).AddFeature(fakeDNS); err != nil {
			t.Fatal(err)
		}
		request := session.ContentFromContext(ctx).SniffingRequest
		if useFakeDNS {
			request.OverrideDestinationForProtocol = append(request.OverrideDestinationForProtocol, "fakedns")
		}
		r, w := pipe.New()
		defer r.Interrupt()
		defer w.Close()
		cached := &cachedReader{reader: r}
		d := &DefaultDispatcher{fdns: fakeDNS}
		result, err := d.sniff(ctx, cached, request, dest)
		if useFakeDNS {
			if err != nil || result.Domain() != "www.youtube.com" || !d.shouldOverride(ctx, result, request, dest) {
				t.Fatalf("usable FakeDNS mapping lost on timeout: %v %v", result, err)
			}
		} else if errors.Cause(err) != errSniffingRejected {
			t.Fatalf("unused FakeDNS mapping bypassed guard: %v", err)
		}
		r.Interrupt()
		awaitSniffWorkers(t, d)
	}
}
