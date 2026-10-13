package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const throughputPacketSize = 1200

func benchmarkBuffers(count, size int) ([][]byte, []int, []conn.Endpoint) {
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	return bufs, make([]int, count), make([]conn.Endpoint, count)
}

func newThroughputTUN(tb testing.TB) *netTun {
	tb.Helper()
	dev, _, s, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.1")}, nil, 1420, false)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { dev.Close() })
	CreateForwarder(s, func(c xnet.Conn, _ xnet.Destination) { c.Close() })
	CreateICMPEchoResponder(s)
	return dev.(*netTun)
}

func throughputEchoPacket() []byte {
	packet := make([]byte, throughputPacketSize)
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.ICMPv4ProtocolNumber),
		SrcAddr: tcpip.AddrFrom4([4]byte{10, 66, 0, 2}), DstAddr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	echo := header.ICMPv4(packet[header.IPv4MinimumSize:])
	echo.SetType(header.ICMPv4Echo)
	echo.SetIdent(123)
	echo.SetChecksum(header.ICMPv4Checksum(echo[:header.ICMPv4MinimumSize], checksum.Checksum(echo.Payload(), 0)))
	return packet
}

func BenchmarkNetTUNWriteRead(b *testing.B) {
	for _, batch := range []int{1, conn.IdealBatchSize} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			dev := newThroughputTUN(b)
			writes, _, _ := benchmarkBuffers(batch, throughputPacketSize)
			packet := throughputEchoPacket()
			ip := header.IPv4(packet)
			ip.SetDestinationAddress(tcpip.AddrFrom4([4]byte{10, 66, 0, 1}))
			ip.SetChecksum(0)
			ip.SetChecksum(^ip.CalculateChecksum())
			for i := range writes {
				copy(writes[i], packet)
			}
			reads, sizes, _ := benchmarkBuffers(dev.BatchSize(), 2048)
			done := make(chan error, 1)
			go func() {
				for range b.N {
					remaining := batch
					for remaining > 0 {
						n, err := dev.Read(reads, sizes, 0)
						if err != nil {
							done <- err
							return
						}
						remaining -= n
					}
					done <- nil
				}
			}()
			b.SetBytes(int64(batch * throughputPacketSize))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := dev.Write(writes, 0); err != nil {
					b.Fatal(err)
				}
				if err := <-done; err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.N*batch)/b.Elapsed().Seconds(), "packets/s")
		})
	}
}

func newThroughputBind(tb testing.TB, network, address string) (*bind, conn.ReceiveFunc, *net.UDPConn) {
	tb.Helper()
	udp, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		tb.Fatal(err)
	}
	udp.SetReadBuffer(4 << 20)
	udp.SetWriteBuffer(4 << 20)
	udp.SetDeadline(time.Now().Add(30 * time.Second))
	b := &bind{listenFunc: func() (net.PacketConn, error) { return udp, nil }}
	fns, _, err := b.Open(0)
	if err != nil {
		udp.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { b.Close() })
	return b, fns[0], udp
}

func BenchmarkBindUDP(b *testing.B) {
	for _, batch := range []int{1, conn.IdealBatchSize} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			sender, _, _ := newThroughputBind(b, "udp4", "127.0.0.1:0")
			receiver, receive, udp := newThroughputBind(b, "udp4", "127.0.0.1:0")
			port := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
			ep, err := sender.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
			if err != nil {
				b.Fatal(err)
			}
			writes, _, _ := benchmarkBuffers(batch, throughputPacketSize)
			reads, sizes, eps := benchmarkBuffers(receiver.BatchSize(), throughputPacketSize)
			done := make(chan error, 1)
			go func() {
				for range b.N {
					remaining := batch
					for remaining > 0 {
						n, err := receive(reads, sizes, eps)
						if err != nil {
							done <- err
							return
						}
						remaining -= n
					}
					done <- nil
				}
			}()
			b.SetBytes(int64(batch * throughputPacketSize))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := sender.Send(writes, ep); err != nil {
					b.Fatal(err)
				}
				if err := <-done; err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.N*batch)/b.Elapsed().Seconds(), "packets/s")
		})
	}
}

func newBenchmarkWireGuardDevices(tb testing.TB, tuns [2]tun.Device) {
	tb.Helper()
	var devs [2]*device.Device
	var ports [2]int
	var private, public [2][32]byte
	for i, tdev := range tuns {
		binding := &bind{listenFunc: func() (net.PacketConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}}
		devs[i] = device.NewDevice(tdev, binding, device.NewLogger(device.LogLevelError, ""))
		tb.Cleanup(devs[i].Close)
		private[i][0] = byte(8 * (i + 1))
		curve25519.ScalarBaseMult(&public[i], &private[i])
		if err := devs[i].IpcSet(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(private[i][:]))); err != nil {
			tb.Fatal(err)
		}
		if err := devs[i].Up(); err != nil {
			tb.Fatal(err)
		}
		cfg, err := devs[i].IpcGet()
		if err != nil {
			tb.Fatal(err)
		}
		for _, line := range strings.Split(cfg, "\n") {
			if value, ok := strings.CutPrefix(line, "listen_port="); ok {
				ports[i], err = strconv.Atoi(value)
				if err != nil {
					tb.Fatal(err)
				}
			}
		}
		if ports[i] == 0 {
			tb.Fatal("WireGuard did not publish a listening port")
		}
	}
	for i, dev := range devs {
		peer := 1 - i
		cfg := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.77.0.%d/32\n",
			hex.EncodeToString(public[peer][:]), ports[peer], peer+1)
		if err := dev.IpcSet(cfg); err != nil {
			tb.Fatal(err)
		}
	}
}

func acceptBenchmarkTCP(tb testing.TB, listener net.Listener, dial func(context.Context) (net.Conn, error)) (net.Conn, net.Conn) {
	tb.Helper()
	tb.Cleanup(func() { listener.Close() })
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := listener.Accept()
		accepted <- acceptResult{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dial(ctx)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { client.Close() })
	var server net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			tb.Fatal(result.err)
		}
		server = result.conn
	case <-ctx.Done():
		tb.Fatal(ctx.Err())
	}
	tb.Cleanup(func() { server.Close() })
	client.SetDeadline(time.Now().Add(30 * time.Second))
	server.SetDeadline(time.Now().Add(30 * time.Second))
	return client, server
}

func newWireGuardTCPPair(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()
	var tuns [2]tun.Device
	var xrayTuns [2]*netTun
	for i := range tuns {
		addresses := []netip.Addr{netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 1)})}
		tunDev, _, _, err := CreateNetTUN(addresses, nil, 1420, true)
		if err != nil {
			tb.Fatal(err)
		}
		tuns[i] = tunDev
		xrayTuns[i] = tunDev.(*netTun)
	}
	newBenchmarkWireGuardDevices(tb, tuns)
	address := netip.MustParseAddrPort("10.77.0.2:12345")
	listener, err := gonet.ListenTCP(xrayTuns[1].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 77, 0, 2}), Port: 12345}, header.IPv4ProtocolNumber)
	if err != nil {
		tb.Fatal(err)
	}
	return acceptBenchmarkTCP(tb, listener, func(ctx context.Context) (net.Conn, error) {
		return xrayTuns[0].DialContextTCPAddrPort(ctx, address)
	})
}

func benchmarkTCPStream(b *testing.B, client, server net.Conn) {
	payload := make([]byte, 64<<10)
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, server, int64(b.N)*int64(len(payload)))
		done <- err
	}()
	b.SetBytes(64 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		n, err := client.Write(payload)
		if err != nil {
			b.Fatal(err)
		}
		if n != len(payload) {
			b.Fatal(io.ErrShortWrite)
		}
	}
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
}

func BenchmarkWireGuardTCP(b *testing.B) {
	client, server := newWireGuardTCPPair(b)
	benchmarkTCPStream(b, client, server)
}

// Infer the key type so this benchmark also compiles against the old string map.
func benchmarkFlowMap[K comparable](map[K]*udpConn) map[K]*udpConn {
	return make(map[K]*udpConn)
}

func BenchmarkUDPManagerSteadyState(b *testing.B) {
	m := &udpManager{handler: func(xnet.Conn, xnet.Destination) {}}
	m.m = benchmarkFlowMap(m.m)
	src := xnet.UDPDestination(xnet.ParseAddress("10.66.0.2"), 1234)
	dst := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	payload := make([]byte, throughputPacketSize)
	m.feed(src, dst, payload)
	var uc *udpConn
	for _, flow := range m.m {
		uc = flow
	}
	uc.queue.pop()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.feed(src, dst, payload)
		uc.queue.pop()
	}
}

func BenchmarkWriteRawUDPPacket(b *testing.B) {
	dev := newThroughputTUN(b)
	// Drain the endpoint directly to avoid the blocking notification callback.
	dev.ep.RemoveNotify(dev.notifyHandle)
	m := &udpManager{stack: dev.stack}
	src := xnet.UDPDestination(xnet.ParseAddress("1.1.1.1"), 53)
	dst := xnet.UDPDestination(xnet.ParseAddress("10.66.0.2"), 1234)
	payload := make([]byte, throughputPacketSize)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := m.writeRawUDPPacket(payload, src, dst); err != nil {
			b.Fatal(err)
		}
		dev.ep.Drain()
	}
}
