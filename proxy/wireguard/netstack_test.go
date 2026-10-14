package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	gonet "net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
)

type closeHandler struct{}

func (closeHandler) HandleConnection(conn net.Conn, _ net.Destination) { conn.Close() }

// onesSum is the Internet checksum of b on top of initial, not inverted.
func onesSum(b []byte, initial uint32) uint16 {
	sum := initial
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(binary.BigEndian.Uint16(b))
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

// The inbound answers ICMP echo requests from peers locally, the way the TUN
// inbound does: ICMP is not proxied, but ping and connectivity checks through
// the tunnel get a reply instead of timing out. The request goes in through
// Write and the reply comes out of Read, as the WireGuard device uses them.
func TestNetTUNEchoReply(t *testing.T) {
	for _, test := range []struct {
		src, dst string
		request  byte
		reply    byte
	}{
		{"10.66.0.2", "1.1.1.1", 8, 0},
		{"fd00::2", "2606:4700:4700::1111", 128, 129},
	} {
		dev, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.1"), netip.MustParseAddr("fd00::1")}, nil, 1420, closeHandler{})
		if err != nil {
			t.Fatal(err)
		}
		src, dst := netip.MustParseAddr(test.src), netip.MustParseAddr(test.dst)
		payload := []byte("xray wireguard ping")
		message := append([]byte{test.request, 0, 0, 0, 0x12, 0x34, 0, 7}, payload...)

		// The stack drops what has a wrong checksum, as what comes through a tunnel has come a long way.
		var pkt []byte
		if src.Is4() {
			pkt = make([]byte, 20, 20+len(message))
			pkt[0] = 0x45
			binary.BigEndian.PutUint16(pkt[2:], uint16(20+len(message)))
			pkt[8], pkt[9] = 64, 1
			copy(pkt[12:], src.AsSlice())
			copy(pkt[16:], dst.AsSlice())
			binary.BigEndian.PutUint16(pkt[10:], ^onesSum(pkt, 0))
			binary.BigEndian.PutUint16(message[2:], ^onesSum(message, 0))
		} else {
			pkt = make([]byte, 40, 40+len(message))
			pkt[0] = 0x60
			binary.BigEndian.PutUint16(pkt[4:], uint16(len(message)))
			pkt[6], pkt[7] = 58, 64
			copy(pkt[8:], src.AsSlice())
			copy(pkt[24:], dst.AsSlice())
			binary.BigEndian.PutUint16(message[2:], ^onesSum(message, uint32(onesSum(pkt[8:40], uint32(len(message))+58))))
		}
		pkt = append(pkt, message...)
		damaged := bytes.Clone(pkt)
		damaged[len(damaged)-1] ^= 1

		// The stack answers inside Write, the reply waits for whoever reads the device.
		got := make(chan []byte, 1)
		const offset = 16
		go func() {
			b := make([]byte, 2048)
			sizes := make([]int, 1)
			if _, err := dev.Read([][]byte{b}, sizes, offset); err == nil {
				got <- b[offset : offset+sizes[0]]
			}
		}()
		if _, err := dev.Write([][]byte{append(make([]byte, offset), damaged...), append(make([]byte, offset), pkt...)}, offset); err != nil {
			t.Fatal(err)
		}
		var reply []byte
		select {
		case reply = <-got:
		case <-time.After(2 * time.Second):
			t.Fatal("no echo reply from the stack")
		}

		header := len(pkt) - len(message)
		if len(reply) != len(pkt) || reply[0] != pkt[0] {
			t.Fatalf("reply of %d bytes, version byte %#x", len(reply), reply[0])
		}
		var replySrc, replyDst netip.Addr
		pseudo := uint32(0)
		if src.Is4() {
			replySrc, replyDst = netip.AddrFrom4([4]byte(reply[12:16])), netip.AddrFrom4([4]byte(reply[16:20]))
			if onesSum(reply[:20], 0) != 0xffff || reply[9] != 1 {
				t.Fatal("bad ipv4 header in the reply")
			}
		} else {
			replySrc, replyDst = netip.AddrFrom16([16]byte(reply[8:24])), netip.AddrFrom16([16]byte(reply[24:40]))
			if reply[6] != 58 {
				t.Fatalf("reply protocol %d, want icmpv6", reply[6])
			}
			pseudo = uint32(onesSum(reply[8:40], uint32(len(message))+58))
		}
		if replySrc != dst || replyDst != src {
			t.Fatalf("reply addresses %v -> %v, want %v -> %v", replySrc, replyDst, dst, src)
		}
		echo := reply[header:]
		if echo[0] != test.reply || echo[1] != 0 {
			t.Fatalf("reply type %d code %d, want echo reply", echo[0], echo[1])
		}
		// A reply to the damaged request, which came first, would not have this payload.
		if !bytes.Equal(echo[4:], message[4:]) {
			t.Fatalf("reply ident, seq and payload %x, want %x", echo[4:], message[4:])
		}
		if onesSum(echo, pseudo) != 0xffff {
			t.Fatal("bad icmp checksum in the reply")
		}

		dev.Close()
		dev.Close()
		if _, err := dev.Read([][]byte{make([]byte, 2048)}, make([]int, 1), 0); err == nil {
			t.Fatal("read from a closed device")
		}
	}
}

// testServer answers what comes through the device of a server: names over UDP port 53, except those that
// start with "silent", and everything else with what it was sent.
type testServer struct{}

func (testServer) HandleConnection(conn net.Conn, dest net.Destination) {
	defer conn.Close()
	b := make([]byte, 4096)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return
		}
		answer := b[:n]
		if dest.Network == net.Network_UDP && dest.Port == 53 {
			var parser dnsmessage.Parser
			header, err := parser.Start(b[:n])
			if err != nil {
				continue
			}
			question, err := parser.Question()
			if err != nil || strings.HasPrefix(question.Name.String(), "silent") {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
			builder.StartQuestions()
			builder.Question(question)
			builder.StartAnswers()
			builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
			if answer, err = builder.Finish(); err != nil {
				continue
			}
		}
		if _, err := conn.Write(answer); err != nil {
			return
		}
	}
}

// A client and a server, each with a stack on its device and the two devices joined as a tunnel joins them:
// names are resolved, and TCP and UDP go through, as the outbound and the inbound use them.
func TestNetTUNClientAndServer(t *testing.T) {
	server, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.1")}, nil, 1420, testServer{})
	if err != nil {
		t.Fatal(err)
	}
	client, tnet, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.2")}, []netip.Addr{netip.MustParseAddr("10.66.0.53")}, 1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()
	// As in a tunnel, what reads a device does not wait for the other end to take the packet: a stack answers
	// inside Write, and its answer has to be read meanwhile.
	for _, pair := range [][2]tun.Device{{client, server}, {server, client}} {
		packets := make(chan []byte, 1024)
		go func() {
			defer close(packets)
			bufs, sizes := [][]byte{make([]byte, 2048)}, make([]int, 1)
			for {
				if _, err := pair[0].Read(bufs, sizes, 0); err != nil {
					return
				}
				select {
				case packets <- bytes.Clone(bufs[0][:sizes[0]]):
				default:
				}
			}
		}()
		go func() {
			for packet := range packets {
				pair[1].Write([][]byte{packet}, 0)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if addrs, err := tnet.LookupContextHost(ctx, "xray.example"); err != nil || len(addrs) != 1 || addrs[0] != "192.0.2.1" {
		t.Fatal("resolved to ", addrs, ", error: ", err)
	}
	// a server that does not answer is not waited for longer than the one who asks wants to wait
	short, cancelShort := context.WithTimeout(ctx, 200*time.Millisecond)
	start := time.Now()
	var timeout *gonet.DNSError
	if addrs, err := tnet.LookupContextHost(short, "silent.example"); !errors.As(err, &timeout) || !timeout.IsTimeout || time.Since(start) > 3*time.Second {
		t.Fatal("resolved to ", addrs, " after ", time.Since(start), ", error: ", err)
	}
	cancelShort()

	sent := make([]byte, 1<<20)
	rand.Read(sent)
	for _, network := range []string{"tcp", "udp"} {
		conn, err := tnet.DialContext(ctx, network, "xray.example:7")
		if err != nil {
			t.Fatal(err)
		}
		size := len(sent)
		if network == "udp" {
			// more than the tunnel takes in one packet
			size = 3000
		}
		go conn.Write(sent[:size])
		received := make([]byte, size)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		done := make(chan error, 1)
		go func() {
			_, err := io.ReadFull(conn, received)
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil || !bytes.Equal(received, sent[:size]) {
				t.Fatal(network, ": received something else than what was sent, error: ", err)
			}
		case <-ctx.Done():
			t.Fatal(network, ": what was sent did not come back")
		}
		conn.Close()
	}
}

// A packet of the stack is in its hands only until WritePacket returns, Read gets it as it was then.
// A device that is closed is not waited for, also not by a stack that has something to send when it is closed.
func TestNetTUNWritePacket(t *testing.T) {
	dev, tnet, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.2")}, nil, 1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, sizes := make([]byte, 16), make([]int, 1)
	for i := range 1000 {
		header, payload := []byte{byte(i), 1, 2, 3}, []byte{4, 5, 6, byte(i)}
		go func() {
			dev.(*netTun).WritePacket(header, payload)
			clear(header)
			clear(payload)
		}()
		if _, err := dev.Read([][]byte{b}, sizes, 0); err != nil || !bytes.Equal(b[:sizes[0]], []byte{byte(i), 1, 2, 3, 4, 5, 6, byte(i)}) {
			t.Fatal("read ", b[:sizes[0]], " of packet ", i, ", error: ", err)
		}
	}

	// nobody reads now, and no more can wait to be read: a connection waits to send its SYN
	for range netTunQueue {
		dev.(*netTun).WritePacket([]byte{1}, nil)
	}
	dialed := make(chan error, 1)
	go func() {
		_, err := tnet.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("192.0.2.1:80"))
		dialed <- err
	}()
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		dev.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the device is not closed while a packet waits to be read")
	}
	if err := <-dialed; err == nil {
		t.Fatal("a connection through a closed device")
	}
}
