/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00,
	0x00, 0x20, 59, 64,
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48,
}

var (
	testSrc4 = netip.MustParseAddr("192.0.2.1")
	testDst4 = netip.MustParseAddr("198.51.100.1")
	testSrc6 = netip.MustParseAddr("2001:db8::1")
	testDst6 = netip.MustParseAddr("2001:db8:1::1")
)

func ipv4Packet(ttl, proto uint8, src, dst netip.Addr, options, payload []byte) []byte {
	hdrLen := ipv4.HeaderLen + len(options)
	b := make([]byte, hdrLen, hdrLen+len(payload))
	b[0] = 4<<4 | byte(hdrLen>>2)
	binary.BigEndian.PutUint16(b[2:4], uint16(hdrLen+len(payload)))
	b[8] = ttl
	b[9] = proto
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	copy(b[ipv4.HeaderLen:], options)
	return append(b, payload...)
}

func ipv6Packet(hopLimit, nextHeader uint8, src, dst netip.Addr, payload []byte) []byte {
	b := make([]byte, ipv6.HeaderLen, ipv6.HeaderLen+len(payload))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = nextHeader
	b[7] = hopLimit
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	return append(b, payload...)
}

func ipv4ChecksumValid(header []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return sum == 0xffff
}

type mockStream struct {
	streamID               quic.StreamID
	reading                []byte
	toRead                 <-chan []byte
	datagrams              <-chan []byte
	maxDatagramPayloadSize int
	sendDatagramErr        error
	sent                   [][]byte
	writeStarted           chan struct{}
	written                chan<- []byte
	readErr                error

	mu               sync.Mutex
	cancelWriteCodes []quic.StreamErrorCode
}

func (m *mockStream) cancelWriteCode() (quic.StreamErrorCode, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cancelWriteCodes) == 0 {
		return 0, false
	}
	return m.cancelWriteCodes[0], true
}

var _ http3Stream = &mockStream{}

func (m *mockStream) StreamID() quic.StreamID { return m.streamID }
func (m *mockStream) Read(p []byte) (int, error) {
	if len(m.reading) == 0 && m.readErr != nil {
		return 0, m.readErr
	}
	if len(m.reading) == 0 {
		m.reading = <-m.toRead
	}
	n := copy(p, m.reading)
	m.reading = m.reading[n:]
	return n, nil
}
func (m *mockStream) CancelRead(quic.StreamErrorCode) {}
func (m *mockStream) Write(p []byte) (int, error) {
	if m.writeStarted != nil {
		close(m.writeStarted)
		m.writeStarted = nil
	}
	if m.written != nil {
		m.written <- bytes.Clone(p)
	}
	return len(p), nil
}
func (m *mockStream) Close() error { return nil }
func (m *mockStream) CancelWrite(code quic.StreamErrorCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelWriteCodes = append(m.cancelWriteCodes, code)
}
func (m *mockStream) SetWriteDeadline(time.Time) error { return nil }
func (m *mockStream) SendDatagram(data []byte) error {
	if m.sendDatagramErr != nil {
		return m.sendDatagramErr
	}
	if size := quicvarint.Len(uint64(m.streamID/4)) + len(data); m.maxDatagramPayloadSize > 0 && size > m.maxDatagramPayloadSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(m.maxDatagramPayloadSize)}
	}
	m.sent = append(m.sent, bytes.Clone(data))
	return nil
}

func (m *mockStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data, ok := <-m.datagrams:
		if !ok {
			return nil, io.EOF
		}
		return data, nil
	}
}

func TestCapsuleWriteQueueLimit(t *testing.T) {
	writes := make(chan []byte)
	writeStarted := make(chan struct{})
	conn := newProxiedConn(&mockStream{
		writeStarted: writeStarted,
		written:      writes,
	})
	t.Cleanup(func() { conn.Close() })

	require.NoError(t, conn.AssignAddresses(nil))
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("capsule write did not start")
	}

	for range maxQueuedCapsules {
		require.NoError(t, conn.AssignAddresses(nil))
	}
	go func() {
		conn.Routes(context.Background())
		for range maxQueuedCapsules + 1 {
			<-writes
		}
	}()
	require.ErrorContains(t, conn.AssignAddresses(nil), "capsule queue full")
	require.ErrorIs(t, conn.AssignAddresses(nil), net.ErrClosed)
}

func TestCapsuleReceiveQueueLimit(t *testing.T) {
	for _, name := range []string{"assignments", "requests"} {
		t.Run(name, func(t *testing.T) {
			var data []byte
			for i := range maxQueuedCapsules + 1 {
				if name == "assignments" {
					data = (&addressAssignCapsule{}).append(data)
				} else {
					data = (&addressRequestCapsule{
						RequestIDs: []AddressRequestID{AddressRequestID(i + 1)},
						Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
					}).append(data)
				}
			}
			conn := newProxiedConn(&mockStream{reading: data})
			t.Cleanup(func() { conn.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := conn.Routes(ctx)
			require.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

func TestAbortErrorCode(t *testing.T) {
	var overflow []byte
	for range maxQueuedCapsules + 1 {
		overflow = (&addressAssignCapsule{}).append(overflow)
	}
	misordered := (&routeAdvertisementCapsule{IPAddressRanges: []IPRoute{
		{StartIP: netip.MustParseAddr("192.0.2.2"), EndIP: netip.MustParseAddr("192.0.2.1")},
	}}).append(nil)
	for _, c := range []struct {
		name string
		str  *mockStream
		code http3.ErrCode
	}{
		{"malformed capsule", &mockStream{reading: misordered}, http3.ErrCodeMessageError},
		{"queue limit", &mockStream{reading: overflow}, http3.ErrCodeExcessiveLoad},
		{"reset by peer", &mockStream{readErr: &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeNoError), Remote: true}}, http3.ErrCodeRequestCanceled},
		{"reset by peer on a request stream", &mockStream{readErr: &http3.Error{ErrorCode: http3.ErrCodeNoError, Remote: true}}, http3.ErrCodeRequestCanceled},
	} {
		t.Run(c.name, func(t *testing.T) {
			conn := newProxiedConn(c.str)
			t.Cleanup(func() { conn.Close() })
			require.Eventually(t, func() bool {
				_, ok := c.str.cancelWriteCode()
				return ok
			}, time.Second, time.Millisecond)
			code, _ := c.str.cancelWriteCode()
			require.Equal(t, quic.StreamErrorCode(c.code), code)
		})
	}
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty packets", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ip: empty packet",
		)
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: unknown IP versions: 5",
		)
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data[:ipv4.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("invalid source address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 11),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram source address not allowed: 192.168.0.11",
		)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3")},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		hdr.Dst = net.IPv4(10, 1, 2, 4)
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.4 (protocol: 0)",
		)
	})

	t.Run("invalid IP protocol", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
			Protocol: 42,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		hdr.Protocol = 41
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.3 (protocol: 41)",
		)

		hdr.Protocol = ipProtoICMP
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})

	t.Run("packet from assigned address", func(t *testing.T) {
		readChan := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: readChan})

		hdr := &ipv4.Header{
			Src:      net.IPv4(159, 70, 42, 98),
			Dst:      net.IPv4(192, 168, 0, 10),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.Error(t, conn.handleIncomingProxiedPacket(data), "connect-ip: datagram destination address")

		readChan <- (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.ReceiveAddressAssignment(ctx)
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})
}

func TestSkipUnknownCapsule(t *testing.T) {
	for _, typ := range []http3.CapsuleType{42, capsuleTypeDatagram} {
		readChan := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: readChan})

		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, 3)
		data = append(data, "foo"...)
		data = (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(data)
		readChan <- data

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		assigned, err := conn.ReceiveAddressAssignment(ctx)
		cancel()
		require.NoError(t, err, "capsule type %d", typ)
		require.Equal(t, []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}}, assigned)
		conn.Close()
	}
}

func FuzzIncomingDatagram(f *testing.F) {
	conn := newProxiedConn(&mockStream{})
	require.NoError(f, conn.AssignAddresses([]netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::0/64"),
	}))
	require.NoError(f, conn.AdvertiseRoute([]IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 42},
	}))

	ipv4Header, err := (&ipv4.Header{
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(159, 70, 42, 98),
		Len:      20,
		Checksum: 89,
	}).Marshal()
	require.NoError(f, err)

	f.Add(ipv4Header)
	f.Add(ipv6Header)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn.handleIncomingProxiedPacket(data)
	})
}

func TestSendingDatagrams(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4
		_, err := conn.composeDatagram(data)
		require.ErrorContains(t, err, "connect-ip: unknown IP versions: 5")
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		_, err = conn.composeDatagram(data[:ipv4.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv4 packet too short")
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		_, err := conn.composeDatagram(ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})
}

func TestWritePacketDropsWithoutSending(t *testing.T) {
	setIHL := func(b []byte, ihl byte) []byte { b[0] = 4<<4 | ihl; return b }
	setTotalLen := func(b []byte, l uint16) []byte { binary.BigEndian.PutUint16(b[2:4], l); return b }
	payload := make([]byte, 20)

	for _, tc := range []struct {
		name   string
		packet []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"IPv4 TTL 1", ipv4Packet(1, 17, testSrc4, testDst4, nil, payload)},
		{"IPv4 TTL 0", ipv4Packet(0, 17, testSrc4, testDst4, nil, payload)},
		{"IPv6 Hop Limit 1", ipv6Packet(1, 17, testSrc6, testDst6, payload)},
		{"IPv6 Hop Limit 0", ipv6Packet(0, 17, testSrc6, testDst6, payload)},
		{"IPv4 IHL below 5", setIHL(ipv4Packet(64, 17, testSrc4, testDst4, nil, payload), 4)},
		{"IPv4 IHL beyond total length", setIHL(ipv4Packet(64, 17, testSrc4, testDst4, nil, payload[:8]), 8)},
		{"IPv4 IHL beyond packet", setTotalLen(setIHL(ipv4Packet(64, 17, testSrc4, testDst4, nil, payload), 15), 60)},
		{"IPv4 total length beyond packet", setTotalLen(ipv4Packet(64, 17, testSrc4, testDst4, nil, payload), 41)},
		{"IPv4 total length below header", setTotalLen(ipv4Packet(64, 17, testSrc4, testDst4, nil, payload), 19)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			str := &mockStream{}
			conn := newProxiedConn(str)
			t.Cleanup(func() { conn.Close() })

			orig := bytes.Clone(tc.packet)
			icmpPacket, err := conn.WritePacket(tc.packet)
			require.NoError(t, err)
			require.Nil(t, icmpPacket)
			require.Empty(t, str.sent)
			require.Equal(t, orig, tc.packet, "dropped packets must not be modified")
		})
	}
}

func TestWritePacketIPv4Checksum(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []byte
	}{
		{"no options", nil},
		{"Router Alert option", []byte{0x94, 0x04, 0x00, 0x00}},
		{"maximum header length", bytes.Repeat([]byte{0x01}, 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			str := &mockStream{}
			conn := newProxiedConn(str)
			t.Cleanup(func() { conn.Close() })

			packet := ipv4Packet(64, 17, testSrc4, testDst4, tc.options, []byte("foobar"))
			icmpPacket, err := conn.WritePacket(packet)
			require.NoError(t, err)
			require.Nil(t, icmpPacket)
			require.Len(t, str.sent, 1)
			require.Equal(t, contextIDZero, str.sent[0][:len(contextIDZero)])
			sent := str.sent[0][len(contextIDZero):]
			require.Len(t, sent, len(packet))
			require.Equal(t, uint8(63), sent[8])
			require.True(t, ipv4ChecksumValid(sent[:ipv4.HeaderLen+len(tc.options)]))
		})
	}
}

func TestWritePacketTooLarge(t *testing.T) {
	for _, tc := range []struct {
		name            string
		streamID        quic.StreamID
		maxPayloadSize  int
		ipv6            bool
		wantMTU         int
		wantMTUTooSmall bool
	}{
		{name: "IPv4", maxPayloadSize: 1200, wantMTU: 1198},
		{name: "IPv4, 2-byte Quarter Stream ID", streamID: 4 * 64, maxPayloadSize: 1200, wantMTU: 1197},
		{name: "IPv4 minimum MTU", maxPayloadSize: 70, wantMTU: 68},
		{name: "IPv4 below minimum MTU", maxPayloadSize: 69, wantMTU: 67, wantMTUTooSmall: true},
		{name: "IPv6", maxPayloadSize: 1400, ipv6: true, wantMTU: 1398},
		{name: "IPv6, 4-byte Quarter Stream ID", streamID: 4 * 20000, maxPayloadSize: 1400, ipv6: true, wantMTU: 1395},
		{name: "IPv6 minimum MTU", maxPayloadSize: 1282, ipv6: true, wantMTU: 1280},
		{name: "IPv6 below minimum MTU", maxPayloadSize: 1281, ipv6: true, wantMTU: 1279, wantMTUTooSmall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			str := &mockStream{streamID: tc.streamID, maxDatagramPayloadSize: tc.maxPayloadSize}
			conn := newProxiedConn(str)
			t.Cleanup(func() { conn.Close() })

			packetOfSize := func(size int) []byte {
				if tc.ipv6 {
					return ipv6Packet(64, 17, testSrc6, testDst6, make([]byte, size-ipv6.HeaderLen))
				}
				return ipv4Packet(64, 17, testSrc4, testDst4, nil, make([]byte, size-ipv4.HeaderLen))
			}
			require.Equal(t, tc.wantMTU, conn.MaxPacketSize())

			icmpPacket, err := conn.WritePacket(packetOfSize(tc.wantMTU))
			require.NoError(t, err)
			require.Nil(t, icmpPacket)
			require.Len(t, str.sent, 1)

			icmpPacket, err = conn.WritePacket(packetOfSize(tc.wantMTU + 1))
			if tc.wantMTUTooSmall {
				require.ErrorIs(t, err, ErrMTUTooSmall)
				require.Nil(t, icmpPacket)
				return
			}
			require.NoError(t, err)
			if tc.ipv6 {
				msg, err := icmp.ParseMessage(ipProtoICMPv6, icmpPacket[ipv6.HeaderLen:])
				require.NoError(t, err)
				require.Equal(t, ipv6.ICMPTypePacketTooBig, msg.Type)
				require.Equal(t, tc.wantMTU, msg.Body.(*icmp.PacketTooBig).MTU)
			} else {
				msg := icmpPacket[ipv4.HeaderLen:]
				require.Equal(t, []byte{3, 4}, msg[:2])
				require.Equal(t, uint16(tc.wantMTU), binary.BigEndian.Uint16(msg[6:8]))
			}
		})
	}
}

func TestMaxPacketSize(t *testing.T) {
	t.Run("sends nothing", func(t *testing.T) {
		str := &mockStream{streamID: 8, maxDatagramPayloadSize: 1350}
		conn := newProxiedConn(str)
		t.Cleanup(func() { conn.Close() })
		require.Equal(t, 1348, conn.MaxPacketSize())
		require.Empty(t, str.sent)
	})

	t.Run("datagrams unsupported", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{sendDatagramErr: errors.New("datagram support disabled")})
		t.Cleanup(func() { conn.Close() })
		require.Zero(t, conn.MaxPacketSize())
	})

	t.Run("closed", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{maxDatagramPayloadSize: 1350})
		require.NoError(t, conn.Close())
		require.Zero(t, conn.MaxPacketSize())
	})
}

func TestReadPacketDropsMalformedDatagrams(t *testing.T) {
	packet := ipv4Packet(64, 17, testSrc4, testDst4, nil, []byte("foobar"))
	for _, tc := range []struct {
		name     string
		datagram []byte
	}{
		{"empty", []byte{}},
		{"truncated Context ID", []byte{0x40}},
		{"unknown Context ID", append([]byte{0x02}, packet...)},
		{"empty IP packet", []byte{0x00}},
		{"invalid IP packet", []byte{0x00, 0x50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			datagrams := make(chan []byte, 2)
			conn := newProxiedConn(&mockStream{datagrams: datagrams})
			t.Cleanup(func() { conn.Close() })
			require.NoError(t, conn.AdvertiseRoute([]IPRoute{
				{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255")},
			}))

			datagrams <- tc.datagram
			datagrams <- append(bytes.Clone(contextIDZero), packet...)
			b := make([]byte, 1500)
			n, err := conn.ReadPacket(b)
			require.NoError(t, err)
			require.Equal(t, packet, b[:n])
		})
	}
}

func TestReadPacketShortBuffer(t *testing.T) {
	datagrams := make(chan []byte, 3)
	conn := newProxiedConn(&mockStream{datagrams: datagrams})
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.AdvertiseRoute([]IPRoute{
		{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255")},
	}))

	packet := ipv4Packet(64, 17, testSrc4, testDst4, nil, []byte("foobar"))
	for range 3 {
		datagrams <- append(bytes.Clone(contextIDZero), packet...)
	}
	n, err := conn.ReadPacket(make([]byte, len(packet)-1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
	require.Zero(t, n)

	b := make([]byte, len(packet))
	n, err = conn.ReadPacket(b)
	require.NoError(t, err)
	require.Equal(t, packet, b[:n])
	n, err = conn.ReadPacket(make([]byte, 1500))
	require.NoError(t, err)
	require.Equal(t, len(packet), n)
}

func TestCloseConcurrently(t *testing.T) {
	for _, side := range []string{"client", "proxy"} {
		t.Run(side, func(t *testing.T) {
			client, server := setupConns(t)
			conn := client
			if side == "proxy" {
				conn = server
			}

			readErr := make(chan error, 1)
			go func() {
				b := make([]byte, 1500)
				for {
					if _, err := conn.ReadPacket(b); err != nil {
						readErr <- err
						return
					}
				}
			}()
			writeErr := make(chan error, 1)
			go func() {
				for {
					if _, err := conn.WritePacket(ipv4Packet(64, 17, testSrc4, testDst4, nil, nil)); err != nil {
						writeErr <- err
						return
					}
				}
			}()

			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() { assert.NoError(t, conn.Close()) })
			}
			wg.Wait()
			for _, errChan := range []chan error{readErr, writeErr} {
				select {
				case err := <-errChan:
					require.ErrorIs(t, err, net.ErrClosed)
				case <-time.After(5 * time.Second):
					t.Fatal("timeout")
				}
			}
			require.NoError(t, conn.Close())
		})
	}
}
