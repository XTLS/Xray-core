package shadowsocks_2022_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	. "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/transport"
	"lukechampine.com/blake3"
)

// encodeRelayClientUDPPacket encodes a Shadowsocks-2022 UDP packet with 1 layer of EIH (Relay)
func encodeRelayClientUDPPacket(relayKey, destKey []byte, sessionID, packetID uint64, dest net.Destination, payload []byte) ([]byte, error) {
	method, err := GetCipherMethod(MethodAES128GCM)
	if err != nil {
		return nil, err
	}
	relayBlock, err := method.NewBlock(relayKey)
	if err != nil {
		return nil, err
	}

	// 1. Plain packet header: sessionID (8B) + packetID (8B)
	var rawHeader [16]byte
	binary.BigEndian.PutUint64(rawHeader[:8], sessionID)
	binary.BigEndian.PutUint64(rawHeader[8:16], packetID)

	// Encrypt packetHeader under relayKey
	var encPacketHeader [16]byte
	relayBlock.Encrypt(encPacketHeader[:], rawHeader[:])

	// 2. EI Header: blake3(destKey)[:16] ^ rawHeader
	var destHash [16]byte
	hash512 := blake3.Sum512(destKey)
	copy(destHash[:], hash512[:16])

	var eiHeader [16]byte
	for i := 0; i < 16; i++ {
		eiHeader[i] = destHash[i] ^ rawHeader[i]
	}
	var encEIHeader [16]byte
	relayBlock.Encrypt(encEIHeader[:], eiHeader[:])

	// 3. Payload under destination server's AEAD
	bodyKey := DeriveSessionSubKey(destKey, rawHeader[:8], 16)
	bodyAead, err := method.NewAEAD(bodyKey)
	if err != nil {
		return nil, err
	}
	bodyNonce := rawHeader[4:16]

	outBuf := buf.New()
	defer outBuf.Release()

	// VarHeader: client type (1) + timestamp (8) + paddingLen (2) + padding + dest + payload
	var hdr [1 + 8 + 2]byte
	hdr[0] = HeaderTypeClient
	binary.BigEndian.PutUint64(hdr[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(hdr[9:11], 0)
	outBuf.Write(hdr[:])

	if err := WriteAddressPort(outBuf, dest); err != nil {
		return nil, err
	}
	outBuf.Write(payload)

	plainBytes := outBuf.Bytes()
	outBuf.Extend(int32(bodyAead.Overhead()))
	bodyAead.Seal(plainBytes[:0], bodyNonce, plainBytes, nil)

	// Full packet: encPacketHeader (16B) + encEIHeader (16B) + sealedBody
	packet := make([]byte, 0, 32+outBuf.Len())
	packet = append(packet, encPacketHeader[:]...)
	packet = append(packet, encEIHeader[:]...)
	packet = append(packet, outBuf.Bytes()...)
	return packet, nil
}

func TestRelayUDPSessionStabilityAndDispatch(t *testing.T) {
	relayKey := []byte("0123456789abcdef")
	destKey := []byte("fedcba9876543210")
	relayKeyB64 := base64.StdEncoding.EncodeToString(relayKey)
	destKeyB64 := base64.StdEncoding.EncodeToString(destKey)

	config := &RelayServerConfig{
		Method: MethodAES128GCM,
		Key:    relayKeyB64,
		Destinations: []*RelayDestination{
			{
				Key:     destKeyB64,
				Address: &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: []byte{127, 0, 0, 1}}},
				Port:    8388,
				Email:   "dest@example.com",
			},
		},
	}

	inbound, err := NewRelayServer(newTestContext(), config)
	if err != nil {
		t.Fatalf("failed to create RelayServer: %v", err)
	}

	sessionID := uint64(0x1122334455667788)
	dest := net.UDPDestination(net.LocalHostIP, 8388)

	pkt1, err := encodeRelayClientUDPPacket(relayKey, destKey, sessionID, 1, dest, []byte("xray packet 1"))
	if err != nil {
		t.Fatalf("failed to encode pkt1: %v", err)
	}
	pkt2, err := encodeRelayClientUDPPacket(relayKey, destKey, sessionID, 2, dest, []byte("xray packet 2"))
	if err != nil {
		t.Fatalf("failed to encode pkt2: %v", err)
	}

	ctx, cancel := context.WithTimeout(newTestContext(), 3*time.Second)
	defer cancel()
	var dispatchCount atomic.Int32
	packets := make(chan []byte, 2)
	reply := make(chan struct{})
	routeDone := make(chan error, 1)
	disp := &dummyDispatcher{
		onDispatch: func(_ context.Context, d net.Destination, link *transport.Link) (err error) {
			defer func() { routeDone <- err }()
			dispatchCount.Add(1)
			if d != dest {
				return errors.New("unexpected relay UDP destination")
			}
			for received := 0; received < 2; {
				mb, err := link.Reader.ReadMultiBuffer()
				if err != nil {
					buf.ReleaseMulti(mb)
					return err
				}
				if len(mb) > 2-received {
					buf.ReleaseMulti(mb)
					return errors.New("received duplicate relay UDP data")
				}
				for _, packet := range mb {
					packets <- bytes.Clone(packet.Bytes())
					received++
				}
				buf.ReleaseMulti(mb)
			}
			select {
			case <-reply:
				return link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("reply at the second peer")))
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}

	startPeer := func() (gonet.Conn, <-chan struct{}) {
		client, server := gonet.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			_ = inbound.Process(ctx, net.Network_UDP, &dummyStatConn{Conn: server}, disp)
		}()
		t.Cleanup(func() {
			client.Close()
			<-done
		})
		return client, done
	}
	readPacket := func() []byte {
		t.Helper()
		select {
		case packet := <-packets:
			return packet
		case <-ctx.Done():
			t.Fatal("did not dispatch a relay packet")
			return nil
		}
	}

	first, firstDone := startPeer()
	if _, err := first.Write(pkt1); err != nil {
		t.Fatalf("write pkt1 failed: %v", err)
	}
	firstPacket := readPacket()
	first.Close()
	<-firstDone

	second, _ := startPeer()
	if _, err := second.Write(pkt2); err != nil {
		t.Fatalf("write pkt2 failed: %v", err)
	}
	secondPacket := readPacket()
	close(reply)
	p := make([]byte, len("reply at the second peer"))
	if _, err := io.ReadFull(second, p); err != nil || string(p) != "reply at the second peer" {
		t.Fatalf("read rebound reply: %q, %v", p, err)
	}
	if err := <-routeDone; err != nil {
		t.Fatal(err)
	}
	if count := dispatchCount.Load(); count != 1 {
		t.Fatalf("expected one route for the same session after reattachment, got %d", count)
	}

	// Verify downstream destination can decode both packets
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)
	destCodec, err := NewUDPServerCodec(method, destKey, nil, 300*time.Second)
	common.Must(err)

	pkts := [][]byte{firstPacket, secondPacket}

	dec1, dec2 := DecodedUDPPacket{}, DecodedUDPPacket{}
	_, dec1, err = destCodec.DecodePacket(pkts[0])
	if err != nil {
		t.Fatalf("dest failed to decode packet 1: %v", err)
	}
	if dec1.SessionID != sessionID || dec1.PacketID != 1 || string(dec1.Payload) != "xray packet 1" {
		t.Fatalf("dec1 mismatch: sess=%x, pktID=%d, payload=%s", dec1.SessionID, dec1.PacketID, string(dec1.Payload))
	}

	_, dec2, err = destCodec.DecodePacket(pkts[1])
	if err != nil {
		t.Fatalf("dest failed to decode packet 2: %v", err)
	}
	if dec2.SessionID != sessionID || dec2.PacketID != 2 || string(dec2.Payload) != "xray packet 2" {
		t.Fatalf("dec2 mismatch: sess=%x, pktID=%d, payload=%s", dec2.SessionID, dec2.PacketID, string(dec2.Payload))
	}
}

type dummyDispatcher struct {
	onDispatch func(context.Context, net.Destination, *transport.Link) error
}

func (d *dummyDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return d.onDispatch(ctx, dest, link)
}

func (d *dummyDispatcher) Start() error      { return nil }
func (d *dummyDispatcher) Close() error      { return nil }
func (d *dummyDispatcher) Type() interface{} { return routing.DispatcherType() }

type dummyStatConn struct {
	gonet.Conn
}

func (c *dummyStatConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, err := b.ReadFrom(c.Conn)
	return buf.MultiBuffer{b}, err
}

func (c *dummyStatConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if _, err := c.Conn.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func TestRelayTCPHandshakeForwarding(t *testing.T) {
	methods := []string{MethodAES128GCM, MethodAES256GCM}
	for _, methodName := range methods {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)

			relayKey := make([]byte, method.KeySaltLength)
			destKey := make([]byte, method.KeySaltLength)
			_, _ = io.ReadFull(rand.Reader, relayKey)
			_, _ = io.ReadFull(rand.Reader, destKey)

			targetPort := uint32(54321)
			relayConfig := &RelayServerConfig{
				Method: methodName,
				Key:    base64.StdEncoding.EncodeToString(relayKey),
				Destinations: []*RelayDestination{
					{
						Key:     base64.StdEncoding.EncodeToString(destKey),
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    targetPort,
						Email:   "test@xray.com",
					},
				},
			}

			testCtx := newTestContext()
			inbound, err := NewRelayServer(testCtx, relayConfig)
			common.Must(err)

			targetDest := net.TCPDestination(net.LocalHostIP, net.Port(targetPort))

			first := make(chan []byte, 1)
			next := make(chan []byte, 1)
			disp := &dummyDispatcher{
				onDispatch: func(_ context.Context, dest net.Destination, link *transport.Link) error {
					if dest != targetDest {
						return errors.New("unexpected relay TCP destination")
					}
					for _, result := range []chan []byte{first, next} {
						mb, err := link.Reader.ReadMultiBuffer()
						if err != nil {
							buf.ReleaseMulti(mb)
							return err
						}
						data := make([]byte, mb.Len())
						mb.Copy(data)
						buf.ReleaseMulti(mb)
						result <- data
					}
					return nil
				},
			}

			clientConn, relayConn := gonet.Pipe()
			defer clientConn.Close()
			defer relayConn.Close()
			clientConn.SetDeadline(time.Now().Add(time.Second))
			ctx, cancel := context.WithTimeout(testCtx, 3*time.Second)
			defer cancel()
			processDone := make(chan error, 1)
			go func() {
				processDone <- inbound.Process(ctx, net.Network_TCP, &dummyStatConn{Conn: relayConn}, disp)
			}()

			clientSalt := make([]byte, method.KeySaltLength)
			_, _ = io.ReadFull(rand.Reader, clientSalt)
			pskList := [][]byte{relayKey, destKey}
			if _, err := WriteTCPRequest(clientConn, method, pskList, targetDest, clientSalt, []byte("relay payload")); err != nil {
				t.Fatalf("WriteTCPRequest failed: %v", err)
			}
			var wire []byte
			select {
			case wire = <-first:
			case err := <-processDone:
				t.Fatalf("relay ended before forwarding the first record: %v", err)
			case <-ctx.Done():
				t.Fatal("timed out waiting for the first downstream record")
			}

			// The downstream must receive the complete forwarded handshake as its first read.
			headerLen := method.KeySaltLength + RequestHeaderFixedChunkLength + AEADTagSize
			if len(wire) < headerLen || !bytes.Equal(wire[:method.KeySaltLength], clientSalt) {
				t.Fatalf("unexpected forwarded handshake length or salt: %d bytes", len(wire))
			}
			sessionKey := DeriveSessionSubKey(destKey, clientSalt, method.KeySaltLength)
			aead, err := method.NewAEAD(sessionKey)
			common.Must(err)
			reader := NewStreamReader(bytes.NewReader(wire[headerLen:]), aead)
			reqHeader, err := ReadClientRequestHeaderWithFixed(reader, wire[method.KeySaltLength:headerLen])
			if err != nil {
				t.Fatalf("downstream failed to parse client request header: %v", err)
			}
			if reqHeader.Destination != targetDest || string(reqHeader.EarlyData) != "relay payload" {
				t.Fatalf("unexpected forwarded destination or payload: %s %q", reqHeader.Destination, reqHeader.EarlyData)
			}

			if _, err := io.WriteString(clientConn, "later bytes"); err != nil {
				t.Fatal(err)
			}
			select {
			case more := <-next:
				if string(more) != "later bytes" {
					t.Fatalf("expected only subsequent stream bytes, got %q", more)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for subsequent stream bytes")
			}
			if err := <-processDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
