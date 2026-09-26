package shadowsocks_2022_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"errors"

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

	var dispatchCount atomic.Int32
	var receivedPackets [][]byte
	var mu sync.Mutex

	disp := &dummyDispatcher{
		onDispatch: func(ctx context.Context, d net.Destination) (*transport.Link, error) {
			dispatchCount.Add(1)
			linkR, linkW := gonet.Pipe()
			t.Cleanup(func() {
				linkW.Close()
				linkR.Close()
			})
			link := &transport.Link{
				Reader: buf.NewReader(linkR),
				Writer: &customWriter{
					write: func(mb buf.MultiBuffer) error {
						mu.Lock()
						defer mu.Unlock()
						for _, b := range mb {
							cpy := make([]byte, b.Len())
							copy(cpy, b.Bytes())
							receivedPackets = append(receivedPackets, cpy)
							b.Release()
						}
						return nil
					},
				},
			}
			return link, nil
		},
	}

	clientConn, serverConn := gonet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	inboundConn := &dummyStatConn{Conn: serverConn}
	ctx, cancel := context.WithCancel(newTestContext())
	defer cancel()

	go func() {
		_ = inbound.Process(ctx, net.Network_UDP, inboundConn, disp)
	}()

	// Send Packet 1
	_, err = clientConn.Write(pkt1)
	if err != nil {
		t.Fatalf("write pkt1 failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Send Packet 2 (same sessionID, packetID=2)
	_, err = clientConn.Write(pkt2)
	if err != nil {
		t.Fatalf("write pkt2 failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Check dispatch count: For the SAME UDP session, Dispatch MUST be called exactly ONCE!
	if count := dispatchCount.Load(); count != 1 {
		t.Fatalf("CRITICAL BUG CONFIRMED: expected dispatchCount = 1 for same session, got %d (sessionID was corrupted by Encrypt!)", count)
	}

	// Verify downstream destination can decode both packets
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)
	destCodec, err := NewUDPServerCodec(method, destKey, 300*time.Second)
	common.Must(err)

	mu.Lock()
	pkts := receivedPackets
	mu.Unlock()

	if len(pkts) != 2 {
		t.Fatalf("expected 2 received packets at destination, got %d", len(pkts))
	}

	dec1, err := destCodec.DecodePacket(pkts[0])
	if err != nil {
		t.Fatalf("dest failed to decode packet 1: %v", err)
	}
	if dec1.SessionID != sessionID || dec1.PacketID != 1 || string(dec1.Payload) != "xray packet 1" {
		t.Fatalf("dec1 mismatch: sess=%x, pktID=%d, payload=%s", dec1.SessionID, dec1.PacketID, string(dec1.Payload))
	}

	dec2, err := destCodec.DecodePacket(pkts[1])
	if err != nil {
		t.Fatalf("dest failed to decode packet 2: %v", err)
	}
	if dec2.SessionID != sessionID || dec2.PacketID != 2 || string(dec2.Payload) != "xray packet 2" {
		t.Fatalf("dec2 mismatch: sess=%x, pktID=%d, payload=%s", dec2.SessionID, dec2.PacketID, string(dec2.Payload))
	}
}

type customWriter struct {
	write func(mb buf.MultiBuffer) error
}

func (w *customWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.write(mb)
}

func (w *customWriter) Close() error {
	return nil
}

func (w *customWriter) Interrupt() {}

type dummyDispatcher struct {
	onDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *dummyDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if d.onDispatch != nil {
		return d.onDispatch(ctx, dest)
	}
	return nil, errors.New("not handled")
}

func (d *dummyDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return nil
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
