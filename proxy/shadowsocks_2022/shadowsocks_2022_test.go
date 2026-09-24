package shadowsocks_2022_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	. "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func newTestContext() context.Context {
	v, err := core.New(&core.Config{})
	common.Must(err)
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{})
	return ctx
}

func generateRandomKey(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestKDF(t *testing.T) {
	// Test ParseKey
	if _, err := ParseKey("", 16); err != ErrBadKey {
		t.Fatalf("expected ErrBadKey for empty key, got %v", err)
	}

	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := ParseKey(shortKey, 16); err != ErrBadKey {
		t.Fatalf("expected ErrBadKey for short key, got %v", err)
	}

	exactKey := []byte("0123456789abcdef")
	exactKeyB64 := base64.StdEncoding.EncodeToString(exactKey)
	normExact, err := ParseKey(exactKeyB64, 16)
	if err != nil || !bytes.Equal(normExact, exactKey) {
		t.Fatalf("unexpected parsed exact key: %v, err: %v", normExact, err)
	}

	longKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef_longer_key_for_testing"))
	if _, err := ParseKey(longKey, 16); err != ErrBadKey {
		t.Fatalf("expected ErrBadKey for long key, got %v", err)
	}

	// Test Session Subkey determinism
	salt := []byte("random_salt_1234")
	k1 := DeriveSessionSubKey(normExact, salt, 16)
	k2 := DeriveSessionSubKey(normExact, salt, 16)
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveSessionSubKey should be deterministic")
	}

	// Identity subkey must differ from session subkey with same inputs
	idKey := DeriveIdentitySubKey(normExact, salt, 16)
	if bytes.Equal(k1, idKey) {
		t.Fatal("DeriveIdentitySubKey must differ from DeriveSessionSubKey")
	}

	// User PSK hash
	h1 := DeriveUserPSKHash(normExact)
	h2 := DeriveUserPSKHash(normExact)
	if h1 != h2 {
		t.Fatal("DeriveUserPSKHash should be deterministic")
	}
}

func TestReplayFilter(t *testing.T) {
	filter := antireplay.NewMapFilter[string](60)

	salt1 := []byte("test_salt_111111")
	salt2 := []byte("test_salt_222222")

	if !filter.Check(string(salt1)) {
		t.Fatal("first check on salt1 should be true")
	}
	if filter.Check(string(salt1)) {
		t.Fatal("second check on salt1 should be false (replay detected)")
	}

	if !filter.Check(string(salt2)) {
		t.Fatal("first check on salt2 should be true")
	}

	// Test SlidingWindow
	var window SlidingWindow
	if !window.Check(1) {
		t.Fatal("packet 1 should be accepted")
	}
	window.Add(1)

	if window.Check(1) {
		t.Fatal("duplicate packet 1 should be rejected")
	}

	if !window.Check(100) {
		t.Fatal("packet 100 should be accepted")
	}
	window.Add(100)

	if window.Check(100) {
		t.Fatal("duplicate packet 100 should be rejected")
	}

	if !window.Check(50) {
		t.Fatal("out-of-order packet 50 within window should be accepted")
	}
	window.Add(50)
	if window.Check(50) {
		t.Fatal("duplicate packet 50 should be rejected")
	}

	// Check packet far behind window (> 8128)
	window.Add(10000)
	if window.Check(1) {
		t.Fatal("packet 1 should be rejected as behind window")
	}
}

func TestTCPStreamAndHandshake(t *testing.T) {
	methods := []struct {
		name    string
		keySize int
	}{
		{MethodAES128GCM, 16},
		{MethodAES256GCM, 32},
		{MethodChaCha20Poly1305, 32},
	}

	dest := net.TCPDestination(net.LocalHostIP, net.Port(8080))
	testPayload := []byte("Hello, Shadowsocks 2022 Native Implementation!")

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			rawKey := make([]byte, m.keySize)
			_, _ = rand.Read(rawKey)
			method, err := GetCipherMethod(m.name)
			common.Must(err)

			clientConn, serverConn := gonet.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			var wg sync.WaitGroup
			wg.Add(2)

			var receivedDest net.Destination
			var receivedPayload []byte

			// Server goroutine
			go func() {
				defer wg.Done()
				salt := make([]byte, method.KeySaltLength)
				_, err := io.ReadFull(serverConn, salt)
				common.Must(err)

				sessionKey := DeriveSessionSubKey(rawKey, salt, method.KeySaltLength)
				aead, err := method.NewAEAD(sessionKey)
				common.Must(err)

				reader := NewStreamReader(serverConn, aead)

				// Read fixed chunk (11 + 16 bytes)
				var fixedBuf [RequestHeaderFixedChunkLength + AEADTagSize]byte
				_, err = io.ReadFull(serverConn, fixedBuf[:])
				common.Must(err)

				plainFixed, err := aead.Open(fixedBuf[:0], reader.Nonce(), fixedBuf[:], nil)
				common.Must(err)
				IncreaseNonce(reader.Nonce())
				if plainFixed[0] != HeaderTypeClient {
					t.Errorf("expected client header type, got %d", plainFixed[0])
				}

				// Read variable chunk
				varLen := int(plainFixed[9])<<8 | int(plainFixed[10])
				varBuf := make([]byte, varLen+AEADTagSize)
				_, err = io.ReadFull(serverConn, varBuf)
				common.Must(err)

				plainVar, err := aead.Open(varBuf[:0], reader.Nonce(), varBuf, nil)
				common.Must(err)
				IncreaseNonce(reader.Nonce())

				vBuf := buf.New()
				vBuf.Write(plainVar)
				receivedDest, err = ReadAddressPort(vBuf)
				common.Must(err)

				// Skip padding
				var padBytes [2]byte
				_, _ = vBuf.Read(padBytes[:])
				padLen := int(padBytes[0])<<8 | int(padBytes[1])
				vBuf.Advance(int32(padLen))

				receivedPayload = make([]byte, vBuf.Len())
				copy(receivedPayload, vBuf.Bytes())
				vBuf.Release()

				// Server sends response handshake
				serverSalt := make([]byte, method.KeySaltLength)
				_, _ = rand.Read(serverSalt)
				respKey := DeriveSessionSubKey(rawKey, serverSalt, method.KeySaltLength)
				respAead, err := method.NewAEAD(respKey)
				writer := NewStreamWriter(serverConn, respAead)
				_, _ = serverConn.Write(serverSalt)

				fixedResp := make([]byte, 1+8+method.KeySaltLength+2)
				fixedResp[0] = HeaderTypeServer
				binary.BigEndian.PutUint64(fixedResp[1:9], uint64(time.Now().Unix()))
				copy(fixedResp[9:9+method.KeySaltLength], salt)
				binary.BigEndian.PutUint16(fixedResp[9+method.KeySaltLength:11+method.KeySaltLength], 0)

				fixedChunk := respAead.Seal(nil, writer.Nonce(), fixedResp, nil)
				IncreaseNonce(writer.Nonce())
				_, _ = serverConn.Write(fixedChunk)

				// Echo stream data
				mb, err := reader.ReadMultiBuffer()
				common.Must(err)
				_ = writer.WriteMultiBuffer(mb)
			}()

			// Client goroutine
			go func() {
				defer wg.Done()
				clientSalt, writer, err := ClientHandshake(clientConn, method, [][]byte{rawKey}, dest, testPayload)
				common.Must(err)

				reader, _, err := ClientVerifyServerResponse(clientConn, method, rawKey, clientSalt)
				common.Must(err)

				// Send additional stream data
				streamData := []byte("stream chunk test")
				_ = writer.WriteChunk(streamData)

				mb, err := reader.ReadMultiBuffer()
				common.Must(err)
				if !bytes.Equal(mb[0].Bytes(), streamData) {
					t.Errorf("echoed stream data mismatch: got %s, want %s", mb[0].Bytes(), streamData)
				}
				buf.ReleaseMulti(mb)
			}()

			wg.Wait()

			if receivedDest.NetAddr() != dest.NetAddr() {
				t.Errorf("destination mismatch: got %s, want %s", receivedDest.NetAddr(), dest.NetAddr())
			}
			if diff := cmp.Diff(receivedPayload, testPayload); diff != "" {
				t.Errorf("payload mismatch: %s", diff)
			}
		})
	}
}

func TestUDPCodec(t *testing.T) {
	methods := []string{
		MethodAES128GCM,
		MethodAES256GCM,
		MethodChaCha20Poly1305,
	}

	dest := net.UDPDestination(net.LocalHostIP, net.Port(53))
	payload := []byte("DNS query payload")

	for _, methodName := range methods {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)

			psk := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(psk)

			clientCodec, err := NewUDPPacketCodec(method, psk)
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, psk, time.Minute)
			common.Must(err)

			pktBuf, err := clientCodec.EncodeClientPacket(dest, payload)
			common.Must(err)
			defer pktBuf.Release()

			decoded, err := serverCodec.DecodePacket(pktBuf.Bytes())
			common.Must(err)

			if decoded.HeaderType != HeaderTypeClient {
				t.Errorf("expected header type %d, got %d", HeaderTypeClient, decoded.HeaderType)
			}
			if decoded.Destination.Port != dest.Port {
				t.Errorf("port mismatch: got %d, want %d", decoded.Destination.Port, dest.Port)
			}
			if !bytes.Equal(decoded.Payload, payload) {
				t.Errorf("payload mismatch: got %s, want %s", decoded.Payload, payload)
			}
		})
	}
}

func TestMultiUserManager(t *testing.T) {
	masterKey := generateRandomKey(16)
	userKey1 := generateRandomKey(16)
	userKey2 := generateRandomKey(16)

	config := &MultiUserServerConfig{
		Method: MethodAES128GCM,
		Key:    masterKey,
		Users: []*protocol.User{
			{
				Email:   "user1@example.com",
				Account: serial.ToTypedMessage(&Account{Key: userKey1}),
			},
		},
	}

	inbound, err := NewMultiServer(newTestContext(), config)
	common.Must(err)

	if inbound.GetUsersCount(context.Background()) != 1 {
		t.Fatalf("expected 1 user, got %d", inbound.GetUsersCount(context.Background()))
	}

	u1 := inbound.GetUser(context.Background(), "user1@example.com")
	if u1 == nil || u1.Email != "user1@example.com" {
		t.Fatal("user1 not found")
	}

	// Add User 2
	rawKey2, _ := base64.StdEncoding.DecodeString(userKey2)
	u2 := &protocol.MemoryUser{
		Email: "user2@example.com",
		Account: &MemoryAccount{
			Key: rawKey2,
		},
	}
	err = inbound.AddUser(context.Background(), u2)
	common.Must(err)

	if inbound.GetUsersCount(context.Background()) != 2 {
		t.Fatalf("expected 2 users, got %d", inbound.GetUsersCount(context.Background()))
	}

	// Remove User 1
	err = inbound.RemoveUser(context.Background(), "user1@example.com")
	common.Must(err)

	if inbound.GetUsersCount(context.Background()) != 1 {
		t.Fatalf("expected 1 user, got %d", inbound.GetUsersCount(context.Background()))
	}
	if inbound.GetUser(context.Background(), "user1@example.com") != nil {
		t.Fatal("user1 should have been removed")
	}
}

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

func TestMultiUserTCPConnection(t *testing.T) {
	masterKey := generateRandomKey(16)
	userKey1 := generateRandomKey(16)
	userKey2 := generateRandomKey(16)

	config := &MultiUserServerConfig{
		Method: MethodAES128GCM,
		Key:    masterKey,
		Users: []*protocol.User{
			{
				Email:   "user1@example.com",
				Account: serial.ToTypedMessage(&Account{Key: userKey1}),
			},
			{
				Email:   "user2@example.com",
				Account: serial.ToTypedMessage(&Account{Key: userKey2}),
			},
		},
	}

	testCtx := newTestContext()
	inbound, err := NewMultiServer(testCtx, config)
	common.Must(err)

	clientConn, serverConn := gonet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	dest := net.TCPDestination(net.LocalHostIP, 443)
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)

	masterRaw, _ := base64.StdEncoding.DecodeString(masterKey)
	user2Raw, _ := base64.StdEncoding.DecodeString(userKey2)
	clientPSKList := [][]byte{masterRaw, user2Raw}

	dispatchedUserChan := make(chan string, 1)

	disp := &dummyDispatcher{
		onDispatch: func(ctx context.Context, d net.Destination) (*transport.Link, error) {
			inbound := session.InboundFromContext(ctx)
			if inbound != nil && inbound.User != nil {
				dispatchedUserChan <- inbound.User.Email
			}
			link := &transport.Link{
				Reader: buf.NewReader(bytes.NewReader(nil)),
				Writer: buf.Discard,
			}
			return link, nil
		},
	}

	go func() {
		_ = inbound.Process(testCtx, net.Network_TCP, &dummyStatConn{Conn: serverConn}, disp)
	}()

	clientSalt, writer, err := ClientHandshake(clientConn, method, clientPSKList, dest, []byte("ping"))
	common.Must(err)

	reader, _, err := ClientVerifyServerResponse(clientConn, method, user2Raw, clientSalt)
	common.Must(err)
	_ = writer
	_ = reader

	select {
	case email := <-dispatchedUserChan:
		if email != "user2@example.com" {
			t.Fatalf("expected user2@example.com, got %s", email)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for dispatched user")
	}
}

func TestUDPReaderWriter(t *testing.T) {
	for _, methodName := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)
			rawPSK := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(rawPSK)

			clientCodec, err := NewUDPPacketCodec(method, rawPSK)
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, rawPSK, time.Minute)
			common.Must(err)

			dest := net.UDPDestination(net.LocalHostIP, 53)

			// Client to Server
			clientPacketBuf, err := clientCodec.EncodeClientPacket(dest, []byte("hello dns"))
			common.Must(err)
			defer clientPacketBuf.Release()

			serverDecoded, err := serverCodec.DecodePacket(clientPacketBuf.Bytes())
			common.Must(err)
			if string(serverDecoded.Payload) != "hello dns" {
				t.Fatalf("unexpected server decoded payload: %s", string(serverDecoded.Payload))
			}

			// Server to Client
			serverPacket, err := serverCodec.EncodePacket(serverDecoded.SessionID, dest, []byte("dns response"))
			common.Must(err)

			clientDecoded, err := clientCodec.DecodePacket(serverPacket)
			common.Must(err)
			if string(clientDecoded.Payload) != "dns response" {
				t.Fatalf("unexpected client decoded payload: %s", string(clientDecoded.Payload))
			}

			// Test UDPWriter and UDPReader pipeline
			pipeR, pipeW := gonet.Pipe()
			defer pipeR.Close()
			defer pipeW.Close()

			writer := &UDPWriter{
				Writer:      pipeW,
				Destination: dest,
				Codec:       clientCodec,
			}
			reader := &UDPReader{
				Reader: pipeR,
				Codec:  clientCodec,
			}

			go func() {
				// Simulate server echoing back as server response
				buf := make([]byte, 2048)
				n, err := pipeR.Read(buf)
				if err != nil {
					return
				}
				dec, err := serverCodec.DecodePacket(buf[:n])
				if err != nil {
					return
				}
				resp, err := serverCodec.EncodePacket(dec.SessionID, dest, dec.Payload)
				if err != nil {
					return
				}
				_, _ = pipeW.Write(resp)
			}()

			b := buf.New()
			b.WriteString("piped udp packet")
			common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{b}))

			received, err := reader.ReadMultiBuffer()
			common.Must(err)
			if received[0].String() != "piped udp packet" {
				t.Fatalf("expected 'piped udp packet', got '%s'", received[0].String())
			}
		})
	}
}

func TestTCPRequestResponse(t *testing.T) {
	for _, methodName := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)
			rawPSK := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(rawPSK)

			clientConn, serverConn := gonet.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			clientSalt := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(clientSalt)
			dest := net.TCPDestination(net.LocalHostIP, 80)

			go func() {
				// Server side: read handshake and verify clientSalt
				salt := make([]byte, method.KeySaltLength)
				if _, err := io.ReadFull(serverConn, salt); err != nil {
					t.Errorf("server read salt error: %v", err)
					return
				}
				sessionKey := DeriveSessionSubKey(rawPSK, salt, method.KeySaltLength)
				aead, err := method.NewAEAD(sessionKey)
				if err != nil {
					t.Errorf("server AEAD error: %v", err)
					return
				}
				sReader := NewStreamReader(serverConn, aead)
				var fixedBuf [RequestHeaderFixedChunkLength + AEADTagSize]byte
				if _, err := io.ReadFull(serverConn, fixedBuf[:]); err != nil {
					t.Errorf("server read fixed error: %v", err)
					return
				}
				plainFixed, err := aead.Open(fixedBuf[:0], sReader.Nonce(), fixedBuf[:], nil)
				if err != nil {
					t.Errorf("server decrypt fixed error: %v", err)
					return
				}
				IncreaseNonce(sReader.Nonce())

				varLen := int(binary.BigEndian.Uint16(plainFixed[9:11]))
				varBuf := make([]byte, varLen+AEADTagSize)
				if _, err := io.ReadFull(serverConn, varBuf); err != nil {
					t.Errorf("server read var error: %v", err)
					return
				}
				plainVar, err := aead.Open(varBuf[:0], sReader.Nonce(), varBuf, nil)
				if err != nil {
					t.Errorf("server decrypt var error: %v", err)
					return
				}
				IncreaseNonce(sReader.Nonce())

				vBuf := buf.New()
				vBuf.Write(plainVar)
				receivedDest, err := ReadAddressPort(vBuf)
				if err != nil || receivedDest != dest {
					t.Errorf("dest mismatch: %v vs %v, err: %v", receivedDest, dest, err)
					return
				}

				// Echo client salt back to client using WriteTCPResponse
				sWriter, err := WriteTCPResponse(serverConn, method, rawPSK, salt, []byte("early-reply"))
				if err != nil {
					t.Errorf("server response error: %v", err)
					return
				}
				_ = sWriter
			}()

			bodyWriter, err := WriteTCPRequest(clientConn, method, [][]byte{rawPSK}, dest, clientSalt, nil)
			common.Must(err)
			_ = bodyWriter

			responseReader, err := ReadTCPResponse(clientConn, method, rawPSK, clientSalt)
			common.Must(err)

			mb, err := responseReader.ReadMultiBuffer()
			common.Must(err)
			if mb[0].String() != "early-reply" {
				t.Fatalf("expected early-reply, got %s", mb[0].String())
			}
		})
	}
}

func TestUDPReplayProtection(t *testing.T) {
	for _, methodName := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)
			rawPSK := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(rawPSK)

			clientCodec, err := NewUDPPacketCodec(method, rawPSK)
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, rawPSK, time.Minute)
			common.Must(err)

			dest := net.UDPDestination(net.LocalHostIP, 53)
			pktBuf, err := clientCodec.EncodeClientPacket(dest, []byte("dns 1"))
			common.Must(err)
			defer pktBuf.Release()

			rawCopy := make([]byte, pktBuf.Len())
			copy(rawCopy, pktBuf.Bytes())

			// First decode should succeed
			_, err = serverCodec.DecodePacket(pktBuf.Bytes())
			if err != nil {
				t.Fatalf("first decode failed: %v", err)
			}

			// Replay same packet wire bytes should fail with ErrPacketIdNotUnique
			_, err = serverCodec.DecodePacket(rawCopy)
			if err != ErrPacketIdNotUnique {
				t.Fatalf("expected ErrPacketIdNotUnique on replay, got: %v", err)
			}
		})
	}
}

func TestServerUDPSessionStabilityAndMonotonicPacketID(t *testing.T) {
	for _, methodName := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)
			rawPSK := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(rawPSK)

			clientCodec, err := NewUDPPacketCodec(method, rawPSK)
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, rawPSK, time.Minute)
			common.Must(err)

			dest := net.UDPDestination(net.LocalHostIP, 53)

			// Client sends packet 1
			pkt1, err := clientCodec.EncodeClientPacket(dest, []byte("request 1"))
			common.Must(err)
			defer pkt1.Release()

			dec1, err := serverCodec.DecodePacket(pkt1.Bytes())
			common.Must(err)

			// Server sends response 1
			resp1, err := serverCodec.EncodePacket(dec1.SessionID, dest, []byte("response 1"))
			common.Must(err)

			// Server sends response 2 to the same client session
			resp2, err := serverCodec.EncodePacket(dec1.SessionID, dest, []byte("response 2"))
			common.Must(err)

			// Decode both on client
			cDec1, err := clientCodec.DecodePacket(resp1)
			common.Must(err)
			cDec2, err := clientCodec.DecodePacket(resp2)
			common.Must(err)

			if cDec1.SessionID != cDec2.SessionID {
				t.Fatalf("expected stable server session ID, got %d and %d", cDec1.SessionID, cDec2.SessionID)
			}
			if cDec2.PacketID <= cDec1.PacketID {
				t.Fatalf("expected monotonically increasing packet ID, got %d then %d", cDec1.PacketID, cDec2.PacketID)
			}
			if string(cDec1.Payload) != "response 1" || string(cDec2.Payload) != "response 2" {
				t.Fatalf("payload mismatch")
			}
		})
	}
}

type mockDialer struct {
	dial func(ctx context.Context, dest net.Destination) (stat.Connection, error)
}

func (d *mockDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	if d.dial != nil {
		return d.dial(ctx, dest)
	}
	c1, c2 := gonet.Pipe()
	_ = c2.Close()
	return &dummyStatConn{Conn: c1}, nil
}

func (d *mockDialer) DestIpAddress() net.IP {
	return net.IP{127, 0, 0, 1}
}

func (d *mockDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

func TestOutboundProcess(t *testing.T) {
	testCtx := newTestContext()
	key := generateRandomKey(16)
	clientConfig := &ClientConfig{
		Address: &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: []byte{127, 0, 0, 1}}},
		Port:    1080,
		Method:  MethodAES128GCM,
		Key:     key,
	}

	outbound, err := NewClient(testCtx, clientConfig)
	common.Must(err)

	ctx := session.ContextWithOutbounds(testCtx, []*session.Outbound{
		{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		},
	})

	link := &transport.Link{
		Reader: buf.NewReader(bytes.NewReader(nil)),
		Writer: buf.Discard,
	}

	dialer := &mockDialer{}
	err = outbound.Process(ctx, link, dialer)
	if err == nil {
		t.Fatal("expected error from closed mock dialer pipe, got nil")
	}
}
