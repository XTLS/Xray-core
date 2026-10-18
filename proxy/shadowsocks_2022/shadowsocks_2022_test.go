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
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/proxy/shadowsocks_2022"
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

func TestSlidingWindow(t *testing.T) {
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

func TestTCPStream(t *testing.T) {
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

				dest, addrLen, err := ParseAddressPort(plainVar)
				common.Must(err)
				receivedDest = net.TCPDestination(dest.Address, dest.Port)
				plainVar = plainVar[addrLen:]
				padLen := int(binary.BigEndian.Uint16(plainVar[:2]))
				receivedPayload = plainVar[2+padLen:]

				// Server sends response stream with receivedPayload as first payload
				writer := NewServerStreamWriter(serverConn, method, rawKey, salt)
				pBuf := buf.New()
				pBuf.Write(receivedPayload)
				_ = writer.WriteMultiBuffer(buf.MultiBuffer{pBuf})

				// Read and echo additional stream data
				mb, err := reader.ReadMultiBuffer()
				common.Must(err)
				_ = writer.WriteMultiBuffer(mb)
				_ = writer.Close()
			}()

			// Client goroutine
			go func() {
				defer wg.Done()
				clientSalt := make([]byte, method.KeySaltLength)
				common.Must2(io.ReadFull(rand.Reader, clientSalt))
				writer, err := WriteTCPRequest(clientConn, method, [][]byte{rawKey}, dest, clientSalt, testPayload)
				common.Must(err)

				reader, err := ReadTCPResponse(clientConn, method, rawKey, clientSalt)
				common.Must(err)

				// The first ReadMultiBuffer drains initialPayload from reader cache
				mbInit, err := reader.ReadMultiBuffer()
				common.Must(err)
				if !bytes.Equal(mbInit[0].Bytes(), testPayload) {
					t.Errorf("drained initial payload mismatch: got %s, want %s", mbInit[0].Bytes(), testPayload)
				}
				buf.ReleaseMulti(mbInit)

				// Send additional stream data
				streamData := []byte("stream chunk test")
				_ = writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(streamData)})

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

			clientCodec, err := NewUDPPacketCodec(method, [][]byte{psk})
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, psk, time.Minute)
			common.Must(err)

			session, err := clientCodec.NewClientSession()
			common.Must(err)
			pktBuf, err := session.EncodePacket(dest, payload)
			common.Must(err)
			defer pktBuf.Release()

			rawCopy := make([]byte, pktBuf.Len())
			copy(rawCopy, pktBuf.Bytes())

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

			// Replay same packet wire bytes should fail with ErrPacketIdNotUnique
			_, err = serverCodec.DecodePacket(rawCopy)
			if err != ErrPacketIdNotUnique {
				t.Fatalf("expected ErrPacketIdNotUnique on replay, got: %v", err)
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

func TestLargeStreamTransfer(t *testing.T) {
	method, err := GetCipherMethod(MethodAES128GCM)
	common.Must(err)
	sessionKey := make([]byte, 16)
	_, _ = rand.Read(sessionKey)

	clientAead, err := method.NewAEAD(sessionKey)
	common.Must(err)
	serverAead, err := method.NewAEAD(sessionKey)
	common.Must(err)

	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	writer := NewStreamWriter(w, clientAead)
	reader := NewStreamReader(r, serverAead)

	const totalSize = 100 * 1024 // 100 KB
	data := make([]byte, totalSize)
	_, _ = rand.Read(data)

	errCh := make(chan error, 1)
	go func() {
		// Write using Write (which splits by MaxPacketSize = 65535)
		_, werr := writer.Write(data)
		if werr != nil {
			errCh <- werr
			return
		}
		_ = w.Close()
		errCh <- nil
	}()

	var received []byte
	for {
		mb, rerr := reader.ReadMultiBuffer()
		if !mb.IsEmpty() {
			for _, b := range mb {
				received = append(received, b.Bytes()...)
			}
			buf.ReleaseMulti(mb)
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			t.Fatalf("ReadMultiBuffer error: %v", rerr)
		}
	}

	if werr := <-errCh; werr != nil {
		t.Fatalf("writer error: %v", werr)
	}

	if len(received) != totalSize {
		t.Fatalf("received size mismatch: got %d, want %d", len(received), totalSize)
	}
	if !bytes.Equal(received, data) {
		t.Fatal("received data does not match sent data")
	}
}

func TestClientUDPSessionMultiDestination(t *testing.T) {
	for _, methodName := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(methodName, func(t *testing.T) {
			method, err := GetCipherMethod(methodName)
			common.Must(err)
			rawKey := make([]byte, method.KeySaltLength)
			_, _ = rand.Read(rawKey)

			clientCodec, err := NewUDPPacketCodec(method, [][]byte{rawKey})
			common.Must(err)
			serverCodec, err := NewUDPServerCodec(method, rawKey, time.Minute)
			common.Must(err)

			session, err := clientCodec.NewClientSession()
			common.Must(err)

			dest1 := net.UDPDestination(net.LocalHostIP, net.Port(53))
			dest2 := net.UDPDestination(net.IPAddress([]byte{127, 0, 0, 2}), net.Port(53))

			payload1 := []byte("query-google-dns")
			payload2 := []byte("query-cloudflare-dns")

			// Client sends to dest1 and dest2 using SAME session
			pkt1, err := session.EncodePacket(dest1, payload1)
			common.Must(err)
			defer pkt1.Release()
			pkt2, err := session.EncodePacket(dest2, payload2)
			common.Must(err)
			defer pkt2.Release()

			// Server decodes both
			dec1, err := serverCodec.DecodePacket(pkt1.Bytes())
			common.Must(err)
			dec2, err := serverCodec.DecodePacket(pkt2.Bytes())
			common.Must(err)

			if dec1.SessionID != session.ClientSessionID() || dec2.SessionID != session.ClientSessionID() {
				t.Fatalf("both packets must share client session ID %d, got %d and %d", session.ClientSessionID(), dec1.SessionID, dec2.SessionID)
			}
			if dec1.Destination.String() != dest1.String() {
				t.Fatalf("expected dest1 %s, got %s", dest1, dec1.Destination)
			}
			if dec2.Destination.String() != dest2.String() {
				t.Fatalf("expected dest2 %s, got %s", dest2, dec2.Destination)
			}
			if !bytes.Equal(dec1.Payload, payload1) || !bytes.Equal(dec2.Payload, payload2) {
				t.Fatal("payload mismatch")
			}

			// Server replies to dest1 and dest2
			respPayload1 := []byte("reply-google-dns")
			respPayload2 := []byte("reply-cloudflare-dns")

			respPkt1, err := serverCodec.EncodeServerPacket(dec1.SessionID, dest1, respPayload1)
			common.Must(err)
			respPkt2, err := serverCodec.EncodeServerPacket(dec2.SessionID, dest2, respPayload2)
			common.Must(err)

			// Client decodes replies
			clientDec1, err := session.DecodePacket(respPkt1)
			common.Must(err)
			if clientDec1.Destination.String() != dest1.String() {
				t.Fatalf("expected client dec1 dest %s, got %s", dest1, clientDec1.Destination)
			}
			if !bytes.Equal(clientDec1.Payload, respPayload1) {
				t.Fatal("reply payload 1 mismatch")
			}

			clientDec2, err := session.DecodePacket(respPkt2)
			common.Must(err)
			if clientDec2.Destination.String() != dest2.String() {
				t.Fatalf("expected client dec2 dest %s, got %s", dest2, clientDec2.Destination)
			}
			if !bytes.Equal(clientDec2.Payload, respPayload2) {
				t.Fatal("reply payload 2 mismatch")
			}
		})
	}
}
