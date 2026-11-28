package xmc

import (
	"bytes"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func newLoginTestClient(t *testing.T, conn net.Conn, version protocolVersion) *clientConn {
	t.Helper()
	key, err := DeriveRSAKey("login-flow")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientConn(conn, version, []loginProfile{{Username: "TestUser"}}, "password", publicKey, "localhost", nil, nil, DefaultDataChannel, DefaultPaddingChannel)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// TestClientHandshakeAdvertisesConfiguredVersion checks that the handshake
// carries the row selected in the configuration, which is what lets one binary
// pair with servers of different releases.
func TestClientHandshakeAdvertisesConfiguredVersion(t *testing.T) {
	for _, number := range []Varint{767, 775, 777} {
		version, ok := protocolVersionByNumber(number)
		if !ok {
			t.Fatalf("protocol %d is missing from the table", number)
		}
		clientRaw, serverRaw := net.Pipe()
		client := newLoginTestClient(t, clientRaw, version)
		go func() { _ = client.handshake() }()

		if err := serverRaw.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		packet, err := readPacket(serverRaw)
		if err != nil {
			t.Fatalf("protocol %d: read handshake: %v", number, err)
		}
		if packet.packetID != handshakeServerboundIntention {
			t.Fatalf("protocol %d: handshake packet id = 0x%02x", number, packet.packetID)
		}
		var (
			gotNumber Varint
			address   String
			port      UnsignedShort
			nextState Varint
		)
		if err := packet.readFields(&gotNumber, &address, &port, &nextState); err != nil {
			t.Fatalf("protocol %d: read handshake fields: %v", number, err)
		}
		if gotNumber != number {
			t.Fatalf("handshake advertised %d, want %d", gotNumber, number)
		}
		if nextState != 2 {
			t.Fatalf("handshake intent = %d, want login (2)", nextState)
		}

		_ = clientRaw.Close()
		_ = serverRaw.Close()
	}
}

// TestClientLoginAnswers checks the two optional login exchanges a vanilla 26.x
// client answers: a custom query gets a null payload, a cookie request gets an
// absent cookie. Both use the ids of the selected version.
func TestClientLoginAnswers(t *testing.T) {
	version := latestProtocolVersion

	t.Run("custom query", func(t *testing.T) {
		var wire, out bytes.Buffer
		transactionID := Varint(7)
		if err := writePacket(&wire, version.login.clientboundCustomQuery, &transactionID, new(String("test:query"))); err != nil {
			t.Fatal(err)
		}
		request, err := readPacket(&wire)
		if err != nil {
			t.Fatal(err)
		}
		client := &clientConn{protocol: version, writer: &out}
		if err := client.answerCustomQuery(request); err != nil {
			t.Fatal(err)
		}
		answer, err := readPacket(&out)
		if err != nil {
			t.Fatal(err)
		}
		if answer.packetID != version.login.serverboundCustomQueryAnswer {
			t.Fatalf("answer packet id = 0x%02x", answer.packetID)
		}
		// transaction id 7, then the nullable payload marker for "no payload".
		if !bytes.Equal(answer.data, []byte{0x07, 0x00}) {
			t.Fatalf("answer body = %x", answer.data)
		}
	})

	t.Run("cookie request", func(t *testing.T) {
		var wire, out bytes.Buffer
		if err := writePacket(&wire, version.login.clientboundCookieRequest, new(String("test:cookie"))); err != nil {
			t.Fatal(err)
		}
		request, err := readPacket(&wire)
		if err != nil {
			t.Fatal(err)
		}
		client := &clientConn{protocol: version, writer: &out}
		if err := client.answerCookieRequest(request); err != nil {
			t.Fatal(err)
		}
		answer, err := readPacket(&out)
		if err != nil {
			t.Fatal(err)
		}
		if answer.packetID != version.login.serverboundCookieResponse {
			t.Fatalf("answer packet id = 0x%02x", answer.packetID)
		}
		var key String
		if err := answer.readFields(&key); err != nil {
			t.Fatal(err)
		}
		if string(key) != "test:cookie" {
			t.Fatalf("cookie key = %q", string(key))
		}
	})
}

// TestReadLoginFinished checks both shapes of the packet: before 26.2 the body
// ends after the game profile, from 26.2 on a session id follows it. Trailing
// bytes are ignored, because Mojang has appended a field to this packet before.
func TestReadLoginFinished(t *testing.T) {
	for _, version := range []protocolVersion{protocolVersions[0], latestProtocolVersion} {
		var (
			wire    bytes.Buffer
			profile = loginProfile{Username: "TestUser", UUID: UUID{1, 2, 3}}
			name    = String("TestUser")
		)
		fields := []field{&profile.UUID, &name, &profile.Properties}
		if version.loginFinishedSessionID {
			sessionID := UUID{9, 9, 9}
			fields = append(fields, &sessionID)
		}
		if err := writePacket(&wire, version.login.clientboundLoginFinished, fields...); err != nil {
			t.Fatal(err)
		}
		packet, err := readPacket(&wire)
		if err != nil {
			t.Fatal(err)
		}

		client := &clientConn{protocol: version}
		got, err := client.readLoginFinished(packet)
		if err != nil {
			t.Fatalf("%s (%d): read login finished: %v", version.name, version.number, err)
		}
		if got.Username != "TestUser" || got.UUID != profile.UUID {
			t.Fatalf("%s (%d): profile = %q %x", version.name, version.number, got.Username, got.UUID)
		}

		// One missing session id must fail, so the flag cannot silently rot.
		if version.loginFinishedSessionID {
			var short bytes.Buffer
			username := String("TestUser")
			if err := writePacket(&short, version.login.clientboundLoginFinished, &profile.UUID, &username, &profile.Properties); err != nil {
				t.Fatal(err)
			}
			packet, err := readPacket(&short)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.readLoginFinished(packet); err == nil {
				t.Fatalf("%s: login finished without a session id was accepted", version.name)
			}
		}
	}
}

// TestServerRejectsUnknownProtocolVersion checks the server answers a version
// outside the table with the same Login Disconnect a vanilla server sends,
// instead of guessing packet ids.
func TestServerRejectsUnknownProtocolVersion(t *testing.T) {
	key, err := DeriveRSAKey("login-flow")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	server, err := wrapConnServer(serverRaw, []loginProfile{{Username: "TestUser"}}, "password", x509.MarshalPKCS1PrivateKey(key), publicKey, nil, nil, DefaultDataChannel, DefaultPaddingChannel)
	if err != nil {
		t.Fatal(err)
	}
	handshakeResult := make(chan error, 1)
	go func() { handshakeResult <- server.handshake() }()

	if err := clientRaw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var (
		protocolNumber Varint        = 999
		address        String        = "localhost"
		port           UnsignedShort = 25565
		nextState      Varint        = 2
	)
	if err := writePacket(clientRaw, handshakeServerboundIntention, &protocolNumber, &address, &port, &nextState); err != nil {
		t.Fatal(err)
	}

	packet, err := readPacket(clientRaw)
	if err != nil {
		t.Fatalf("read login disconnect: %v", err)
	}
	if packet.packetID != latestProtocolVersion.login.clientboundLoginDisconnect {
		t.Fatalf("disconnect packet id = 0x%02x", packet.packetID)
	}
	var reason String
	if err := packet.readFields(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reason), "multiplayer.disconnect.incompatible") {
		t.Fatalf("disconnect reason = %s", string(reason))
	}

	if err := <-handshakeResult; err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Fatalf("handshake error = %v", err)
	}
}

// TestClientRejectsOfflineLogin checks the client refuses a login that never
// asks for encryption: XMC reproduces the online-mode login, and an offline
// server has none of it.
func TestClientRejectsOfflineLogin(t *testing.T) {
	version := latestProtocolVersion
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := newLoginTestClient(t, clientRaw, version)
	handshakeResult := make(chan error, 1)
	go func() { handshakeResult <- client.handshake() }()

	if err := serverRaw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := readPacket(serverRaw); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if _, err := readPacket(serverRaw); err != nil {
		t.Fatalf("read login start: %v", err)
	}

	// An offline-mode server answers Login Start with Login Finished directly.
	var (
		profile  = loginProfile{Username: "TestUser", UUID: UUID{1}}
		username = String("TestUser")
		session  = UUID{9}
	)
	if err := writePacket(serverRaw, version.login.clientboundLoginFinished, &profile.UUID, &username, &profile.Properties, &session); err != nil {
		t.Fatal(err)
	}

	err := <-handshakeResult
	if err == nil || !strings.Contains(err.Error(), "offline-mode servers are not supported") {
		t.Fatalf("handshake error = %v", err)
	}
}

// TestClientRejectsUnauthenticatedServer checks that a server which still
// encrypts but tells the client not to authenticate is refused in Yggdrasil
// mode: that flag is an offline-mode server.
func TestClientRejectsUnauthenticatedServer(t *testing.T) {
	version := latestProtocolVersion

	var wire bytes.Buffer
	var (
		serverID           String
		publicKey          Bytes = Bytes{1, 2, 3}
		challenge          Bytes = Bytes{4, 5, 6, 7}
		shouldAuthenticate Boolean
	)
	if err := writePacket(&wire, version.login.clientboundHello, &serverID, &publicKey, &challenge, &shouldAuthenticate); err != nil {
		t.Fatal(err)
	}
	request, err := readPacket(&wire)
	if err != nil {
		t.Fatal(err)
	}

	client := &clientConn{protocol: version, writer: io.Discard, yggdrasil: &yggdrasilAuth{}}
	if _, _, err := client.handleEncryptionRequest(request, loginProfile{}); err == nil || !strings.Contains(err.Error(), "offline-mode servers are not supported") {
		t.Fatalf("handle encryption request error = %v", err)
	}
}
