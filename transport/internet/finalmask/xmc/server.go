package xmc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	yggdrasilVerifyTimeout = 10 * time.Second
	// The client sends its join request right after the encryption response,
	// so the session is usually registered within a few milliseconds. Poll
	// quickly at first and back off to yggdrasilVerifyMaxPoll while it is
	// still missing, instead of making every login wait a fixed interval.
	yggdrasilVerifyFirstPoll = 10 * time.Millisecond
	yggdrasilVerifyMaxPoll   = 200 * time.Millisecond
	// maxPlayerNameLength is vanilla's Login Start limit (readUtf(16)).
	maxPlayerNameLength = 16
)

var errYggdrasilNotJoined = errors.New("player did not join the minecraft session")

// serverSessionID is the connection session id that Login Finished carries from
// 26.2 on. Vanilla generates it once per server rather than per connection, so
// one value for the process has the same shape.
var serverSessionID = sync.OnceValues(func() (UUID, error) {
	var sessionID UUID
	if _, err := rand.Read(sessionID[:]); err != nil {
		return UUID{}, fmt.Errorf("generate session id: %w", err)
	}
	return sessionID, nil
})

type serverState int

var (
	serverStateHandshake serverState = 1
	serverStateProxy     serverState = 3
)

type serverConn struct {
	reader io.Reader
	writer io.Writer
	c      net.Conn

	state serverState

	// protocol is the row selected from the client's handshake. Both ends have
	// to use the same ids, and the client is the side that names the version.
	protocol protocolVersion

	handshakeLock   sync.Mutex
	lifecycleMu     sync.Mutex
	closed          bool
	profiles        []loginProfile
	password        string
	rsaPrivateKey   *rsa.PrivateKey
	rsaPublicKey    []byte
	dataChannel     string
	paddingChannel  string
	yggdrasil       *yggdrasilVerifier
	paddingSchedule []paddingTurn
	packet          *tickStream
	deadlines       *connectionDeadlines

	done      chan struct{}
	closeOnce sync.Once
}

func (c *serverConn) handshake() error {
	c.handshakeLock.Lock()
	defer c.handshakeLock.Unlock()

	if c.state != serverStateHandshake {
		return nil
	}

	if err := c.deadlines.beginHandshake(); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer func() { _ = c.deadlines.endHandshake() }()

	var (
		protocolNumber Varint
		serverAddress  String
		serverPort     UnsignedShort
		nextState      Varint
	)

	// handshake packet

	pkt, err := readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read handshake packet: %w", err)
	}

	if pkt.packetID != handshakeServerboundIntention {
		return fmt.Errorf("bad handshake packet id")
	}

	err = pkt.readFields(&protocolNumber, &serverAddress, &serverPort, &nextState)
	if err != nil {
		return fmt.Errorf("read handshake packet: %w", err)
	}

	switch nextState {
	case 1:

		// Ping

		for range 2 {

			pkt, err := readPacket(c.reader)
			if err != nil {
				return fmt.Errorf("read packet: %w", err)
			}

			switch pkt.packetID {
			case statusServerboundRequest: // Status Request

				err = writePacket(c.writer, statusClientboundResponse, new(String(statusResponse(latestProtocolVersion))))
				if err != nil {
					return fmt.Errorf("write status response: %w", err)
				}

			case statusServerboundPing: // Ping

				var payload Long
				err = pkt.readFields(&payload)
				if err != nil {
					return fmt.Errorf("read ping packet: %w", err)
				}

				err = writePacket(c.writer, statusClientboundPong, &payload)
				if err != nil {
					return fmt.Errorf("write ping response: %w", err)
				}

			}

		}

		return fmt.Errorf("ping")

	case 2, 3:

		// Login. A vanilla server starts the login protocol, checks the version
		// against its own, and only then reads Login Start; TRANSFER shares the
		// login but is only accepted when the server allows transfers, which the
		// mask does not.
		if nextState == 3 {
			reason := `{"translate":"multiplayer.disconnect.transfers_disabled"}`
			_ = writePacket(c.writer, latestProtocolVersion.login.clientboundLoginDisconnect, new(String(reason)))
			return fmt.Errorf("transfers are disabled")
		}

		// The version picks the row, not the other way around: the ids are the
		// registration order of the peer's own protocol, so the client decides.
		// An unknown version is rejected with the same Login Disconnect a vanilla
		// server sends for it. The disconnect id is taken from the newest row
		// because no row matches, and no release has ever moved it.
		protocol, known := protocolVersionByNumber(protocolNumber)
		if !known {
			reason := String(loginRejectReason(protocolNumber))
			_ = writePacket(c.writer, latestProtocolVersion.login.clientboundLoginDisconnect, &reason)
			return fmt.Errorf("unsupported protocol version: %d", protocolNumber)
		}
		c.protocol = protocol

		if err = c.login(); err != nil {
			return err
		}
		return nil

	default:
		return fmt.Errorf("bad handshake packet: bad next state: %d", nextState)
	}
}

// login runs the login state once the protocol version is known.
func (c *serverConn) login() error {
	// login start

	pkt, err := readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read login start packet: %w", err)
	}

	if pkt.packetID != c.protocol.login.serverboundLoginStart {
		return fmt.Errorf("bad login start packet id")
	}

	var (
		username String
		uuid     UUID
	)

	err = pkt.readFields(&username, &uuid)
	if err != nil {
		return fmt.Errorf("read login start packet: %w", err)
	}
	if !validPlayerName(string(username)) {
		return fmt.Errorf("invalid player name: %q", string(username))
	}
	profile, found := findProfile(c.profiles, string(username), uuid)

	// encrypt request

	var (
		serverId           String  = String("")
		publicKey          Bytes   = Bytes(c.rsaPublicKey)
		verifyToken        Bytes   = Bytes(make([]byte, 4))
		shouldAuthenticate Boolean = true
	)

	if _, err = rand.Read(verifyToken); err != nil {
		return fmt.Errorf("generate verify token: %w", err)
	}

	err = writePacket(c.writer, c.protocol.login.clientboundHello, &serverId, &publicKey, &verifyToken, &shouldAuthenticate)
	if err != nil {
		return fmt.Errorf("write encryption request: %w", err)
	}

	// encrypt response

	var (
		encryptedSharedSecret Bytes
		encryptedVerifyToken  Bytes

		sharedSecret         []byte
		decryptedVerifyToken []byte
	)

	pkt, err = readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read encrypt response: %w", err)
	}

	if pkt.packetID != c.protocol.login.serverboundKey {
		return fmt.Errorf("bad encrypt response packet id")
	}

	err = pkt.readFields(&encryptedSharedSecret, &encryptedVerifyToken)
	if err != nil {
		return fmt.Errorf("read encrypt response: %w", err)
	}

	sharedSecret, err = rsa.DecryptPKCS1v15(rand.Reader, c.rsaPrivateKey, encryptedSharedSecret)
	if err != nil {
		return fmt.Errorf("decrypt shared secret: %w", err)
	}
	if len(sharedSecret) != 16 {
		return fmt.Errorf("bad shared secret length: %d", len(sharedSecret))
	}

	decryptedVerifyToken, err = rsa.DecryptPKCS1v15(rand.Reader, c.rsaPrivateKey, encryptedVerifyToken)
	if err != nil {
		return fmt.Errorf("decrypt verify token: %w", err)
	}

	if len(decryptedVerifyToken) < 4 || !bytes.Equal(verifyToken, decryptedVerifyToken[:4]) {
		return fmt.Errorf("verify token mismatch")
	}

	c.reader, err = newCryptoReader(c.reader, sharedSecret)
	if err != nil {
		return fmt.Errorf("new crypto reader: %w", err)
	}

	c.writer, err = newCryptoWriter(c.writer, sharedSecret)
	if err != nil {
		return fmt.Errorf("new crypto writer: %w", err)
	}

	if c.yggdrasil != nil {
		// Online-mode login: verify the player through the session server
		// instead of the pre-shared password and the static profile list.
		if !bytes.Equal(decryptedVerifyToken, verifyToken) {
			return fmt.Errorf("verify token mismatch")
		}

		serverID := minecraftServerID(string(serverId), sharedSecret, c.rsaPublicKey)
		profile, err = c.verifyYggdrasilLogin(string(username), uuid, serverID)
		if err != nil {
			reason := `{"translate":"multiplayer.disconnect.unverified_username"}`
			if !errors.Is(err, errYggdrasilNotJoined) {
				reason = `{"translate":"multiplayer.disconnect.authservers_down"}`
			}
			if writeErr := writeDisconnectPacket(c.writer, c.protocol.login.clientboundLoginDisconnect, reason); writeErr != nil {
				return fmt.Errorf("write yggdrasil disconnect: %w", writeErr)
			}
			return fmt.Errorf("verify yggdrasil login: %w", err)
		}
	} else {
		// verify password
		receivedPassword := decryptedVerifyToken[4:]

		if subtle.ConstantTimeCompare(receivedPassword, []byte(c.password)) != 1 {
			_ = writeDisconnectPacket(c.writer, c.protocol.login.clientboundLoginDisconnect, `{"translate":"multiplayer.disconnect.authservers_down"}`)
			return fmt.Errorf("bad password")
		}
		if !found {
			if err = writeDisconnectPacket(c.writer, c.protocol.login.clientboundLoginDisconnect, `{"text":"You are not white-listed on this server!"}`); err != nil {
				return fmt.Errorf("write unknown login profile disconnect: %w", err)
			}
			return fmt.Errorf("unknown login profile")
		}
	}

	// No Set Compression, which is the same wire as a vanilla server with
	// network-compression-threshold=-1: the startup padding preset reproduces a
	// login that ran without it, and the tunnel payloads are already compressed
	// or encrypted by whoever produced them. The client still negotiates the
	// compressed framing when the peer is a real server that enables it.
	if err = writeLoginFinished(c.writer, c.protocol, profile); err != nil {
		return fmt.Errorf("write login finished: %w", err)
	}

	var loginAcknowledgedLength int
	pkt, loginAcknowledgedLength, err = readPacketWithLength(c.reader)
	if err != nil {
		return fmt.Errorf("read login acknowledged: %w", err)
	}
	if err = validateLoginAcknowledgedPacket(pkt, c.protocol.login.serverboundLoginAcknowledged); err != nil {
		return err
	}

	return c.startProxy(loginAcknowledgedLength)
}

// startProxy runs the startup padding and hands the connection to the tick
// stream. It is called once the login reached the configuration state.
func (c *serverConn) startProxy(loginAcknowledgedLength int) error {
	c.reader = newPaddingReader(c.reader, false, c.paddingChannel, c.protocol.configuration)
	if err := runPaddingSchedule(c.writer, false, loginAcknowledgedLength, c.paddingSchedule, c.paddingPause, c.paddingChannel, c.protocol.configuration); err != nil {
		_ = c.Close() // Unblock the startup reader if writing failed.
		return fmt.Errorf("run startup padding: %w", err)
	}

	packet := newTickStream(c.reader, c.writer, false, c.protocol.configuration, c.dataChannel, c.paddingChannel)
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		packet.Stop()
		return net.ErrClosed
	}
	c.packet = packet
	c.reader = packet
	c.writer = packet
	c.state = serverStateProxy
	c.lifecycleMu.Unlock()

	return nil
}

// validPlayerName mirrors vanilla's Login Start check in 26.x: at most sixteen
// bytes, all printable ASCII. The older "letters, digits and underscore"
// restriction was dropped, so filtering it here would reject players a vanilla
// server accepts.
func validPlayerName(name string) bool {
	if len(name) > maxPlayerNameLength {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] <= 32 || name[i] >= 127 {
			return false
		}
	}
	return true
}

// statusResponse is the status JSON a vanilla server of this version builds:
// a collapsed literal description, the player counts with an empty sample, and
// the version the server speaks.
func statusResponse(version protocolVersion) string {
	return fmt.Sprintf(
		`{"description":"A Minecraft Server","players":{"max":20,"online":0,"sample":[]},"version":{"name":%q,"protocol":%d},"enforcesSecureChat":true}`,
		version.name,
		version.number,
	)
}

func (c *serverConn) verifyYggdrasilLogin(username string, uuid UUID, serverID string) (loginProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), yggdrasilVerifyTimeout)
	defer cancel()

	poll := yggdrasilVerifyFirstPoll
	for {
		account, err := c.yggdrasil.hasJoined(ctx, username, serverID)
		if err != nil {
			return loginProfile{}, err
		}
		if account != nil {
			profileUUID, err := normalizeMinecraftUUID(account.ID)
			if err != nil {
				return loginProfile{}, err
			}
			if profileUUID != uuid {
				return loginProfile{}, fmt.Errorf("yggdrasil profile UUID mismatch")
			}
			if account.Name != username {
				return loginProfile{}, fmt.Errorf("yggdrasil profile name mismatch")
			}
			return loginProfile{
				Username:   account.Name,
				UUID:       profileUUID,
				Properties: propertyListFromYggdrasil(account.Properties),
			}, nil
		}

		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return loginProfile{}, fmt.Errorf("%w: %q", errYggdrasilNotJoined, username)
		case <-timer.C:
		}
		if poll < yggdrasilVerifyMaxPoll {
			poll *= 2
			if poll > yggdrasilVerifyMaxPoll {
				poll = yggdrasilVerifyMaxPoll
			}
		}
	}
}

func validateLoginAcknowledgedPacket(pkt *mcPacket, packetID int) error {
	if pkt.packetID != packetID {
		return fmt.Errorf("bad login acknowledged packet id: %d", pkt.packetID)
	}
	if len(pkt.data) != 0 {
		return fmt.Errorf("bad login acknowledged packet data length: %d", len(pkt.data))
	}
	return nil
}

func (c *serverConn) Read(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}

	return c.reader.Read(b)
}

func (c *serverConn) Write(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}

	return c.writer.Write(b)
}

func (c *serverConn) Close() error {
	c.lifecycleMu.Lock()
	c.closed = true
	packet := c.packet
	c.lifecycleMu.Unlock()
	c.closeOnce.Do(func() { close(c.done) })
	if packet != nil {
		// Write returns once data is queued for the next tick, so a graceful
		// close has to flush the last tick instead of dropping it.
		_ = c.c.SetWriteDeadline(time.Now().Add(time.Second))
		_ = packet.Flush()
		packet.Stop()
	}
	return c.c.Close()
}

// paddingPause applies one padding pause, stopping early on Close.
func (c *serverConn) paddingPause(d time.Duration) error {
	return pausePadding(c.done, d)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *serverConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *serverConn) SetDeadline(t time.Time) error {
	return c.deadlines.setDeadline(t)
}

func (c *serverConn) SetReadDeadline(t time.Time) error {
	return c.deadlines.setReadDeadline(t)
}

func (c *serverConn) SetWriteDeadline(t time.Time) error {
	return c.deadlines.setWriteDeadline(t)
}

func wrapConnServer(c net.Conn, profiles []loginProfile, password string, rsaPrivateKeyDER []byte, rsaPublicKey []byte, paddingSchedule []paddingTurn, yggdrasil *yggdrasilVerifier, dataChannel, paddingChannel string) (*serverConn, error) {
	if len(profiles) == 0 && yggdrasil == nil {
		return nil, fmt.Errorf("empty profiles")
	}
	if len(rsaPrivateKeyDER) == 0 {
		return nil, fmt.Errorf("empty rsa private key")
	}
	if len(rsaPublicKey) == 0 {
		return nil, fmt.Errorf("empty rsa public key")
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(rsaPrivateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse rsa private key: %w", err)
	}

	s := &serverConn{
		reader:          bufio.NewReader(c),
		writer:          c,
		c:               c,
		state:           serverStateHandshake,
		profiles:        profiles,
		password:        password,
		rsaPrivateKey:   rsaPrivateKey,
		rsaPublicKey:    rsaPublicKey,
		dataChannel:     dataChannel,
		paddingChannel:  paddingChannel,
		yggdrasil:       yggdrasil,
		paddingSchedule: paddingSchedule,
		deadlines:       newConnectionDeadlines(c),
		done:            make(chan struct{}),
	}

	return s, nil
}
