package xmc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"
)

type clientConn struct {
	reader io.Reader
	writer io.Writer
	c      net.Conn

	state clientState

	// protocol selects the packet ids and field shapes of the login the client
	// performs. The server picks its own row from the handshake, so both ends
	// agree without a negotiation round trip.
	protocol protocolVersion

	handshakeLock   sync.Mutex
	lifecycleMu     sync.Mutex
	closed          bool
	profiles        []loginProfile
	password        string
	rsaPublicKey    []byte
	hostname        string
	dataChannel     string
	paddingChannel  string
	yggdrasil       *yggdrasilAuth
	paddingSchedule []paddingTurn
	packet          *tickStream
	deadlines       *connectionDeadlines

	done      chan struct{}
	closeOnce sync.Once
}

type clientState int

var (
	clientStateHandshake clientState = 1
	clientStateProxy     clientState = 2
)

func newClientConn(c net.Conn, protocol protocolVersion, profiles []loginProfile, password string, rsaPublicKey []byte, hostname string, paddingSchedule []paddingTurn, yggdrasil *yggdrasilAuth, dataChannel, paddingChannel string) (*clientConn, error) {
	if len(rsaPublicKey) == 0 && yggdrasil == nil {
		return nil, fmt.Errorf("empty rsa public key")
	}
	if len(profiles) == 0 && yggdrasil == nil {
		return nil, fmt.Errorf("empty profiles")
	}
	if len(password) > MaxLegacyPasswordLength {
		return nil, fmt.Errorf("password is longer than %d bytes", MaxLegacyPasswordLength)
	}
	return &clientConn{
		reader:          bufio.NewReader(c),
		writer:          c,
		c:               c,
		state:           clientStateHandshake,
		protocol:        protocol,
		handshakeLock:   sync.Mutex{},
		profiles:        profiles,
		password:        password,
		rsaPublicKey:    rsaPublicKey,
		hostname:        hostname,
		dataChannel:     dataChannel,
		paddingChannel:  paddingChannel,
		yggdrasil:       yggdrasil,
		paddingSchedule: paddingSchedule,
		deadlines:       newConnectionDeadlines(c),
		done:            make(chan struct{}),
	}, nil
}

// paddingPause applies one padding pause, stopping early on Close.
func (c *clientConn) paddingPause(d time.Duration) error {
	return pausePadding(c.done, d)
}

func (c *clientConn) handshake() error {
	c.handshakeLock.Lock()
	defer c.handshakeLock.Unlock()

	if c.state != clientStateHandshake {
		return nil
	}

	if err := c.deadlines.beginHandshake(); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer func() { _ = c.deadlines.endHandshake() }()

	var (
		protocolNumber Varint        = c.protocol.number
		serverAddress  String        = String(c.hostname)
		serverPort     UnsignedShort = UnsignedShort(25565)
		nextState      Varint        = Varint(2)
	)

	host, portString, err := net.SplitHostPort(c.c.RemoteAddr().String())
	if err == nil {
		port, err := strconv.Atoi(portString)
		if err == nil {
			serverPort = UnsignedShort(port)
		}

		if serverAddress == "" {
			serverAddress = String(host)
		}
	}

	err = writePacket(c.writer, handshakeServerboundIntention, &protocolNumber, &serverAddress, &serverPort, &nextState)
	if err != nil {
		return fmt.Errorf("write handshake packet: %w", err)
	}

	// Login Start
	var selectedProfile loginProfile
	if c.yggdrasil != nil {
		token, loginErr := c.yggdrasil.login(context.Background())
		if loginErr != nil {
			return fmt.Errorf("yggdrasil login: %w", loginErr)
		}
		profileUUID, uuidErr := normalizeMinecraftUUID(token.profile.ID)
		if uuidErr != nil {
			return fmt.Errorf("yggdrasil login: %w", uuidErr)
		}
		selectedProfile = loginProfile{
			Username: token.profile.Name,
			UUID:     profileUUID,
		}
	} else {
		randomProfile, randErr := rand.Int(rand.Reader, big.NewInt(int64(len(c.profiles))))
		if randErr != nil {
			return fmt.Errorf("select profile: %w", randErr)
		}
		selectedProfile = c.profiles[randomProfile.Int64()]
	}
	username := String(selectedProfile.Username)

	err = writePacket(c.writer, c.protocol.login.serverboundLoginStart, &username, &selectedProfile.UUID)
	if err != nil {
		return fmt.Errorf("write login start: %w", err)
	}

	// From here the server drives the login: Encryption Request, then optionally
	// Set Compression, then Login Finished; queries and cookie requests can
	// appear at any point between them, so the client loops over the login
	// packets like a vanilla one instead of expecting a fixed sequence.
	//
	// The encryption exchange is mandatory. XMC exists to look like a licensed
	// player joining an online-mode server (with a third-party API in Yggdrasil
	// mode), and an offline-mode login skips the encryption request entirely, so
	// there is nothing to reproduce and nothing to authenticate.
	handledEncryption := false
	joinedSession := false
	for {
		pkt, readErr := readPacket(c.reader)
		if readErr != nil {
			return fmt.Errorf("read login packet: %w", readErr)
		}

		switch pkt.packetID {
		case c.protocol.login.clientboundHello:
			if handledEncryption {
				return fmt.Errorf("duplicate encryption request")
			}
			handledEncryption = true
			updatedProfile, joined, helloErr := c.handleEncryptionRequest(pkt, selectedProfile)
			if helloErr != nil {
				return helloErr
			}
			selectedProfile = updatedProfile
			joinedSession = joined

		case c.protocol.login.clientboundLoginCompression:
			// Set Compression is not compressed itself and must be handled before
			// the packet that follows it, which already uses the compressed
			// framing. The threshold only decides whether the framing applies:
			// this writer never compresses, so a server-side threshold does not
			// shrink padding turns.
			var threshold Varint
			if thresholdErr := pkt.readFields(&threshold); thresholdErr != nil {
				return fmt.Errorf("read login compression threshold: %w", thresholdErr)
			}
			if threshold >= 0 {
				c.reader = newCompressionReader(c.reader)
				c.writer = newCompressionWriter(c.writer)
			}

		case c.protocol.login.clientboundCustomQuery:
			// A vanilla 26.x client answers a login query with a null payload: the
			// server-driven login extensions of older versions are gone, and a
			// server that still asks gets an explicit "no answer".
			if answerErr := c.answerCustomQuery(pkt); answerErr != nil {
				return answerErr
			}

		case c.protocol.login.clientboundCookieRequest:
			if answerErr := c.answerCookieRequest(pkt); answerErr != nil {
				return answerErr
			}

		case c.protocol.login.clientboundLoginDisconnect:
			var reason String
			if readErr := pkt.readFields(&reason); readErr != nil {
				return fmt.Errorf("authentication rejected")
			}
			return fmt.Errorf("authentication rejected: %s", reason)

		case c.protocol.login.clientboundLoginFinished:
			if !handledEncryption {
				return fmt.Errorf("server finished the login without an encryption request: offline-mode servers are not supported")
			}
			receivedProfile, finishErr := c.readLoginFinished(pkt)
			if finishErr != nil {
				return fmt.Errorf("read login finished fields: %w", finishErr)
			}
			if verifyErr := c.verifyLoginProfile(receivedProfile, selectedProfile, joinedSession); verifyErr != nil {
				return verifyErr
			}
			selectedProfile = receivedProfile

			loginAcknowledgedLength, writeErr := writePacketWithLength(c.writer, c.protocol.login.serverboundLoginAcknowledged)
			if writeErr != nil {
				return fmt.Errorf("write login acknowledged: %w", writeErr)
			}
			return c.startProxy(loginAcknowledgedLength)

		default:
			return fmt.Errorf("unexpected login packet: 0x%02x", pkt.packetID)
		}
	}
}

// handleEncryptionRequest performs the shared-secret exchange and reports the
// session profile plus whether the session server was joined, which decides how
// strictly the returned game profile can be checked.
func (c *clientConn) handleEncryptionRequest(pkt *mcPacket, profile loginProfile) (loginProfile, bool, error) {
	var (
		serverId           String
		publicKey          Bytes
		verifyToken        Bytes
		shouldAuthenticate Boolean
	)

	err := pkt.readFields(&serverId, &publicKey, &verifyToken, &shouldAuthenticate)
	if err != nil {
		return profile, false, fmt.Errorf("read encryption request fields: %w", err)
	}

	// shouldAuthenticate is false for an offline-mode server that still encrypts.
	// XMC only reproduces the online-mode login, so the client does not pretend
	// to authenticate against it.
	if c.yggdrasil != nil && !shouldAuthenticate {
		return profile, false, fmt.Errorf("server asked the client not to authenticate: offline-mode servers are not supported")
	}

	if c.yggdrasil == nil && !bytes.Equal(publicKey, c.rsaPublicKey) {
		return profile, false, fmt.Errorf("server public key mismatch")
	}

	k, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return profile, false, fmt.Errorf("parse server public key: %w", err)
	}

	rsaPublicKey, ok := k.(*rsa.PublicKey)
	if !ok {
		return profile, false, fmt.Errorf("parse server public key: not rsa")
	}
	if rsaPublicKey.N.BitLen() < 1024 {
		return profile, false, fmt.Errorf("server public key is too short: %d bits", rsaPublicKey.N.BitLen())
	}

	sharedSecret := make([]byte, 16)
	if _, err = rand.Read(sharedSecret); err != nil {
		return profile, false, fmt.Errorf("generate shared secret: %w", err)
	}

	encryptedSharedSecret, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, sharedSecret)
	if err != nil {
		return profile, false, fmt.Errorf("encrypt shared secret: %w", err)
	}

	if c.yggdrasil == nil {
		verifyToken = append(verifyToken, []byte(c.password)...) // append pre-shared password
	}

	encryptedVerifyToken, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, verifyToken)
	if err != nil {
		return profile, false, fmt.Errorf("encrypt verify token: %w", err)
	}

	// Send Encryption Response, then switch the ciphers on: vanilla starts
	// encrypting only after the response itself has been written.
	err = writePacket(
		c.writer,
		c.protocol.login.serverboundKey,
		(*Bytes)(&encryptedSharedSecret),
		(*Bytes)(&encryptedVerifyToken),
	)
	if err != nil {
		return profile, false, fmt.Errorf("write encryption response: %w", err)
	}

	c.reader, err = newCryptoReader(c.reader, sharedSecret)
	if err != nil {
		return profile, false, fmt.Errorf("new crypto reader: %w", err)
	}

	c.writer, err = newCryptoWriter(c.writer, sharedSecret)
	if err != nil {
		return profile, false, fmt.Errorf("new crypto writer: %w", err)
	}

	// Online mode: join the session with the digest of the handshake data so the
	// server can verify it through hasJoined. The password mode has no session
	// server; its login is authenticated by the pre-shared password instead.
	if c.yggdrasil == nil {
		return profile, false, nil
	}

	serverID := minecraftServerID(string(serverId), sharedSecret, publicKey)
	token, joinErr := c.yggdrasil.join(context.Background(), serverID)
	if joinErr != nil {
		return profile, false, fmt.Errorf("yggdrasil session join: %w", joinErr)
	}
	profileUUID, uuidErr := normalizeMinecraftUUID(token.profile.ID)
	if uuidErr != nil {
		return profile, false, fmt.Errorf("yggdrasil session join: %w", uuidErr)
	}
	return loginProfile{Username: token.profile.Name, UUID: profileUUID}, true, nil
}

// answerCustomQuery replies to a login query with a null payload, which is what
// a vanilla 26.x client sends.
func (c *clientConn) answerCustomQuery(pkt *mcPacket) error {
	var transactionID Varint
	if err := pkt.readFields(&transactionID); err != nil {
		return fmt.Errorf("read login query: %w", err)
	}
	// The answer payload is nullable; a vanilla 26.x client leaves it absent.
	answered := Boolean(false)
	if err := writePacket(c.writer, c.protocol.login.serverboundCustomQueryAnswer, &transactionID, &answered); err != nil {
		return fmt.Errorf("write login query answer: %w", err)
	}
	return nil
}

// answerCookieRequest replies with an absent cookie, like a client that has
// never received a cookie for the key.
func (c *clientConn) answerCookieRequest(pkt *mcPacket) error {
	var key String
	if err := pkt.readFields(&key); err != nil {
		return fmt.Errorf("read login cookie request: %w", err)
	}
	// The cookie is nullable; an absent value means "no cookie for this key".
	answered := Boolean(false)
	if err := writePacket(c.writer, c.protocol.login.serverboundCookieResponse, &key, &answered); err != nil {
		return fmt.Errorf("write login cookie response: %w", err)
	}
	return nil
}

// readLoginFinished reads the game profile and, from 26.2 on, the connection
// session id that follows it. Trailing bytes are ignored on purpose: Mojang has
// appended a field to this packet before, and a client that needs an exact
// length would stop pairing on the next release.
func (c *clientConn) readLoginFinished(pkt *mcPacket) (loginProfile, error) {
	var (
		profile  loginProfile
		username String
	)
	fields := []field{&profile.UUID, &username, &profile.Properties}
	if c.protocol.loginFinishedSessionID {
		var sessionID UUID
		fields = append(fields, &sessionID)
	}
	if err := pkt.readFields(fields...); err != nil {
		return loginProfile{}, err
	}
	profile.Username = string(username)
	return profile, nil
}

// verifyLoginProfile checks the profile the server returned. A session join
// pins the identity to the Yggdrasil account and its signed textures; the
// pre-shared password mode compares the configured profile; an offline-mode
// server derives the profile from the name, so it is accepted as it is.
func (c *clientConn) verifyLoginProfile(received, selected loginProfile, joinedSession bool) error {
	switch {
	case joinedSession:
		if !sameProfileIdentity(received, selected) {
			return fmt.Errorf("login profile mismatch")
		}
		if err := c.yggdrasil.verifyLoginProfile(received); err != nil {
			return fmt.Errorf("verify login profile: %w", err)
		}
	case c.yggdrasil == nil:
		if !sameLoginProfile(received, selected) {
			return fmt.Errorf("login profile mismatch")
		}
	}
	return nil
}

// startProxy runs the startup padding and hands the connection to the tick
// stream. It is called once the login reached the configuration state.
func (c *clientConn) startProxy(loginAcknowledgedLength int) error {
	c.reader = newPaddingReader(c.reader, true, c.paddingChannel, c.protocol.configuration)
	if err := runPaddingSchedule(c.writer, true, loginAcknowledgedLength, c.paddingSchedule, c.paddingPause, c.paddingChannel, c.protocol.configuration); err != nil {
		_ = c.Close() // Unblock the startup reader if writing failed.
		return fmt.Errorf("run startup padding: %w", err)
	}

	packet := newTickStream(c.reader, c.writer, true, c.protocol.configuration, c.dataChannel, c.paddingChannel)
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		packet.Stop()
		return net.ErrClosed
	}
	c.packet = packet
	c.reader = packet
	c.writer = packet
	c.state = clientStateProxy
	c.lifecycleMu.Unlock()

	return nil
}

func (c *clientConn) Read(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}

	return c.reader.Read(b)
}

func (c *clientConn) Write(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}

	return c.writer.Write(b)
}

func (c *clientConn) Close() error {
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

func (c *clientConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return c.deadlines.setDeadline(t)
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	return c.deadlines.setReadDeadline(t)
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.deadlines.setWriteDeadline(t)
}
