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
)

var errYggdrasilNotJoined = errors.New("player did not join the minecraft session")

// Response by vanilla 26.1.2 server.
var statusResponse = `{"description":"A Minecraft Server","players":{"max":20,"online":0},"version":{"name":"26.1.2","protocol":775},"enforcesSecureChat":true}`

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

	handshakeLock   sync.Mutex
	lifecycleMu     sync.Mutex
	closed          bool
	profiles        []loginProfile
	password        string
	rsaPrivateKey   *rsa.PrivateKey
	rsaPublicKey    []byte
	yggdrasil       *yggdrasilVerifier
	paddingSchedule []paddingTurn
	packet          *packetStream
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
		protocolVersion Varint
		serverAddress   String
		serverPort      UnsignedShort
		nextState       Varint
	)

	// handshake packet

	pkt, err := readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read handshake packet: %w", err)
	}

	if pkt.packetID != 0 {
		return fmt.Errorf("bad handshake packet id")
	}

	err = pkt.readFields(&protocolVersion, &serverAddress, &serverPort, &nextState)
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
			case 0: // Status Request

				err = writePacket(c.writer, 0, new(String(statusResponse)))
				if err != nil {
					return fmt.Errorf("write status response: %w", err)
				}

			case 1: // Ping

				var payload Long
				err = pkt.readFields(&payload)
				if err != nil {
					return fmt.Errorf("read ping packet: %w", err)
				}

				err = writePacket(c.writer, 1, &payload)
				if err != nil {
					return fmt.Errorf("write ping response: %w", err)
				}

			}

		}

		return fmt.Errorf("ping")

	case 2:

		// Login

		// login start

		pkt, err := readPacket(c.reader)
		if err != nil {
			return fmt.Errorf("read login start packet: %w", err)
		}

		if pkt.packetID != 0 {
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

		err = writePacket(c.writer, 0x01, &serverId, &publicKey, &verifyToken, &shouldAuthenticate)
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

		if pkt.packetID != 0x01 {
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
				reason := `{"type":"translatable","translate":"multiplayer.disconnect.unverified_username"}`
				if !errors.Is(err, errYggdrasilNotJoined) {
					reason = `{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}`
				}
				if writeErr := writeDisconnectPacket(c.writer, reason); writeErr != nil {
					return fmt.Errorf("write yggdrasil disconnect: %w", writeErr)
				}
				return fmt.Errorf("verify yggdrasil login: %w", err)
			}
		} else {
			// verify password
			receivedPassword := decryptedVerifyToken[4:]

			if subtle.ConstantTimeCompare(receivedPassword, []byte(c.password)) != 1 {
				_ = writeDisconnectPacket(c.writer, `{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}`)
				return fmt.Errorf("bad password")
			}
			if !found {
				if err = writeDisconnectPacket(c.writer, `{"text":"You are not white-listed on this server!"}`); err != nil {
					return fmt.Errorf("write unknown login profile disconnect: %w", err)
				}
				return fmt.Errorf("unknown login profile")
			}
		}

		if err = writeLoginSuccess(c.writer, profile); err != nil {
			return fmt.Errorf("write login finished: %w", err)
		}

		var loginAcknowledgedLength int
		pkt, loginAcknowledgedLength, err = readPacketWithLength(c.reader)
		if err != nil {
			return fmt.Errorf("read login acknowledged: %w", err)
		}
		if err = validateLoginAcknowledgedPacket(pkt); err != nil {
			return err
		}
		c.reader = newPaddingReader(c.reader, false)
		if err = runPaddingSchedule(c.writer, false, loginAcknowledgedLength, c.paddingSchedule, c.paddingPause); err != nil {
			_ = c.Close() // Unblock the startup reader if writing failed.
			return fmt.Errorf("run startup padding: %w", err)
		}

		packet := newPacketStream(c.reader, c.writer, false)
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

	default:
		return fmt.Errorf("bad handshake packet: bad next state: %d", nextState)
	}
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

func validateLoginAcknowledgedPacket(pkt *mcPacket) error {
	if pkt.packetID != 0x03 {
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

func wrapConnServer(c net.Conn, profiles []loginProfile, password string, rsaPrivateKeyDER []byte, rsaPublicKey []byte, paddingSchedule []paddingTurn, yggdrasil *yggdrasilVerifier) (*serverConn, error) {
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
		yggdrasil:       yggdrasil,
		paddingSchedule: paddingSchedule,
		deadlines:       newConnectionDeadlines(c),
		done:            make(chan struct{}),
	}

	return s, nil
}
