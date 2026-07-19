package xmc

import (
	"bufio"
	"bytes"
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

	handshakeLock   sync.Mutex
	lifecycleMu     sync.Mutex
	closed          bool
	profiles        []loginProfile
	password        string
	rsaPublicKey    []byte
	hostname        string
	paddingSchedule []paddingTurn
	packet          *packetStream
	deadlines       *connectionDeadlines
}

type clientState int

var (
	clientStateHandshake clientState = 1
	clientStateProxy     clientState = 2
)

func newClientConn(c net.Conn, profiles []loginProfile, password string, rsaPublicKey []byte, hostname string) (*clientConn, error) {
	if len(rsaPublicKey) == 0 {
		return nil, fmt.Errorf("empty rsa public key")
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("empty profiles")
	}
	paddingSchedule, err := newClientPaddingSchedule2612()
	if err != nil {
		return nil, fmt.Errorf("select padding profile: %w", err)
	}
	return &clientConn{
		reader:          bufio.NewReader(c),
		writer:          c,
		c:               c,
		state:           clientStateHandshake,
		handshakeLock:   sync.Mutex{},
		profiles:        profiles,
		password:        password,
		rsaPublicKey:    rsaPublicKey,
		hostname:        hostname,
		paddingSchedule: paddingSchedule,
		deadlines:       newConnectionDeadlines(c),
	}, nil
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
		protocolVersion Varint        = Varint(775)
		serverAddress   String        = String(c.hostname)
		serverPort      UnsignedShort = UnsignedShort(25565)
		nextState       Varint        = Varint(2)
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

	err = writePacket(c.writer, 0x00, &protocolVersion, &serverAddress, &serverPort, &nextState)
	if err != nil {
		return fmt.Errorf("write handshake packet: %w", err)
	}

	// Login Start
	randomProfile, err := rand.Int(rand.Reader, big.NewInt(int64(len(c.profiles))))
	if err != nil {
		return fmt.Errorf("select profile: %w", err)
	}
	selectedProfile := c.profiles[randomProfile.Int64()]
	username := String(selectedProfile.Username)

	err = writePacket(c.writer, 0x00, &username, &selectedProfile.UUID)
	if err != nil {
		return fmt.Errorf("write login start: %w", err)
	}

	// Encryption Request
	pkt, err := readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read encryption request: %w", err)
	}

	if pkt.packetID != 0x01 {
		return fmt.Errorf("bad encrypt request packet id")
	}

	var (
		serverId    String
		publicKey   Bytes
		verifyToken Bytes
	)

	err = pkt.readFields(&serverId, &publicKey, &verifyToken)
	if err != nil {
		return fmt.Errorf("read encryption request fields: %w", err)
	}

	if !bytes.Equal(publicKey, c.rsaPublicKey) {
		return fmt.Errorf("server public key mismatch")
	}

	k, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse server public key: %w", err)
	}

	rsaPublicKey, ok := k.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("parse server public key: not rsa")
	}

	sharedSecret := make([]byte, 16)
	if _, err = rand.Read(sharedSecret); err != nil {
		return fmt.Errorf("generate shared secret: %w", err)
	}

	encryptedSharedSecret, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, sharedSecret)
	if err != nil {
		return fmt.Errorf("encrypt shared secret: %w", err)
	}

	verifyToken = append(verifyToken, []byte(c.password)...) // append pre-shared password

	encryptedVerifyToken, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, verifyToken)
	if err != nil {
		return fmt.Errorf("encrypt verify token: %w", err)
	}

	// Send Encryption Response
	err = writePacket(
		c.writer,
		0x01,
		(*Bytes)(&encryptedSharedSecret),
		(*Bytes)(&encryptedVerifyToken),
	)
	if err != nil {
		return fmt.Errorf("write encryption response: %w", err)
	}

	// Enable encryption
	c.reader, err = newCryptoReader(c.reader, sharedSecret)
	if err != nil {
		return fmt.Errorf("new crypto reader: %w", err)
	}

	c.writer, err = newCryptoWriter(c.writer, sharedSecret)
	if err != nil {
		return fmt.Errorf("new crypto writer: %w", err)
	}

	pkt, err = readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read login finished: %w", err)
	}
	if pkt.packetID == 0x00 {
		var reason String
		if readErr := pkt.readFields(&reason); readErr != nil {
			return fmt.Errorf("authentication rejected")
		}
		return fmt.Errorf("authentication rejected: %s", reason)
	}
	if pkt.packetID != 0x02 {
		return fmt.Errorf("bad login finished packet id: %d", pkt.packetID)
	}

	receivedProfile, err := readLoginSuccess(pkt)
	if err != nil {
		return fmt.Errorf("read login finished fields: %w", err)
	}
	if receivedProfile != selectedProfile {
		return fmt.Errorf("login profile mismatch")
	}
	loginAcknowledgedLength, err := writePacketWithLength(c.writer, 0x03)
	if err != nil {
		return fmt.Errorf("write login acknowledged: %w", err)
	}
	if err = runPaddingSchedule(c.reader, c.writer, true, loginAcknowledgedLength, c.paddingSchedule); err != nil {
		return fmt.Errorf("run startup padding: %w", err)
	}

	packet := newPacketStream(c.reader, c.writer, true)
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
	if packet != nil {
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
