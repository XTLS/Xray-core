package minecraft

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

type clientConn struct {
	reader io.Reader
	writer io.Writer
	c      net.Conn

	state clientState

	handshakeLock sync.Mutex
	usernames     []string
	shortId       []byte
	publicKeyHash []byte
}

type clientState int

var (
	clientStateHandshake clientState = 1
	clientStateProxy     clientState = 2
)

func newClientConn(c net.Conn, usernames []string, shortId []byte, publicKeyHashHex string) (*clientConn, error) {
	publicKeyHash, err := hex.DecodeString(publicKeyHashHex)
	if err != nil {
		return nil, fmt.Errorf("decode public key hash: %w", err)
	}

	return &clientConn{
		reader:        bufio.NewReader(c),
		writer:        c,
		c:             c,
		state:         clientStateHandshake,
		handshakeLock: sync.Mutex{},
		usernames:     usernames,
		shortId:       shortId,
		publicKeyHash: publicKeyHash,
	}, nil
}

func (c *clientConn) handshake() error {
	c.handshakeLock.Lock()
	defer c.handshakeLock.Unlock()

	if c.state != clientStateHandshake {
		return nil
	}

	// Handshake timeout
	err := c.c.SetDeadline(time.Now().Add(time.Second * 30))
	if err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer c.c.SetDeadline(time.Time{})

	var (
		protocolVersion Varint        = Varint(775)
		serverAddress   String        = String("mc.hypixel.net")
		serverPort      UnsignedShort = UnsignedShort(25565)
		nextState       Varint        = Varint(2)
	)

	err = writePacket(c.writer, 0x00, &protocolVersion, &serverAddress, &serverPort, &nextState)
	if err != nil {
		return fmt.Errorf("write handshake packet: %w", err)
	}

	// Login Start
	var (
		username    string
		offlineUUID UUID
	)

	randomUsername, _ := rand.Int(rand.Reader, big.NewInt(int64(len(c.usernames))))
	username = c.usernames[randomUsername.Int64()]
	generateOfflineUUID(&offlineUUID, string(username))

	err = writePacket(c.writer, 0x00, new(String(username)), &offlineUUID)
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

	// verify public key hash
	if len(c.publicKeyHash) > 0 {
		keyHash := sha256.Sum256(publicKey)
		if !bytes.Equal(keyHash[:], c.publicKeyHash) {
			return fmt.Errorf("server public key mismatch")
		}
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
	rand.Read(sharedSecret)

	encryptedSharedSecret, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, sharedSecret)
	if err != nil {
		return fmt.Errorf("encrypt shared secret: %w", err)
	}

	verifyToken = append(verifyToken, c.shortId...) // append short id

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

	c.state = clientStateProxy

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
	return c.c.Close()
}

func (c *clientConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

func generateOfflineUUID(uuid *UUID, username string) {
	h := sha256.Sum256([]byte("OfflinePlayer:" + username))
	copy(uuid[:], h[:16])
	uuid[6] = (uuid[6] & 0x0f) | 0x30 // UUID version 3
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // UUID variant
}
