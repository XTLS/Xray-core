package xmc

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

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

	handshakeLock sync.Mutex
	password      string
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  []byte
	packet        *packetStream
}

func (c *serverConn) handshake() error {
	c.handshakeLock.Lock()
	defer c.handshakeLock.Unlock()

	if c.state != serverStateHandshake {
		return nil
	}

	// handshake timeout
	err := c.c.SetDeadline(time.Now().Add(time.Second * 30))
	if err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer c.c.SetDeadline(time.Time{})

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

		// encrypt request

		var (
			serverId           String = String("")
			publicKey          Bytes  = Bytes(c.rsaPublicKey)
			verifyToken        Bytes  = Bytes(make([]byte, 4))
			shouldAuthenticate Varint = Varint(1)
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

		// verify password
		receivedPassword := decryptedVerifyToken[4:]

		if subtle.ConstantTimeCompare(receivedPassword, []byte(c.password)) != 1 {
			writeDisconnectPacket(c.writer, `{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}`)
			return fmt.Errorf("bad password")
		}

		propertyCount := Varint(0)
		if err = writePacket(c.writer, 0x02, &uuid, &username, &propertyCount); err != nil {
			return fmt.Errorf("write login success: %w", err)
		}

		pkt, err = readPacket(c.reader)
		if err != nil {
			return fmt.Errorf("read login acknowledged: %w", err)
		}
		if pkt.packetID != 0x03 {
			return fmt.Errorf("bad login acknowledged packet id: %d", pkt.packetID)
		}

		c.packet = newPacketStream(c.reader, c.writer, false)
		c.reader = c.packet
		c.writer = c.packet

		c.state = serverStateProxy

		return nil

	default:
		return fmt.Errorf("bad handshake packet: bad next state: %d", nextState)
	}
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
	if c.packet != nil {
		c.packet.Stop()
	}
	return c.c.Close()
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *serverConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *serverConn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c *serverConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *serverConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

func wrapConnServer(c net.Conn, password string, rsaPrivateKeyDER []byte, rsaPublicKey []byte) (*serverConn, error) {
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
		reader:        bufio.NewReader(c),
		writer:        c,
		c:             c,
		state:         serverStateHandshake,
		password:      password,
		rsaPrivateKey: rsaPrivateKey,
		rsaPublicKey:  rsaPublicKey,
	}

	return s, nil
}
