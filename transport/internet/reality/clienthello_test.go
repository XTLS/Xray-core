package reality

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type recordingConn struct {
	writes [][]byte
}

func (*recordingConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (*recordingConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (dummyAddr) Network() string  { return "tcp" }
func (a dummyAddr) String() string { return string(a) }

func newChromeClientHello(conn net.Conn) *utls.UConn {
	return utls.UClient(conn, &utls.Config{
		ServerName:             "www.example.com",
		SessionTicketsDisabled: true,
	}, utls.HelloChrome_Auto)
}

func buildChromeClientHello(t *testing.T) *utls.UConn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	uConn := newChromeClientHello(client)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return uConn
}

func TestCompactClientHelloUsesOneTLSRecordWrite(t *testing.T) {
	conn := new(recordingConn)
	uConn := newChromeClientHello(conn)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if err := applyClientHelloPolicy(uConn, &Config{
		Fingerprint:        "chrome",
		ClientHelloProfile: ClientHelloProfileCompactSingleSegment,
	}); err != nil {
		t.Fatal(err)
	}
	wantSize := clientHelloRecordSize(uConn)

	if err := uConn.Handshake(); err == nil {
		t.Fatal("expected handshake to stop when the recording connection returns EOF")
	}
	if len(conn.writes) != 1 {
		t.Fatalf("expected one write for ClientHello, got %d", len(conn.writes))
	}
	record := conn.writes[0]
	if uint32(len(record)) != wantSize {
		t.Fatalf("first write size = %d, want %d", len(record), wantSize)
	}
	if len(record) < 5 || record[0] != 22 {
		t.Fatalf("first write is not a TLS handshake record: %x", record)
	}
	if int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 {
		t.Fatalf("TLS record length does not match first write size: %d", len(record))
	}
}

func TestCompactClientHello(t *testing.T) {
	uConn := buildChromeClientHello(t)
	originalSize := clientHelloRecordSize(uConn)
	if originalSize <= DefaultCompactClientHelloMaxBytes {
		t.Fatalf("expected the Chrome ClientHello to exceed %d bytes, got %d", DefaultCompactClientHelloMaxBytes, originalSize)
	}

	err := applyClientHelloPolicy(uConn, &Config{
		Fingerprint:        "chrome",
		ClientHelloProfile: ClientHelloProfileCompactSingleSegment,
	})
	if err != nil {
		t.Fatal(err)
	}

	compactSize := clientHelloRecordSize(uConn)
	t.Logf("Chrome ClientHello record size: original=%d compact=%d", originalSize, compactSize)
	if compactSize > DefaultCompactClientHelloMaxBytes {
		t.Fatalf("compact ClientHello is %d bytes, limit is %d", compactSize, DefaultCompactClientHelloMaxBytes)
	}
	if compactSize >= originalSize {
		t.Fatalf("compact ClientHello did not shrink: original=%d compact=%d", originalSize, compactSize)
	}

	hasX25519 := false
	for _, keyShare := range uConn.HandshakeState.Hello.KeyShares {
		switch keyShare.Group {
		case utls.X25519:
			hasX25519 = true
		case utls.X25519MLKEM768, utls.X25519Kyber768Draft00:
			t.Fatalf("compact ClientHello still contains hybrid key share %v", keyShare.Group)
		}
	}
	if !hasX25519 {
		t.Fatal("compact ClientHello has no X25519 key share")
	}
}

func TestClientHelloLimitWithoutProfileDoesNotModifyHello(t *testing.T) {
	uConn := buildChromeClientHello(t)
	original := append([]byte(nil), uConn.HandshakeState.Hello.Raw...)
	originalSize := clientHelloRecordSize(uConn)

	err := applyClientHelloPolicy(uConn, &Config{
		Fingerprint:         "chrome",
		ClientHelloMaxBytes: originalSize - 1,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds configured limit") {
		t.Fatalf("expected a size error, got %v", err)
	}
	if string(original) != string(uConn.HandshakeState.Hello.Raw) {
		t.Fatal("size-only policy modified ClientHello")
	}
}

func TestClientHelloPolicyValidation(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		profile     string
		maxBytes    uint32
		wantError   bool
	}{
		{name: "disabled"},
		{name: "compact chrome", fingerprint: "chrome", profile: ClientHelloProfileCompactSingleSegment},
		{name: "compact default chrome", profile: ClientHelloProfileCompactSingleSegment},
		{name: "unknown profile", fingerprint: "chrome", profile: "unknown", wantError: true},
		{name: "non chrome profile", fingerprint: "firefox", profile: ClientHelloProfileCompactSingleSegment, wantError: true},
		{name: "record too large", maxBytes: maxSingleTLSRecordBytes + 1, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateClientHelloPolicy(test.fingerprint, test.profile, test.maxBytes)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateClientHelloPolicy() error = %v, wantError = %v", err, test.wantError)
			}
		})
	}
}
