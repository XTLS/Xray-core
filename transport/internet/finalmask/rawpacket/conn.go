package rawpacket

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
)

type Method int

const (
	MethodWrongSequence Method = iota
	MethodWrongChecksum
	MethodWrongAcknowledgment
	MethodWrongMD5Sig
	MethodWrongTimestamp
)

const (
	MethodNameWrongSequence       = "wrong-sequence"
	MethodNameWrongChecksum       = "wrong-checksum"
	MethodNameWrongAcknowledgment = "wrong-ack"
	MethodNameWrongMD5Sig         = "wrong-md5"
	MethodNameWrongTimestamp      = "wrong-timestamp"
)

func ParseMethod(s string) (Method, error) {
	switch s {
	case "", MethodNameWrongSequence:
		return MethodWrongSequence, nil
	case MethodNameWrongChecksum:
		return MethodWrongChecksum, nil
	case MethodNameWrongAcknowledgment:
		return MethodWrongAcknowledgment, nil
	case MethodNameWrongMD5Sig:
		return MethodWrongMD5Sig, nil
	case MethodNameWrongTimestamp:
		return MethodWrongTimestamp, nil
	default:
		return 0, fmt.Errorf("rawpacket: unknown method: %s", s)
	}
}

func (m Method) String() string {
	switch m {
	case MethodWrongSequence:
		return MethodNameWrongSequence
	case MethodWrongChecksum:
		return MethodNameWrongChecksum
	case MethodWrongAcknowledgment:
		return MethodNameWrongAcknowledgment
	case MethodWrongMD5Sig:
		return MethodNameWrongMD5Sig
	case MethodWrongTimestamp:
		return MethodNameWrongTimestamp
	default:
		return "unknown"
	}
}

type rawSpoofer interface {
	Inject(payload []byte) error
	Close() error
}

type Conn struct {
	net.Conn
	spoofer        rawSpoofer
	fakePayload    []byte
	injectionCount int
	maxInjections  int
}

func NewConnClient(cfg *Config, conn net.Conn) (net.Conn, error) {
	if cfg.Payload == "" && cfg.Sni == "" {
		return conn, nil
	}
	if !PlatformSupported {
		return nil, errors.New("rawpacket is not supported on this platform")
	}
	var payload []byte
	var err error
	if cfg.Payload != "" {
		payload, err = base64.StdEncoding.DecodeString(cfg.Payload)
		if err != nil {
			return nil, fmt.Errorf("rawpacket: invalid base64 payload: %w", err)
		}
		if len(payload) == 0 {
			return nil, errors.New("rawpacket: payload is empty")
		}
	} else {
		payload, err = BuildFakeClientHello(cfg.Sni)
		if err != nil {
			return nil, fmt.Errorf("rawpacket: build fake ClientHello: %w", err)
		}
	}
	method, err := ParseMethod(cfg.Method)
	if err != nil {
		return nil, err
	}
	ttl := uint8(cfg.Ttl)
	if ttl == 0 {
		ttl = 3
	}
	spoofer, err := newRawSpoofer(conn, method, ttl)
	if err != nil {
		return nil, wrapPermissionError(err)
	}
	maxInjections := int(cfg.Count)
	if maxInjections <= 0 {
		maxInjections = 1
	}
	return &Conn{
		Conn:          conn,
		spoofer:       spoofer,
		fakePayload:   payload,
		maxInjections: maxInjections,
	}, nil
}

func NewConnServer(_ *Config, conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.injectionCount >= c.maxInjections {
		return c.Conn.Write(b)
	}
	closeSpoofer := false
	defer func() {
		if closeSpoofer {
			if closeErr := c.spoofer.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("rawpacket: close spoofer: %w", closeErr)
			}
		}
	}()
	err = c.spoofer.Inject(c.fakePayload)
	if err != nil {
		return 0, fmt.Errorf("rawpacket: inject: %w", err)
	}
	c.injectionCount++
	if c.injectionCount >= c.maxInjections {
		closeSpoofer = true
	}
	n, err = c.Conn.Write(b)
	return n, err
}

func (c *Conn) Close() error {
	connErr := c.Conn.Close()
	spooferErr := c.spoofer.Close()
	if connErr != nil {
		return connErr
	}
	return spooferErr
}

func (c *Conn) TcpMaskConn() {}

func (c *Conn) RawConn() net.Conn {
	return c.Conn
}

func (c *Conn) Splice() bool {
	return c.injectionCount >= c.maxInjections
}

func wrapPermissionError(err error) error {
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		return fmt.Errorf("%w\n  Hint: run as root, or grant capabilities:\n  sudo setcap cap_net_raw,cap_net_admin+ep /path/to/xray", err)
	case "darwin":
		return fmt.Errorf("%w\n  Hint: rawpacket requires root on macOS. Run with: sudo ./xray", err)
	case "freebsd":
		return fmt.Errorf("%w\n  Hint: rawpacket requires root on FreeBSD. Run with: sudo ./xray", err)
	case "windows":
		return fmt.Errorf("%w\n  Hint: rawpacket requires Administrator on Windows (WinDivert driver)", err)
	default:
		return err
	}
}
