package tlsspoof

import (
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

func ParseOptions(spoof, method string) (string, Method, error) {
	if spoof == "" {
		if method != "" {
			return "", 0, errors.New("spoof_method requires spoof")
		}
		return "", 0, nil
	}
	if net.ParseIP(spoof) != nil {
		return "", 0, errors.New("tls_spoof: IP-literal server names are not allowed")
	}
	if !PlatformSupported {
		return "", 0, errors.New("tls_spoof is not supported on this platform")
	}
	parsedMethod, err := ParseMethod(method)
	if err != nil {
		return "", 0, err
	}
	return spoof, parsedMethod, nil
}

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
		return 0, fmt.Errorf("tls_spoof: unknown method: %s", s)
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
	fakeHello      []byte
	injectionCount int
	maxInjections  int // how many times to inject; default 1
}

// NewConn wraps a connection with TLS spoofing. maxInjections controls how
// many Write() calls will trigger a fake ClientHello injection (0 or 1 = single-shot).
func NewConn(conn net.Conn, method Method, fakeSNI string, maxInjections int) (*Conn, error) {
	spoofer, err := newRawSpoofer(conn, method)
	if err != nil {
		return nil, wrapPermissionError(err)
	}
	result, err := newConn(conn, spoofer, fakeSNI, maxInjections)
	if err != nil {
		spoofer.Close()
		return nil, err
	}
	return result, nil
}

func newConn(conn net.Conn, spoofer rawSpoofer, fakeSNI string, maxInjections int) (*Conn, error) {
	fakeHello, err := buildFakeClientHello(fakeSNI)
	if err != nil {
		return nil, func(err error, m string) error { return err }(err, "tls_spoof: build fake ClientHello")
	}
	if maxInjections <= 0 {
		maxInjections = 1
	}
	return &Conn{
		Conn:          conn,
		spoofer:       spoofer,
		fakeHello:     fakeHello,
		maxInjections: maxInjections,
	}, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.injectionCount >= c.maxInjections {
		return c.Conn.Write(b)
	}
	err = c.spoofer.Inject(c.fakeHello)
	if err != nil {
		return 0, func(err error, m string) error { return err }(err, "tls_spoof: inject")
	}
	c.injectionCount++
	if c.injectionCount >= c.maxInjections {
		closeErr := c.spoofer.Close()
		if closeErr != nil {
			return 0, func(err error, m string) error { return err }(closeErr, "tls_spoof: close spoofer")
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	return func(e1, e2 error) error {
		if e1 != nil {
			return e1
		}
		return e2
	}(c.Conn.Close(), c.spoofer.Close())
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.injectionCount >= c.maxInjections
}

func (c *Conn) Upstream() any {
	return c.Conn
}

// wrapPermissionError adds platform-specific hints when the spoofer fails
// due to insufficient privileges.
func wrapPermissionError(err error) error {
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		return fmt.Errorf("%w\n  Hint: run as root, or grant capabilities:\n  sudo setcap cap_net_raw,cap_net_admin+ep /path/to/xray", err)
	case "darwin":
		return fmt.Errorf("%w\n  Hint: TLS spoofing requires root on macOS. Run with: sudo ./xray", err)
	case "freebsd":
		return fmt.Errorf("%w\n  Hint: TLS spoofing requires root on FreeBSD. Run with: sudo ./xray", err)
	default:
		return err
	}
}
