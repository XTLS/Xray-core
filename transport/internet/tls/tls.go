package tls

import (
	"crypto/rand"
	"crypto/tls"
	"math/big"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

type Interface interface {
	net.Conn
	Handshake() error
	VerifyHostname(host string) error
	NegotiatedProtocol() (name string, mutual bool)
}

var _ buf.Writer = (*Conn)(nil)

type Conn struct {
	*tls.Conn
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *Conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func (c *Conn) NegotiatedProtocol() (name string, mutual bool) {
	state := c.ConnectionState()
	return state.NegotiatedProtocol, state.NegotiatedProtocolIsMutual
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn}
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &Conn{Conn: tlsConn}
}

type UConn struct {
	*utls.UConn
}

func (c *UConn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

// WebsocketHandshake basically calls UConn.Handshake inside it but it will only send
// http/1.1 in its ALPN.
func (c *UConn) WebsocketHandshake() error {
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.Handshake()
}

func (c *UConn) NegotiatedProtocol() (name string, mutual bool) {
	state := c.ConnectionState()
	return state.NegotiatedProtocol, state.NegotiatedProtocolIsMutual
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	utlsConn := utls.UClient(c, copyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func copyConfig(c *tls.Config) *utls.Config {
	return &utls.Config{
		RootCAs:               c.RootCAs,
		ServerName:            c.ServerName,
		InsecureSkipVerify:    c.InsecureSkipVerify,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
	}
}

func init() {
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ModernFingerprints))))
	stopAt := int(bigInt.Int64())
	i := 0
	for _, v := range ModernFingerprints {
		if i == stopAt {
			PresetFingerprints["random"] = v
			break
		}
		i++
	}
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomized
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	PresetFingerprints["randomized"] = &randomized
}

func GetFingerprint(name string) (fingerprint *utls.ClientHelloID) {
	if name == "" {
		return
	}
	if fingerprint = PresetFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = ModernFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = OtherFingerprints[name]; fingerprint != nil {
		return
	}
	return
}

var PresetFingerprints = map[string]*utls.ClientHelloID{
	// Recommended preset options in GUI clients
	"chrome":     &utls.HelloChrome_Auto,
	"firefox":    &utls.HelloFirefox_Auto,
	"safari":     &utls.HelloSafari_Auto,
	"ios":        &utls.HelloIOS_Auto,
	"android":    &utls.HelloAndroid_11_OkHttp,
	"edge":       &utls.HelloEdge_Auto,
	"360":        &utls.Hello360_Auto,
	"qq":         &utls.HelloQQ_Auto,
	"random":     nil,
	"randomized": nil,
}

var ModernFingerprints = map[string]*utls.ClientHelloID{
	// One of these will be chosen as `random` at startup
	"hellofirefox_99":         &utls.HelloFirefox_99,
	"hellofirefox_102":        &utls.HelloFirefox_102,
	"hellofirefox_105":        &utls.HelloFirefox_105,
	"hellochrome_83":          &utls.HelloChrome_83,
	"hellochrome_87":          &utls.HelloChrome_87,
	"hellochrome_96":          &utls.HelloChrome_96,
	"hellochrome_100":         &utls.HelloChrome_100,
	"hellochrome_102":         &utls.HelloChrome_102,
	"hellochrome_106_shuffle": &utls.HelloChrome_106_Shuffle,
	"helloios_13":             &utls.HelloIOS_13,
	"helloios_14":             &utls.HelloIOS_14,
	"helloedge_85":            &utls.HelloEdge_85,
	"helloedge_106":           &utls.HelloEdge_106,
	"hellosafari_16_0":        &utls.HelloSafari_16_0,
	"hello360_11_0":           &utls.Hello360_11_0,
	"helloqq_11_1":            &utls.HelloQQ_11_1,
}

var OtherFingerprints = map[string]*utls.ClientHelloID{
	// Golang, randomized, auto, and fingerprints that are too old
	"hellogolang":            &utls.HelloGolang,
	"hellorandomized":        &utls.HelloRandomized,
	"hellorandomizedalpn":    &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":  &utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":      &utls.HelloFirefox_Auto,
	"hellofirefox_55":        &utls.HelloFirefox_55,
	"hellofirefox_56":        &utls.HelloFirefox_56,
	"hellofirefox_63":        &utls.HelloFirefox_63,
	"hellofirefox_65":        &utls.HelloFirefox_65,
	"hellochrome_auto":       &utls.HelloChrome_Auto,
	"hellochrome_58":         &utls.HelloChrome_58,
	"hellochrome_62":         &utls.HelloChrome_62,
	"hellochrome_70":         &utls.HelloChrome_70,
	"hellochrome_72":         &utls.HelloChrome_72,
	"helloios_auto":          &utls.HelloIOS_Auto,
	"helloios_11_1":          &utls.HelloIOS_11_1,
	"helloios_12_1":          &utls.HelloIOS_12_1,
	"helloandroid_11_okhttp": &utls.HelloAndroid_11_OkHttp,
	"helloedge_auto":         &utls.HelloEdge_Auto,
	"hellosafari_auto":       &utls.HelloSafari_Auto,
	"hello360_auto":          &utls.Hello360_Auto,
	"hello360_7_5":           &utls.Hello360_7_5,
	"helloqq_auto":           &utls.HelloQQ_Auto,
}
