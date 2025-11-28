package hyconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	hyserver "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/server"
	"github.com/xtls/xray-core/proxy/hysteria2/hyextras/v2/auth"
	"github.com/xtls/xray-core/proxy/hysteria2/hyextras/v2/obfs"
	"github.com/xtls/xray-core/proxy/hysteria2/hyutils"
)

type ServerConfig struct {
	// Listen is unused in Xray integration (handled by inbound), kept for parity.
	Listen string `json:"listen" mapstructure:"listen"`

	Obfs struct {
		Type       string `json:"type" mapstructure:"type"`
		Salamander struct {
			Password string `json:"password" mapstructure:"password"`
		} `json:"salamander" mapstructure:"salamander"`
	} `json:"obfs" mapstructure:"obfs"`

	TLS  *ServerTLSConfig  `json:"tls" mapstructure:"tls"`
	QUIC ServerQUICConfig  `json:"quic" mapstructure:"quic"`
	Auth ServerAuthConfig  `json:"auth" mapstructure:"auth"`
	Band ServerBandwidth   `json:"bandwidth" mapstructure:"bandwidth"`
	Misc ServerMiscOptions `json:"-" mapstructure:"-"`

	IgnoreClientBandwidth bool          `json:"ignoreClientBandwidth" mapstructure:"ignoreClientBandwidth"`
	DisableUDP            bool          `json:"disableUDP" mapstructure:"disableUDP"`
	UDPIdleTimeout        time.Duration `json:"udpIdleTimeout" mapstructure:"udpIdleTimeout"`
}

type ServerTLSConfig struct {
	Cert     string `json:"cert" mapstructure:"cert"`
	Key      string `json:"key" mapstructure:"key"`
	ClientCA string `json:"clientCA" mapstructure:"clientCA"`
	SNIGuard string `json:"sniGuard" mapstructure:"sniGuard"`
}

type ServerQUICConfig struct {
	InitStreamReceiveWindow     uint64        `json:"initStreamReceiveWindow" mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64        `json:"maxStreamReceiveWindow" mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64        `json:"initConnReceiveWindow" mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64        `json:"maxConnReceiveWindow" mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration `json:"maxIdleTimeout" mapstructure:"maxIdleTimeout"`
	MaxIncomingStreams          int64         `json:"maxIncomingStreams" mapstructure:"maxIncomingStreams"`
	DisablePathMTUDiscovery     bool          `json:"disablePathMTUDiscovery" mapstructure:"disablePathMTUDiscovery"`
}

type ServerAuthConfig struct {
	Type     string            `json:"type" mapstructure:"type"`
	Password string            `json:"password" mapstructure:"password"`
	UserPass map[string]string `json:"userpass" mapstructure:"userpass"`
}

type ServerBandwidth struct {
	Up   string `json:"up" mapstructure:"up"`
	Down string `json:"down" mapstructure:"down"`
}

type ServerMiscOptions struct {
	IgnoreClientBandwidth bool          `json:"ignoreClientBandwidth" mapstructure:"ignoreClientBandwidth"`
	DisableUDP            bool          `json:"disableUDP" mapstructure:"disableUDP"`
	UDPIdleTimeout        time.Duration `json:"udpIdleTimeout" mapstructure:"udpIdleTimeout"`
}

type BuildOptions struct {
	UseTLSFromStream bool
	StreamTLS        *tls.Config
}

func (c *ServerConfig) Build(listener net.PacketConn, opts BuildOptions) (*hyserver.Config, error) {
	cfg := &hyserver.Config{
		Conn:                  listener,
		IgnoreClientBandwidth: c.IgnoreClientBandwidth || c.Misc.IgnoreClientBandwidth,
		DisableUDP:            c.DisableUDP || c.Misc.DisableUDP,
		UDPIdleTimeout:        c.UDPIdleTimeout,
	}
	if cfg.UDPIdleTimeout == 0 {
		cfg.UDPIdleTimeout = c.Misc.UDPIdleTimeout
	}

	if err := c.fillTLS(cfg, opts); err != nil {
		return nil, err
	}

	cfg.QUICConfig = hyserver.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             c.QUIC.MaxIncomingStreams,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}

	if err := c.fillBandwidth(cfg); err != nil {
		return nil, err
	}
	if err := c.fillAuth(cfg); err != nil {
		return nil, err
	}

	if err := c.applyObfs(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *ServerConfig) fillTLS(cfg *hyserver.Config, opts BuildOptions) error {
	if opts.UseTLSFromStream && opts.StreamTLS != nil {
		tlsCfg := opts.StreamTLS.Clone()
		if len(tlsCfg.NextProtos) == 0 {
			tlsCfg.NextProtos = []string{"h3"}
		}
		cfg.TLSConfig = hyserver.TLSConfig{
			Certificates:   tlsCfg.Certificates,
			GetCertificate: tlsCfg.GetCertificate,
			ClientCAs:      tlsCfg.ClientCAs,
		}
		return nil
	}

	if c.TLS == nil {
		return fmt.Errorf("tls is required when use_xray_tls is false")
	}
	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("tls cert/key cannot be empty")
	}

	loader := &hyutils.LocalCertificateLoader{
		CertFile: c.TLS.Cert,
		KeyFile:  c.TLS.Key,
	}
	switch strings.ToLower(c.TLS.SNIGuard) {
	case "", "dns-san":
		loader.SNIGuard = hyutils.SNIGuardDNSSAN
	case "strict":
		loader.SNIGuard = hyutils.SNIGuardStrict
	case "disable":
	default:
		return fmt.Errorf("unsupported tls.sniGuard: %s", c.TLS.SNIGuard)
	}

	if err := loader.InitializeCache(); err != nil {
		return err
	}
	cfg.TLSConfig.GetCertificate = loader.GetCertificate

	if c.TLS.ClientCA != "" {
		ca, err := os.ReadFile(c.TLS.ClientCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return fmt.Errorf("failed to parse client CA")
		}
		cfg.TLSConfig.ClientCAs = pool
	}
	return nil
}

func (c *ServerConfig) fillBandwidth(cfg *hyserver.Config) error {
	if c.Band.Up != "" {
		v, err := hyutils.ConvBandwidth(c.Band.Up)
		if err != nil {
			return err
		}
		cfg.BandwidthConfig.MaxTx = v
	}
	if c.Band.Down != "" {
		v, err := hyutils.ConvBandwidth(c.Band.Down)
		if err != nil {
			return err
		}
		cfg.BandwidthConfig.MaxRx = v
	}
	return nil
}

func (c *ServerConfig) fillAuth(cfg *hyserver.Config) error {
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		if c.Auth.Password == "" {
			return fmt.Errorf("auth.password is required")
		}
		cfg.Authenticator = &auth.PasswordAuthenticator{Password: c.Auth.Password}
	case "userpass":
		if len(c.Auth.UserPass) == 0 {
			return fmt.Errorf("auth.userpass is empty")
		}
		cfg.Authenticator = auth.NewUserPassAuthenticator(c.Auth.UserPass)
	default:
		return fmt.Errorf("unsupported auth.type: %s", c.Auth.Type)
	}
	return nil
}

func (c *ServerConfig) applyObfs(cfg *hyserver.Config) error {
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		return nil
	case "salamander":
		ob, err := obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return err
		}
		cfg.Conn = obfs.WrapPacketConn(cfg.Conn, ob)
	default:
		return fmt.Errorf("unsupported obfs.type: %s", c.Obfs.Type)
	}
	return nil
}

// DefaultMasqHandler returns a simple masquerade handler.
func DefaultMasqHandler() http.Handler {
	return http.NotFoundHandler()
}
