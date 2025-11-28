package hyconfig

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	hyclient "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/client"
	"github.com/xtls/xray-core/proxy/hysteria2/hyextras/v2/obfs"
	"github.com/xtls/xray-core/proxy/hysteria2/hyutils"
)

type ClientConfig struct {
	Server string `json:"server"`
	Auth   string `json:"auth"`

	Obfs struct {
		Type       string `json:"type"`
		Salamander struct {
			Password string `json:"password"`
		} `json:"salamander"`
	} `json:"obfs"`

	TLS struct {
		SNI               string `json:"sni"`
		Insecure          bool   `json:"insecure"`
		PinSHA256         string `json:"pinSHA256"`
		CA                string `json:"ca"`
		ClientCertificate string `json:"clientCertificate"`
		ClientKey         string `json:"clientKey"`
	} `json:"tls"`

	QUIC struct {
		InitStreamReceiveWindow     uint64        `json:"initStreamReceiveWindow"`
		MaxStreamReceiveWindow      uint64        `json:"maxStreamReceiveWindow"`
		InitConnectionReceiveWindow uint64        `json:"initConnReceiveWindow"`
		MaxConnectionReceiveWindow  uint64        `json:"maxConnReceiveWindow"`
		MaxIdleTimeout              time.Duration `json:"maxIdleTimeout"`
		KeepAlivePeriod             time.Duration `json:"keepAlivePeriod"`
		DisablePathMTUDiscovery     bool          `json:"disablePathMTUDiscovery"`
	} `json:"quic"`

	Bandwidth struct {
		Up   string `json:"up"`
		Down string `json:"down"`
	} `json:"bandwidth"`

	FastOpen bool `json:"fastOpen"`
}

type ClientBuildOptions struct {
	UseTLSFromStream bool
	StreamTLS        *tls.Config
	ConnFactory      hyclient.ConnFactory
}

func (c *ClientConfig) Build(opts ClientBuildOptions) (*hyclient.Config, error) {
	if c.Server == "" {
		return nil, fmt.Errorf("server is empty")
	}
	if opts.ConnFactory == nil {
		return nil, fmt.Errorf("conn factory is nil")
	}

	addr, err := net.ResolveUDPAddr("udp", c.Server)
	if err != nil {
		return nil, err
	}

	cfg := &hyclient.Config{
		ConnFactory:     opts.ConnFactory,
		ServerAddr:      addr,
		Auth:            c.Auth,
		FastOpen:        c.FastOpen,
		BandwidthConfig: hyclient.BandwidthConfig{},
	}

	if err := c.fillTLS(cfg, opts); err != nil {
		return nil, err
	}
	c.fillQUIC(cfg)
	if err := c.fillBandwidth(cfg); err != nil {
		return nil, err
	}
	if err := c.applyObfs(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *ClientConfig) fillTLS(cfg *hyclient.Config, opts ClientBuildOptions) error {
	if opts.UseTLSFromStream && opts.StreamTLS != nil {
		t := opts.StreamTLS.Clone()
		cfg.TLSConfig.ServerName = t.ServerName
		cfg.TLSConfig.InsecureSkipVerify = t.InsecureSkipVerify
		cfg.TLSConfig.VerifyPeerCertificate = t.VerifyPeerCertificate
		cfg.TLSConfig.RootCAs = t.RootCAs
		cfg.TLSConfig.GetClientCertificate = t.GetClientCertificate
		return nil
	}

	if c.TLS.SNI != "" {
		cfg.TLSConfig.ServerName = c.TLS.SNI
	}
	cfg.TLSConfig.InsecureSkipVerify = c.TLS.Insecure

	if c.TLS.PinSHA256 != "" {
		nHash := normalizeCertHash(c.TLS.PinSHA256)
		cfg.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			hash := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(hash[:]) == nHash {
				return nil
			}
			return fmt.Errorf("certificate hash mismatch")
		}
	}

	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return fmt.Errorf("failed to parse CA")
		}
		cfg.TLSConfig.RootCAs = pool
	}

	if c.TLS.ClientCertificate != "" && c.TLS.ClientKey != "" {
		loader := &hyutils.LocalCertificateLoader{
			CertFile: c.TLS.ClientCertificate,
			KeyFile:  c.TLS.ClientKey,
		}
		if err := loader.InitializeCache(); err != nil {
			return err
		}
		cfg.TLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loader.GetCertificate(nil)
		}
	}

	return nil
}

func (c *ClientConfig) fillQUIC(cfg *hyclient.Config) {
	cfg.QUICConfig = hyclient.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
}

func (c *ClientConfig) fillBandwidth(cfg *hyclient.Config) error {
	if c.Bandwidth.Up != "" {
		v, err := hyutils.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return err
		}
		cfg.BandwidthConfig.MaxTx = v
	}
	if c.Bandwidth.Down != "" {
		v, err := hyutils.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return err
		}
		cfg.BandwidthConfig.MaxRx = v
	}
	return nil
}

func (c *ClientConfig) applyObfs(cfg *hyclient.Config) error {
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		return nil
	case "salamander":
		ob, err := obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return err
		}
		cfg.ConnFactory = &adaptiveConnFactory{
			NewFunc:    cfg.ConnFactory.New,
			Obfuscator: ob,
		}
	default:
		return fmt.Errorf("unsupported obfs.type: %s", c.Obfs.Type)
	}
	return nil
}

func normalizeCertHash(hash string) string {
	n := strings.ToLower(strings.TrimSpace(hash))
	return strings.TrimPrefix(n, "0x")
}

// adaptiveConnFactory wraps another ConnFactory and applies obfuscation if configured.
type adaptiveConnFactory struct {
	NewFunc    func(net.Addr) (net.PacketConn, error)
	Obfuscator obfs.Obfuscator
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	pc, err := f.NewFunc(addr)
	if err != nil || f.Obfuscator == nil {
		return pc, err
	}
	return obfs.WrapPacketConn(pc, f.Obfuscator), nil
}
