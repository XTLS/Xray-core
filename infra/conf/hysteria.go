package conf

import (
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/xtls/xray-core/proxy/hysteria2"
	"github.com/xtls/xray-core/proxy/hysteria2/hyconfig"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type hysteriaObfs struct {
	Type       string `json:"type"`
	Salamander struct {
		Password string `json:"password"`
	} `json:"salamander"`
}

type hysteriaServerTLS struct {
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"clientCA"`
	SNIGuard string `json:"sniGuard"`
}

type hysteriaQUIC struct {
	InitStreamReceiveWindow     uint64 `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64 `json:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64 `json:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64 `json:"maxConnReceiveWindow"`
	MaxIdleTimeout              uint64 `json:"maxIdleTimeout"` // seconds
	MaxIncomingStreams          int64  `json:"maxIncomingStreams"`
	DisablePathMTUDiscovery     bool   `json:"disablePathMTUDiscovery"`
}

type hysteriaBandwidth struct {
	Up   string `json:"up"`
	Down string `json:"down"`
}

type HysteriaInboundConfig struct {
	Auth                  map[string]any    `json:"auth"`
	TLS                   hysteriaServerTLS `json:"tls"`
	Obfs                  hysteriaObfs      `json:"obfs"`
	QUIC                  hysteriaQUIC      `json:"quic"`
	Bandwidth             hysteriaBandwidth `json:"bandwidth"`
	IgnoreClientBandwidth bool              `json:"ignoreClientBandwidth"`
	DisableUDP            bool              `json:"disableUDP"`
	UDPIdleTimeout        uint64            `json:"udpIdleTimeout"` // seconds
}

func (c *HysteriaInboundConfig) Build() (proto.Message, error) {
	var cfg hyconfig.ServerConfig
	cfg.Obfs.Type = c.Obfs.Type
	cfg.Obfs.Salamander.Password = c.Obfs.Salamander.Password
	cfg.TLS = &hyconfig.ServerTLSConfig{
		Cert:     c.TLS.Cert,
		Key:      c.TLS.Key,
		ClientCA: c.TLS.ClientCA,
		SNIGuard: c.TLS.SNIGuard,
	}
	cfg.QUIC = hyconfig.ServerQUICConfig{
		InitStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:      c.QUIC.MaxStreamReceiveWindow,
		InitConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:  c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:              time.Duration(c.QUIC.MaxIdleTimeout) * time.Second,
		MaxIncomingStreams:          c.QUIC.MaxIncomingStreams,
		DisablePathMTUDiscovery:     c.QUIC.DisablePathMTUDiscovery,
	}
	cfg.Auth = hyconfig.ServerAuthConfig{
		Type:     toString(c.Auth["type"]),
		Password: toString(c.Auth["password"]),
	}
	if m, ok := c.Auth["userpass"].(map[string]any); ok {
		cfg.Auth.UserPass = make(map[string]string, len(m))
		for k, v := range m {
			cfg.Auth.UserPass[k] = toString(v)
		}
	}
	cfg.Band.Up = c.Bandwidth.Up
	cfg.Band.Down = c.Bandwidth.Down
	cfg.IgnoreClientBandwidth = c.IgnoreClientBandwidth
	cfg.DisableUDP = c.DisableUDP
	cfg.UDPIdleTimeout = time.Duration(c.UDPIdleTimeout) * time.Second

	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	st, err := structpb.NewStruct(m)
	if err != nil {
		return nil, err
	}
	return &hysteria2.InboundConfig{Settings: st}, nil
}

type HysteriaOutboundServer struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

type HysteriaOutboundConfig struct {
	Server *HysteriaOutboundServer `json:"server"`
	Auth   string                  `json:"auth"`
	TLS    struct {
		SNI       string `json:"sni"`
		Insecure  bool   `json:"insecure"`
		PinSHA256 string `json:"pinSHA256"`
		CA        string `json:"ca"`
		Cert      string `json:"clientCertificate"`
		Key       string `json:"clientKey"`
	} `json:"tls"`
	Obfs      hysteriaObfs      `json:"obfs"`
	QUIC      hysteriaQUIC      `json:"quic"`
	Bandwidth hysteriaBandwidth `json:"bandwidth"`
	FastOpen  bool              `json:"fastOpen"`
}

func (c *HysteriaOutboundConfig) Build() (proto.Message, error) {
	var cfg hyconfig.ClientConfig
	if c.Server != nil && c.Server.Address != nil {
		cfg.Server = net.JoinHostPort(c.Server.Address.String(), toPortString(c.Server.Port))
	}
	cfg.Auth = c.Auth
	cfg.Obfs.Type = c.Obfs.Type
	cfg.Obfs.Salamander.Password = c.Obfs.Salamander.Password
	cfg.TLS.SNI = c.TLS.SNI
	cfg.TLS.Insecure = c.TLS.Insecure
	cfg.TLS.PinSHA256 = c.TLS.PinSHA256
	cfg.TLS.CA = c.TLS.CA
	cfg.TLS.ClientCertificate = c.TLS.Cert
	cfg.TLS.ClientKey = c.TLS.Key
	cfg.QUIC.InitStreamReceiveWindow = c.QUIC.InitStreamReceiveWindow
	cfg.QUIC.MaxStreamReceiveWindow = c.QUIC.MaxStreamReceiveWindow
	cfg.QUIC.InitConnectionReceiveWindow = c.QUIC.InitConnectionReceiveWindow
	cfg.QUIC.MaxConnectionReceiveWindow = c.QUIC.MaxConnectionReceiveWindow
	cfg.QUIC.MaxIdleTimeout = time.Duration(c.QUIC.MaxIdleTimeout) * time.Second
	cfg.QUIC.DisablePathMTUDiscovery = c.QUIC.DisablePathMTUDiscovery
	cfg.Bandwidth.Up = c.Bandwidth.Up
	cfg.Bandwidth.Down = c.Bandwidth.Down
	cfg.FastOpen = c.FastOpen

	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	st, err := structpb.NewStruct(m)
	if err != nil {
		return nil, err
	}
	return &hysteria2.OutboundConfig{Settings: st}, nil
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toPortString(p uint16) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(int(p))
}

func init() {
	_ = inboundConfigLoader.cache.RegisterCreator("hysteria2", func() interface{} { return new(HysteriaInboundConfig) })
	_ = outboundConfigLoader.cache.RegisterCreator("hysteria2", func() interface{} { return new(HysteriaOutboundConfig) })
}
