package conf

import (
	"os"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "raw", "tcp":
		return "tcp", nil
	case "xhttp", "splithttp":
		return "splithttp", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "grpc":
		errors.PrintNonRemovalDeprecatedFeatureWarning("gRPC transport (with unnecessary costs, etc.)", "XHTTP stream-up H2")
		return "grpc", nil
	case "ws", "websocket":
		errors.PrintNonRemovalDeprecatedFeatureWarning("WebSocket transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
		return "websocket", nil
	case "httpupgrade":
		errors.PrintNonRemovalDeprecatedFeatureWarning("HTTPUpgrade transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
		return "httpupgrade", nil
	case "h2", "h3", "http":
		return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
	case "quic":
		return "", errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
	case "hysteria":
		return "hysteria", nil
	default:
		return "", errors.New("Config: unknown transport protocol: ", p)
	}
}

type StreamConfig struct {
	Address             *Address           `json:"address"`
	Port                uint16             `json:"port"`
	Network             *TransportProtocol `json:"network"`
	Security            string             `json:"security"`
	FinalMask           *FinalMask         `json:"finalmask"`
	TLSSettings         *TLSConfig         `json:"tlsSettings"`
	REALITYSettings     *REALITYConfig     `json:"realitySettings"`
	RAWSettings         *TCPConfig         `json:"rawSettings"`
	TCPSettings         *TCPConfig         `json:"tcpSettings"`
	XHTTPSettings       *SplitHTTPConfig   `json:"xhttpSettings"`
	SplitHTTPSettings   *SplitHTTPConfig   `json:"splithttpSettings"`
	KCPSettings         *KCPConfig         `json:"kcpSettings"`
	GRPCSettings        *GRPCConfig        `json:"grpcSettings"`
	WSSettings          *WebSocketConfig   `json:"wsSettings"`
	HTTPUPGRADESettings *HttpUpgradeConfig `json:"httpupgradeSettings"`
	HysteriaSettings    *HysteriaConfig    `json:"hysteriaSettings"`
	SocketSettings      *SocketConfig      `json:"sockopt"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		Port:         uint32(c.Port),
		ProtocolName: "tcp",
	}
	if c.Address != nil {
		config.Address = c.Address.Build()
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}

	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp" && config.ProtocolName != "grpc" {
			return nil, errors.New("REALITY only supports RAW, XHTTP and gRPC for now.")
		}
		if c.REALITYSettings == nil {
			return nil, errors.New(`REALITY: Empty "realitySettings".`)
		}
		ts, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, errors.PrintRemovedFeatureError(`Legacy XTLS`, `xtls-rprx-vision with TLS or REALITY`)
	default:
		return nil, errors.New(`Unknown security "` + c.Security + `".`)
	}

	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build RAW config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.XHTTPSettings != nil {
		c.SplitHTTPSettings = c.XHTTPSettings
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XHTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.KCPSettings != nil {
		ts, err := c.KCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build mKCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.GRPCSettings != nil {
		gs, err := c.GRPCSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build gRPC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build WebSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPUPGRADESettings != nil {
		hs, err := c.HTTPUPGRADESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build HTTPUpgrade config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.HysteriaSettings != nil {
		hs, err := c.HysteriaSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build Hysteria config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "hysteria",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}

	if c.FinalMask != nil {
		for _, mask := range c.FinalMask.Tcp {
			u, err := mask.Build(true)
			if err != nil {
				return nil, errors.New("failed to build mask with type ", mask.Type).Base(err)
			}
			config.Tcpmasks = append(config.Tcpmasks, serial.ToTypedMessage(u))
		}
		for _, mask := range c.FinalMask.Udp {
			u, err := mask.Build(false)
			if err != nil {
				return nil, errors.New("failed to build mask with type ", mask.Type).Base(err)
			}
			config.Udpmasks = append(config.Udpmasks, serial.ToTypedMessage(u))
		}
		if c.FinalMask.QuicParams != nil {
			profile := strings.ToLower(c.FinalMask.QuicParams.BbrProfile)
			switch profile {
			case "", string(bbr.ProfileConservative), string(bbr.ProfileStandard), string(bbr.ProfileAggressive):
				if profile == "" {
					profile = string(bbr.ProfileStandard)
				}
			default:
				return nil, errors.New("unknown bbr profile")
			}

			up, err := c.FinalMask.QuicParams.BrutalUp.Bps()
			if err != nil {
				return nil, err
			}
			down, err := c.FinalMask.QuicParams.BrutalDown.Bps()
			if err != nil {
				return nil, err
			}

			if up > 0 && up < 65536 {
				return nil, errors.New("BrutalUp must be at least 65536 bytes per second")
			}
			if down > 0 && down < 65536 {
				return nil, errors.New("BrutalDown must be at least 65536 bytes per second")
			}

			c.FinalMask.QuicParams.Congestion = strings.ToLower(c.FinalMask.QuicParams.Congestion)
			switch c.FinalMask.QuicParams.Congestion {
			case "", "brutal", "reno", "bbr":
			case "force-brutal":
				if up == 0 {
					return nil, errors.New("force-brutal requires up")
				}
			default:
				return nil, errors.New("unknown congestion control: ", c.FinalMask.QuicParams.Congestion, ", valid values: reno, bbr, brutal, force-brutal")
			}

			if (c.FinalMask.QuicParams.UdpHop.Interval.From != 0 && c.FinalMask.QuicParams.UdpHop.Interval.From < 5) || (c.FinalMask.QuicParams.UdpHop.Interval.To != 0 && c.FinalMask.QuicParams.UdpHop.Interval.To < 5) {
				return nil, errors.New("Interval must be at least 5")
			}

			if c.FinalMask.QuicParams.InitStreamReceiveWindow > 0 && c.FinalMask.QuicParams.InitStreamReceiveWindow < 16384 {
				return nil, errors.New("InitStreamReceiveWindow must be at least 16384")
			}
			if c.FinalMask.QuicParams.MaxStreamReceiveWindow > 0 && c.FinalMask.QuicParams.MaxStreamReceiveWindow < 16384 {
				return nil, errors.New("MaxStreamReceiveWindow must be at least 16384")
			}
			if c.FinalMask.QuicParams.InitConnectionReceiveWindow > 0 && c.FinalMask.QuicParams.InitConnectionReceiveWindow < 16384 {
				return nil, errors.New("InitConnectionReceiveWindow must be at least 16384")
			}
			if c.FinalMask.QuicParams.MaxConnectionReceiveWindow > 0 && c.FinalMask.QuicParams.MaxConnectionReceiveWindow < 16384 {
				return nil, errors.New("MaxConnectionReceiveWindow must be at least 16384")
			}
			if c.FinalMask.QuicParams.MaxIdleTimeout != 0 && (c.FinalMask.QuicParams.MaxIdleTimeout < 4 || c.FinalMask.QuicParams.MaxIdleTimeout > 120) {
				return nil, errors.New("MaxIdleTimeout must be between 4 and 120")
			}
			if c.FinalMask.QuicParams.KeepAlivePeriod != 0 && (c.FinalMask.QuicParams.KeepAlivePeriod < 2 || c.FinalMask.QuicParams.KeepAlivePeriod > 60) {
				return nil, errors.New("KeepAlivePeriod must be between 2 and 60")
			}
			if c.FinalMask.QuicParams.MaxIncomingStreams != 0 && c.FinalMask.QuicParams.MaxIncomingStreams < 8 {
				return nil, errors.New("MaxIncomingStreams must be at least 8")
			}

			if c.FinalMask.QuicParams.Debug {
				os.Setenv("HYSTERIA_BBR_DEBUG", "true")
				os.Setenv("HYSTERIA_BRUTAL_DEBUG", "true")
			}

			config.QuicParams = &internet.QuicParams{
				Congestion: c.FinalMask.QuicParams.Congestion,
				BbrProfile: profile,
				BrutalUp:   up,
				BrutalDown: down,
				UdpHop: &internet.UdpHop{
					Ports:       c.FinalMask.QuicParams.UdpHop.PortList.Build().Ports(),
					IntervalMin: int64(c.FinalMask.QuicParams.UdpHop.Interval.From),
					IntervalMax: int64(c.FinalMask.QuicParams.UdpHop.Interval.To),
				},
				InitStreamReceiveWindow: c.FinalMask.QuicParams.InitStreamReceiveWindow,
				MaxStreamReceiveWindow:  c.FinalMask.QuicParams.MaxStreamReceiveWindow,
				InitConnReceiveWindow:   c.FinalMask.QuicParams.InitConnectionReceiveWindow,
				MaxConnReceiveWindow:    c.FinalMask.QuicParams.MaxConnectionReceiveWindow,
				MaxIdleTimeout:          c.FinalMask.QuicParams.MaxIdleTimeout,
				KeepAlivePeriod:         c.FinalMask.QuicParams.KeepAlivePeriod,
				DisablePathMtuDiscovery: c.FinalMask.QuicParams.DisablePathMTUDiscovery,
				MaxIncomingStreams:      c.FinalMask.QuicParams.MaxIncomingStreams,
			}
		}
	}

	return config, nil
}

type ProxyConfig struct {
	Tag string `json:"tag"`

	// TransportLayerProxy: For compatibility.
	TransportLayerProxy bool `json:"transportLayer"`
}

// Build implements Buildable.
func (v *ProxyConfig) Build() (*internet.ProxyConfig, error) {
	if v.Tag == "" {
		return nil, errors.New("Proxy tag is not set.")
	}
	return &internet.ProxyConfig{
		Tag:                 v.Tag,
		TransportLayerProxy: v.TransportLayerProxy,
	}, nil
}
