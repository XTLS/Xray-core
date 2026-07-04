package session

import (
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/client"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/control"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/server"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
)

// ValidateTunnel validates the subset of Config needed to run an embedded
// client or server tunnel (i.e. everything except the CLI-only mode/SOCKS/gen
// fields checked by Validate). RegisterDefaults must have been called first so
// the carrier and transport registries are populated.
func ValidateTunnel(cfg Config) error {
	if err := validateAuth(cfg); err != nil {
		return err
	}
	if err := validateTransportRegistration(cfg); err != nil {
		return err
	}
	if err := validateCommon(cfg); err != nil {
		return err
	}
	if err := validateTransportConfig(cfg); err != nil {
		return err
	}
	if err := validateLivenessConfig(cfg); err != nil {
		return err
	}
	if err := validateLifecycleConfig(cfg); err != nil {
		return err
	}
	return validateTrafficConfig(cfg)
}

// prepare applies transport + liveness defaults and derives the liveness and
// traffic configs shared by client and server construction.
func prepare(cfg Config) (Config, control.Config, transport.TrafficConfig, error) {
	cfg = ApplyTransportDefaults(cfg)
	cfg = ApplyLivenessDefaults(cfg)
	liveness, err := livenessConfig(cfg)
	if err != nil {
		return cfg, control.Config{}, transport.TrafficConfig{}, err
	}
	traffic, err := trafficConfig(cfg)
	if err != nil {
		return cfg, control.Config{}, transport.TrafficConfig{}, err
	}
	return cfg, liveness, traffic, nil
}

// ClientConfig builds the internal client (cnc-style) config from cfg, applying
// documented defaults. It is used by embedded callers that drive stream dialing
// themselves via client.StartTunnel instead of a local SOCKS listener. It does
// not override the process-wide DNS resolver.
func ClientConfig(cfg Config) (client.Config, error) {
	cfg, liveness, traffic, err := prepare(cfg)
	if err != nil {
		return client.Config{}, err
	}
	return client.Config{
		Transport:        cfg.Transport,
		Carrier:          cfg.Auth,
		RoomURL:          cfg.RoomID,
		ChannelID:        cfg.ChannelID,
		KeyHex:           cfg.KeyHex,
		DNSServer:        cfg.DNSServer,
		SOCKSUser:        cfg.SOCKSUser,
		SOCKSPass:        cfg.SOCKSPass,
		TransportOptions: buildTransportOptions(cfg),
		Engine:           cfg.Engine,
		URL:              cfg.URL,
		Token:            cfg.Token,
		AuthToken:        cfg.AuthToken,
		Liveness:         liveness,
		Traffic:          traffic,
		DeviceID:         cfg.DeviceID,
		DeviceIDPath:     cfg.DeviceIDPath,
		Claims:           cfg.Claims,
	}, nil
}

// ServerConfig builds the internal server config from cfg, applying documented
// defaults and wiring the given egress dial hook (which fully replaces the
// built-in TCP/SOCKS dialer when non-nil).
func ServerConfig(cfg Config, dial server.DialFunc) (server.Config, error) {
	cfg, liveness, traffic, err := prepare(cfg)
	if err != nil {
		return server.Config{}, err
	}
	return server.Config{
		Transport:        cfg.Transport,
		Carrier:          cfg.Auth,
		RoomURL:          cfg.RoomID,
		ChannelID:        cfg.ChannelID,
		KeyHex:           cfg.KeyHex,
		DNSServer:        cfg.DNSServer,
		SOCKSProxyAddr:   cfg.SOCKSProxyAddr,
		SOCKSProxyPort:   cfg.SOCKSProxyPort,
		SOCKSProxyUser:   cfg.SOCKSProxyUser,
		SOCKSProxyPass:   cfg.SOCKSProxyPass,
		TransportOptions: buildTransportOptions(cfg),
		Engine:           cfg.Engine,
		URL:              cfg.URL,
		Token:            cfg.Token,
		AuthToken:        cfg.AuthToken,
		Liveness:         liveness,
		Traffic:          traffic,
		DialHook:         dial,
	}, nil
}
