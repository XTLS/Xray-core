package bayed

import (
	"time"

	libbayed "github.com/EvrkMs/bayed-tls/bayed"
	"github.com/xtls/xray-core/transport/internet"
)

// ConfigFromStreamSettings extracts the bayed Config from stream settings.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

// GetBayedServerConfig converts the proto Config to the bayed library ServerConfig.
func (c *Config) GetBayedServerConfig() *libbayed.ServerConfig {
	cfg := &libbayed.ServerConfig{
		PSK:                 c.Psk,
		UpstreamAddr:        c.UpstreamAddr,
		Upstreams:           c.Upstreams,
		MaxHandshakesPerSec: int(c.MaxHandshakesPerSec),
		Show:                c.Show,
	}
	if c.UpstreamTimeoutMs > 0 {
		cfg.UpstreamTimeout = time.Duration(c.UpstreamTimeoutMs) * time.Millisecond
	}
	return cfg
}

// GetBayedClientConfig converts the proto Config to the bayed library ClientConfig.
func (c *Config) GetBayedClientConfig() *libbayed.ClientConfig {
	return &libbayed.ClientConfig{
		PSK:                c.Psk,
		ServerName:         c.ServerName,
		Fingerprint:        c.Fingerprint,
		InsecureSkipVerify: c.InsecureSkipVerify,
		Show:               c.Show,
	}
}
