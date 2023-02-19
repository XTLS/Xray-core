package reality

import (
	"time"

	"github.com/xtls/reality"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetREALITYConfig() *reality.Config {
	config := &reality.Config{
		Show: c.Show,
		Type: c.Type,
		Dest: c.Dest,
		Xver: byte(c.Xver),

		PrivateKey:   c.PrivateKey,
		MinClientVer: c.MinClientVer,
		MaxClientVer: c.MaxClientVer,
		MaxTimeDiff:  time.Duration(c.MaxTimeDiff) * time.Millisecond,

		NextProtos:             nil, // should be nil
		SessionTicketsDisabled: true,
	}
	config.ServerNames = make(map[string]bool)
	for _, serverName := range c.ServerNames {
		config.ServerNames[serverName] = true
	}
	config.ShortIds = make(map[[8]byte]bool)
	for _, shortId := range c.ShortIds {
		config.ShortIds[*(*[8]byte)(shortId)] = true
	}
	return config
}

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
