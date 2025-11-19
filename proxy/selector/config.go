package selector

import (
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/serial"
)

// Config defines the configuration for the Selector outbound.
type Config struct {
    Proxies []string `json:"proxies"` // A list of outbound tags
    Default string   `json:"default"`
}

func (c *Config) GetDefaultProxy() string {
    if c.Default != "" {
        return c.Default
    }
    if len(c.Proxies) > 0 {
        return c.Proxies[0]
    }
    return ""
}