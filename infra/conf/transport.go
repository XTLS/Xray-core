package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/global"
)

type TransportConfig struct {
	TCPConfig         *TCPConfig          `json:"tcpSettings"`
	KCPConfig         *KCPConfig          `json:"kcpSettings"`
	WSConfig          *WebSocketConfig    `json:"wsSettings"`
	HTTPConfig        *HTTPConfig         `json:"httpSettings"`
	GRPCConfig        *GRPCConfig         `json:"grpcSettings"`
	GUNConfig         *GRPCConfig         `json:"gunSettings"`
	HTTPUPGRADEConfig *HttpUpgradeConfig  `json:"httpupgradeSettings"`
	SplitHTTPConfig   *SplitHTTPConfig    `json:"splithttpSettings"`
}

// Build implements Buildable.
func (c *TransportConfig) Build() (*global.Config, error) {
	config := new(global.Config)

	// if any valid transport config
	if c.TCPConfig != nil || c.KCPConfig != nil || c.WSConfig != nil || c.HTTPConfig != nil || c.GRPCConfig != nil || c.GUNConfig != nil || c.HTTPUPGRADEConfig != nil || c.SplitHTTPConfig != nil {
		return nil, errors.New("Global transport config is deprecated")
	}

	return config, nil
}
