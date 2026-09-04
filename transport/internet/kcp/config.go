package kcp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.UplinkCapacity * 1024 * 1024 / c.Mtu / (1000 / c.Tti)
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetSendingBufferSize() uint32 {
	return c.MaxSendingWindow / c.Mtu
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.DownlinkCapacity * 1024 * 1024 / c.Mtu / (1000 / c.Tti)
	if size < 8 {
		size = 8
	}
	return size
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(ProtocolName, func() interface{} {
		return &Config{
			Mtu:              1350,
			Tti:              50,
			UplinkCapacity:   5,
			DownlinkCapacity: 20,
			CwndMultiplier:   1,
			MaxSendingWindow: 2 * 1024 * 1024,
		}
	}))
}
