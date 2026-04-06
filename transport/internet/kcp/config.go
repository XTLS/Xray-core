package kcp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetMTUValue() uint32 {
	if c.Mtu == 0 {
		return 1350
	}
	return c.Mtu
}

func (c *Config) GetTTIValue() uint32 {
	if c.Tti == 0 {
		return 50
	}
	return c.Tti
}

func (c *Config) GetCwndMultiplierValue() uint32 {
	if c.CwndMultiplier == 0 {
		return 1
	}
	return c.CwndMultiplier
}

func (c *Config) GetWriteBufferSize() uint32 {
	if c.WriteBuffer == 0 {
		return 2 * 1024 * 1024
	}
	return c.WriteBuffer
}

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.UplinkCapacity * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetSendingBufferSize() uint32 {
	return c.GetWriteBufferSize() / c.GetMTUValue()
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.DownlinkCapacity * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
