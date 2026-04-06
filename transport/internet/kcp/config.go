package kcp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

// GetMTUValue returns the value of MTU settings.
func (c *Config) GetMTUValue() uint32 {
	if c == nil || c.Mtu == 0 {
		return 1350
	}
	return c.Mtu
}

// GetTTIValue returns the value of TTI settings.
func (c *Config) GetTTIValue() uint32 {
	if c == nil || c.Tti == 0 {
		return 50
	}
	return c.Tti
}

// GetUplinkCapacityValue returns the value of UplinkCapacity settings.
func (c *Config) GetUplinkCapacityValue() uint32 {
	if c == nil || c.UplinkCapacity == 0 {
		return 5
	}
	return c.UplinkCapacity
}

// GetDownlinkCapacityValue returns the value of DownlinkCapacity settings.
func (c *Config) GetDownlinkCapacityValue() uint32 {
	if c == nil || c.DownlinkCapacity == 0 {
		return 20
	}
	return c.DownlinkCapacity
}

func (c *Config) GetCwndMultiplierValue() uint32 {
	if c == nil || c.CwndMultiplier == 0 {
		return 1
	}
	return c.CwndMultiplier
}

// GetWriteBufferSize returns the size of WriterBuffer in bytes.
func (c *Config) GetWriteBufferSize() uint32 {
	if c == nil || c.WriteBuffer == 0 {
		return 2 * 1024 * 1024
	}
	return c.WriteBuffer
}

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.GetUplinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetSendingBufferSize() uint32 {
	return c.GetWriteBufferSize() / c.GetMTUValue()
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.GetDownlinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
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
