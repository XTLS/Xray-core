package wireguard

func (c *DeviceConfig) preferIP4() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP ||
		c.DomainStrategy == DeviceConfig_FORCE_IP4 ||
		c.DomainStrategy == DeviceConfig_FORCE_IP46
}

func (c *DeviceConfig) preferIP6() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP ||
		c.DomainStrategy == DeviceConfig_FORCE_IP6 ||
		c.DomainStrategy == DeviceConfig_FORCE_IP64
}

func (c *DeviceConfig) hasFallback() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP46 || c.DomainStrategy == DeviceConfig_FORCE_IP64
}

func (c *DeviceConfig) fallbackIP4() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP64
}

func (c *DeviceConfig) fallbackIP6() bool {
	return c.DomainStrategy == DeviceConfig_FORCE_IP46
}
