package internet

import (
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
)

type ConfigCreator func() interface{}

var (
	globalTransportConfigCreatorCache = make(map[string]ConfigCreator)
	globalTransportSettings           []*TransportConfig
)

var strategy = [][]byte{
	//              name        strategy,   prefer, fallback
	{0, 0, 0}, //   AsIs        none,       /,      /
	{1, 0, 0}, //   UseIP       use,        both,   none
	{1, 4, 0}, //   UseIPv4     use,        4,      none
	{1, 6, 0}, //   UseIPv6     use,        6,      none
	{1, 4, 6}, //   UseIPv4v6   use,        4,      6
	{1, 6, 4}, //   UseIPv6v4   use,        6,      4
	{2, 0, 0}, //   ForceIP     force,      both,   none
	{2, 4, 0}, //   ForceIPv4   force,      4,      none
	{2, 6, 0}, //   ForceIPv6   force,      6,      none
	{2, 4, 6}, //   ForceIPv4v6 force,      4,      6
	{2, 6, 4}, //   ForceIPv6v4 force,      6,      4
}

const unknownProtocol = "unknown"

func transportProtocolToString(protocol TransportProtocol) string {
	switch protocol {
	case TransportProtocol_TCP:
		return "tcp"
	case TransportProtocol_UDP:
		return "udp"
	case TransportProtocol_HTTP:
		return "http"
	case TransportProtocol_MKCP:
		return "mkcp"
	case TransportProtocol_WebSocket:
		return "websocket"
	case TransportProtocol_DomainSocket:
		return "domainsocket"
	case TransportProtocol_HTTPUpgrade:
		return "httpupgrade"
	default:
		return unknownProtocol
	}
}

func RegisterProtocolConfigCreator(name string, creator ConfigCreator) error {
	if _, found := globalTransportConfigCreatorCache[name]; found {
		return newError("protocol ", name, " is already registered").AtError()
	}
	globalTransportConfigCreatorCache[name] = creator
	return nil
}

func CreateTransportConfig(name string) (interface{}, error) {
	creator, ok := globalTransportConfigCreatorCache[name]
	if !ok {
		return nil, newError("unknown transport protocol: ", name)
	}
	return creator(), nil
}

func (c *TransportConfig) GetTypedSettings() (interface{}, error) {
	return c.Settings.GetInstance()
}

func (c *TransportConfig) GetUnifiedProtocolName() string {
	if len(c.ProtocolName) > 0 {
		return c.ProtocolName
	}

	return transportProtocolToString(c.Protocol)
}

func (c *StreamConfig) GetEffectiveProtocol() string {
	if c == nil {
		return "tcp"
	}

	if len(c.ProtocolName) > 0 {
		return c.ProtocolName
	}

	return transportProtocolToString(c.Protocol)
}

func (c *StreamConfig) GetEffectiveTransportSettings() (interface{}, error) {
	protocol := c.GetEffectiveProtocol()
	return c.GetTransportSettingsFor(protocol)
}

func (c *StreamConfig) GetTransportSettingsFor(protocol string) (interface{}, error) {
	if c != nil {
		for _, settings := range c.TransportSettings {
			if settings.GetUnifiedProtocolName() == protocol {
				return settings.GetTypedSettings()
			}
		}
	}

	for _, settings := range globalTransportSettings {
		if settings.GetUnifiedProtocolName() == protocol {
			return settings.GetTypedSettings()
		}
	}

	return CreateTransportConfig(protocol)
}

func (c *StreamConfig) GetEffectiveSecuritySettings() (interface{}, error) {
	for _, settings := range c.SecuritySettings {
		if settings.Type == c.SecurityType {
			return settings.GetInstance()
		}
	}
	return serial.GetInstance(c.SecurityType)
}

func (c *StreamConfig) HasSecuritySettings() bool {
	return len(c.SecurityType) > 0
}

func ApplyGlobalTransportSettings(settings []*TransportConfig) error {
	features.PrintDeprecatedFeatureWarning("global transport settings")
	globalTransportSettings = settings
	return nil
}

func (c *ProxyConfig) HasTag() bool {
	return c != nil && len(c.Tag) > 0
}

func (m SocketConfig_TProxyMode) IsEnabled() bool {
	return m != SocketConfig_Off
}

func (s DomainStrategy) hasStrategy() bool {
	return strategy[s][0] != 0
}

func (s DomainStrategy) forceIP() bool {
	return strategy[s][0] == 2
}

func (s DomainStrategy) preferIP4() bool {
	return strategy[s][1] == 4 || strategy[s][1] == 0
}

func (s DomainStrategy) preferIP6() bool {
	return strategy[s][1] == 6 || strategy[s][1] == 0
}

func (s DomainStrategy) hasFallback() bool {
	return strategy[s][2] != 0
}

func (s DomainStrategy) fallbackIP4() bool {
	return strategy[s][2] == 4
}

func (s DomainStrategy) fallbackIP6() bool {
	return strategy[s][2] == 6
}
