package conf

import (
	"github.com/xtls/xray-core/app/policy"
)

type Policy struct {
	Handshake         *uint32 `json:"handshake,omitempty"`
	ConnectionIdle    *uint32 `json:"connIdle,omitempty"`
	UplinkOnly        *uint32 `json:"uplinkOnly,omitempty"`
	DownlinkOnly      *uint32 `json:"downlinkOnly,omitempty"`
	StatsUserUplink   bool    `json:"statsUserUplink,omitempty"`
	StatsUserDownlink bool    `json:"statsUserDownlink,omitempty"`
	BufferSize        *int32  `json:"bufferSize,omitempty"`
}

func (t *Policy) Build() (*policy.Policy, error) {
	config := new(policy.Policy_Timeout)
	if t.Handshake != nil {
		config.Handshake = &policy.Second{Value: *t.Handshake}
	}
	if t.ConnectionIdle != nil {
		config.ConnectionIdle = &policy.Second{Value: *t.ConnectionIdle}
	}
	if t.UplinkOnly != nil {
		config.UplinkOnly = &policy.Second{Value: *t.UplinkOnly}
	}
	if t.DownlinkOnly != nil {
		config.DownlinkOnly = &policy.Second{Value: *t.DownlinkOnly}
	}

	p := &policy.Policy{
		Timeout: config,
		Stats: &policy.Policy_Stats{
			UserUplink:   t.StatsUserUplink,
			UserDownlink: t.StatsUserDownlink,
		},
	}

	if t.BufferSize != nil {
		bs := int32(-1)
		if *t.BufferSize >= 0 {
			bs = (*t.BufferSize) * 1024
		}
		p.Buffer = &policy.Policy_Buffer{
			Connection: bs,
		}
	}

	return p, nil
}

type SystemPolicy struct {
	StatsInboundUplink    bool `json:"statsInboundUplink,omitempty"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink,omitempty"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink,omitempty"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink,omitempty"`
}

func (p *SystemPolicy) Build() (*policy.SystemPolicy, error) {
	return &policy.SystemPolicy{
		Stats: &policy.SystemPolicy_Stats{
			InboundUplink:    p.StatsInboundUplink,
			InboundDownlink:  p.StatsInboundDownlink,
			OutboundUplink:   p.StatsOutboundUplink,
			OutboundDownlink: p.StatsOutboundDownlink,
		},
	}, nil
}

type PolicyConfig struct {
	Levels map[uint32]*Policy `json:"levels,omitempty"`
	System *SystemPolicy      `json:"system,omitempty"`
}

func (c *PolicyConfig) Build() (*policy.Config, error) {
	levels := make(map[uint32]*policy.Policy)
	for l, p := range c.Levels {
		if p != nil {
			pp, err := p.Build()
			if err != nil {
				return nil, err
			}
			levels[l] = pp
		}
	}
	config := &policy.Config{
		Level: levels,
	}

	if c.System != nil {
		sc, err := c.System.Build()
		if err != nil {
			return nil, err
		}
		config.System = sc
	}

	return config, nil
}
