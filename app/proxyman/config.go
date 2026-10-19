package proxyman

import (
	"slices"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/session"
)

func (c *SniffingConfig) Validate() error {
	if c.TlsSniffingTimeout == 0 {
		return nil
	}
	if c.TlsSniffingTimeout > 60000 {
		return errors.New("tlsSniffingTimeout must not exceed 60000 milliseconds")
	}
	if !c.Enabled || c.MetadataOnly || !slices.Contains(c.DestinationOverride, "tls") {
		return errors.New("tlsSniffingTimeout requires enabled content sniffing and tls in destOverride")
	}
	return nil
}

func BuildSniffingRequest(config *SniffingConfig) (session.SniffingRequest, error) {
	if config == nil {
		return session.SniffingRequest{}, nil
	}
	if err := config.Validate(); err != nil {
		return session.SniffingRequest{}, err
	}

	request := session.SniffingRequest{
		Enabled:                        config.Enabled,
		OverrideDestinationForProtocol: config.DestinationOverride,
		MetadataOnly:                   config.MetadataOnly,
		RouteOnly:                      config.RouteOnly,
		TLSSniffingTimeout:             time.Duration(config.TlsSniffingTimeout) * time.Millisecond,
	}
	if len(config.DomainsExcluded) > 0 {
		excludeForDomain, err := geodata.DomainReg.BuildDomainMatcher(config.DomainsExcluded)
		if err != nil {
			return session.SniffingRequest{}, err
		}
		request.ExcludeForDomain = excludeForDomain
	}
	if len(config.IpsExcluded) > 0 {
		excludeForIP, err := geodata.IPReg.BuildIPMatcher(config.IpsExcluded)
		if err != nil {
			return session.SniffingRequest{}, err
		}
		request.ExcludeForIP = excludeForIP
	}
	return request, nil
}
