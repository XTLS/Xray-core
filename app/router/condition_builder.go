//go:build windows || wasm

package router

import (
	"context"
	"regexp"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

func (rr *RoutingRule) BuildCondition() (Condition, error) {
	conds := NewConditionChan()

	if len(rr.InboundTag) > 0 {
		conds.Add(NewInboundTagMatcher(rr.InboundTag))
	}

	if len(rr.Networks) > 0 {
		conds.Add(NewNetworkMatcher(rr.Networks))
	}

	if len(rr.Protocol) > 0 {
		conds.Add(NewProtocolMatcher(rr.Protocol))
	}

	if rr.PortList != nil {
		conds.Add(NewPortMatcher(rr.PortList, MatcherAsType_Target))
	}

	if rr.SourcePortList != nil {
		conds.Add(NewPortMatcher(rr.SourcePortList, MatcherAsType_Source))
	}

	if rr.LocalPortList != nil {
		conds.Add(NewPortMatcher(rr.LocalPortList, MatcherAsType_Local))
	}

	if rr.VlessRouteList != nil {
		conds.Add(NewPortMatcher(rr.VlessRouteList, MatcherAsType_VlessRoute))
	}

	if len(rr.UserEmail) > 0 {
		conds.Add(NewUserMatcher(rr.UserEmail))
	}

	if len(rr.Attributes) > 0 {
		configuredKeys := make(map[string]*regexp.Regexp)
		for key, value := range rr.Attributes {
			configuredKeys[strings.ToLower(key)] = regexp.MustCompile(value)
		}
		conds.Add(&AttributeMatcher{configuredKeys})
	}

	if len(rr.Geoip) > 0 {
		cond, err := NewIPMatcher(rr.Geoip, MatcherAsType_Target)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	}

	if len(rr.SourceGeoip) > 0 {
		cond, err := NewIPMatcher(rr.SourceGeoip, MatcherAsType_Source)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	}

	if len(rr.LocalGeoip) > 0 {
		cond, err := NewIPMatcher(rr.LocalGeoip, MatcherAsType_Local)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
		errors.LogWarning(context.Background(), "Due to some limitations, in UDP connections, localIP is always equal to listen interface IP, so \"localIP\" rule condition does not work properly on UDP inbound connections that listen on all interfaces")
	}

	if len(rr.Domain) > 0 {
		matcher, err := NewMphMatcherGroup(rr.Domain)
		if err != nil {
			return nil, errors.New("failed to build domain condition with MphDomainMatcher").Base(err)
		}
		errors.LogDebug(context.Background(), "MphDomainMatcher is enabled for ", len(rr.Domain), " domain rule(s)")
		conds.Add(matcher)
	}

	if conds.Len() == 0 {
		return nil, errors.New("this rule has no effective fields").AtWarning()
	}

	return conds, nil
}
