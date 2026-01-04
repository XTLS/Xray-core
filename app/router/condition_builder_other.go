//go:build ios || darwin

package router

import (
	"context"
	"regexp"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem/assets"
	"google.golang.org/protobuf/proto"
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
		geoip, err := getGeoIPList(rr.Geoip)
		if err != nil {
			return nil, errors.New("failed to build geoip from mmap").Base(err)
		}

		cond, err := NewIPMatcher(geoip, MatcherAsType_Target)
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
		domains, err := getDomainList(rr.Domain)
		if err != nil {
			return nil, errors.New("failed to build domains from mmap").Base(err)
		}

		matcher, err := NewMphMatcherGroup(domains)
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

func getGeoIPList(ips []*GeoIP) ([]*GeoIP, error) {
	geoipList := []*GeoIP{}
	for _, ip := range ips {
		if ip.CountryCode != "" {
			geoMeta := assets.GeoIP.GetGeoMeta(ip.CountryCode)
			if geoMeta == nil || geoMeta.Length == 0 {
				return nil, errors.New("geoip not founded: ", ip.CountryCode)
			}

			bs := assets.GeoIP.Slice(geoMeta.Start, geoMeta.Start+geoMeta.Length)
			var geoip GeoIP

			if err := proto.Unmarshal(bs, &geoip); err != nil {
				return nil, errors.New("failed Unmarshal :").Base(err)
			}
			geoipList = append(geoipList, &geoip)

		} else {
			geoipList = append(geoipList, ip)
		}
	}
	return geoipList, nil

}

func getDomainList(domains []*Domain) ([]*Domain, error) {
	domainList := []*Domain{}
	for _, domain := range domains {
		if code, ok := strings.CutPrefix(domain.Value, "geosite:"); ok {

			geoMeta := assets.GeoSite.GetGeoMeta(code)
			if geoMeta == nil || geoMeta.Length == 0 {
				return nil, errors.New("geosite not founded: ", code)
			}
			bs := assets.GeoSite.Slice(geoMeta.Start, geoMeta.Start+geoMeta.Length)
			var geosite GeoSite

			if err := proto.Unmarshal(bs, &geosite); err != nil {
				return nil, errors.New("failed Unmarshal :").Base(err)
			}
			domainList = append(domainList, geosite.Domain...)

		} else {
			domainList = append(domainList, domain)
		}
	}
	return domainList, nil
}
