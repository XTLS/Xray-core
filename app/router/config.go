package router

import (
	"context"
	"regexp"
	"runtime"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

type Rule struct {
	Tag       string
	RuleTag   string
	Balancer  *Balancer
	Condition Condition
}

func (r *Rule) GetTag() (string, error) {
	if r.Balancer != nil {
		return r.Balancer.PickOutbound()
	}
	return r.Tag, nil
}

// Apply checks rule matching of current routing context.
func (r *Rule) Apply(ctx routing.Context) bool {
	return r.Condition.Apply(ctx)
}

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
		geoip := rr.Geoip
		if runtime.GOOS != "windows" && runtime.GOOS != "wasm" {
			var err error
			geoip, err = GetGeoIPList(rr.Geoip)
			if err != nil {
				return nil, errors.New("failed to build geoip from mmap").Base(err)
			}
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
		domains := rr.Domain
		if runtime.GOOS != "windows" && runtime.GOOS != "wasm" {
			var err error
			domains, err = GetDomainList(rr.Domain)
			if err != nil {
				return nil, errors.New("failed to build domains from mmap").Base(err)
			}
		}

		matcher, err := NewMphMatcherGroup(domains)
		if err != nil {
			return nil, errors.New("failed to build domain condition with MphDomainMatcher").Base(err)
		}
		errors.LogDebug(context.Background(), "MphDomainMatcher is enabled for ", len(domains), " domain rule(s)")
		conds.Add(matcher)
	}

	if len(rr.Process) > 0 {
		conds.Add(NewProcessNameMatcher(rr.Process))
	}

	if conds.Len() == 0 {
		return nil, errors.New("this rule has no effective fields").AtWarning()
	}

	return conds, nil
}

// Build builds the balancing rule
func (br *BalancingRule) Build(ohm outbound.Manager, dispatcher routing.Dispatcher) (*Balancer, error) {
	switch strings.ToLower(br.Strategy) {
	case "leastping":
		return &Balancer{
			selectors:   br.OutboundSelector,
			strategy:    &LeastPingStrategy{},
			fallbackTag: br.FallbackTag,
			ohm:         ohm,
		}, nil
	case "roundrobin":
		return &Balancer{
			selectors:   br.OutboundSelector,
			strategy:    &RoundRobinStrategy{FallbackTag: br.FallbackTag},
			fallbackTag: br.FallbackTag,
			ohm:         ohm,
		}, nil
	case "leastload":
		i, err := br.StrategySettings.GetInstance()
		if err != nil {
			return nil, err
		}
		s, ok := i.(*StrategyLeastLoadConfig)
		if !ok {
			return nil, errors.New("not a StrategyLeastLoadConfig").AtError()
		}
		leastLoadStrategy := NewLeastLoadStrategy(s)
		return &Balancer{
			selectors:   br.OutboundSelector,
			ohm:         ohm,
			fallbackTag: br.FallbackTag,
			strategy:    leastLoadStrategy,
		}, nil
	case "random":
		fallthrough
	case "":
		return &Balancer{
			selectors:   br.OutboundSelector,
			ohm:         ohm,
			fallbackTag: br.FallbackTag,
			strategy:    &RandomStrategy{FallbackTag: br.FallbackTag},
		}, nil
	default:
		return nil, errors.New("unrecognized balancer type")
	}
}

func GetGeoIPList(ips []*GeoIP) ([]*GeoIP, error) {
	geoipList := []*GeoIP{}
	for _, ip := range ips {
		if ip.CountryCode != "" {
			val := strings.Split(ip.CountryCode, "_")
			fileName := "geoip.dat"
			if len(val) == 2 {
				fileName = strings.ToLower(val[0])
			}
			bs, err := filesystem.ReadAsset(fileName)
			if err != nil {
				return nil, errors.New("failed to load file: ", fileName).Base(err)
			}
			bs = filesystem.Find(bs, []byte(ip.CountryCode))

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

func GetDomainList(domains []*Domain) ([]*Domain, error) {
	domainList := []*Domain{}
	for _, domain := range domains {
		val := strings.Split(domain.Value, "_")

		if len(val) >= 2 {

			fileName := val[0]
			code := val[1]

			bs, err := filesystem.ReadAsset(fileName)
			if err != nil {
				return nil, errors.New("failed to load file: ", fileName).Base(err)
			}
			bs = filesystem.Find(bs, []byte(code))
			var geosite GeoSite

			if err := proto.Unmarshal(bs, &geosite); err != nil {
				return nil, errors.New("failed Unmarshal :").Base(err)
			}

			// parse attr
			if len(val) == 3 {
				siteWithAttr := strings.Split(val[2], ",")
				attrs := ParseAttrs(siteWithAttr)

				if !attrs.IsEmpty() {
					filteredDomains := make([]*Domain, 0, len(domains))
					for _, domain := range geosite.Domain {
						if attrs.Match(domain) {
							filteredDomains = append(filteredDomains, domain)
						}
					}
					geosite.Domain = filteredDomains
				}

			}

			domainList = append(domainList, geosite.Domain...)

		} else {
			domainList = append(domainList, domain)
		}
	}
	return domainList, nil
}
