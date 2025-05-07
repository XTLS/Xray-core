package dns

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// Server is the interface for Name Server.
type Server interface {
	// Name of the Client.
	Name() string
	// QueryIP sends IP queries to its configured server.
	QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error)
}

// Client is the interface for DNS client.
type Client struct {
	server        Server
	skipFallback  bool
	domains       []string
	expectedIPs   []*router.GeoIPMatcher
	unexpectedIPs []*router.GeoIPMatcher
	actPrior      bool
	actUnprior    bool
	tag           string
	timeoutMs     time.Duration
	finalQuery    bool
	ipOption      *dns.IPOption
	checkSystem   bool
}

// NewServer creates a name server object according to the network destination url.
func NewServer(ctx context.Context, dest net.Destination, dispatcher routing.Dispatcher, disableCache bool, clientIP net.IP) (Server, error) {
	if address := dest.Address; address.Family().IsDomain() {
		u, err := url.Parse(address.Domain())
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(), nil
		case strings.EqualFold(u.Scheme, "https"): // DNS-over-HTTPS Remote mode
			return NewDoHNameServer(u, dispatcher, false, disableCache, clientIP), nil
		case strings.EqualFold(u.Scheme, "h2c"): // DNS-over-HTTPS h2c Remote mode
			return NewDoHNameServer(u, dispatcher, true, disableCache, clientIP), nil
		case strings.EqualFold(u.Scheme, "https+local"): // DNS-over-HTTPS Local mode
			return NewDoHNameServer(u, nil, false, disableCache, clientIP), nil
		case strings.EqualFold(u.Scheme, "h2c+local"): // DNS-over-HTTPS h2c Local mode
			return NewDoHNameServer(u, nil, true, disableCache, clientIP), nil
		case strings.EqualFold(u.Scheme, "quic+local"): // DNS-over-QUIC Local mode
			return NewQUICNameServer(u, disableCache, clientIP)
		case strings.EqualFold(u.Scheme, "tcp"): // DNS-over-TCP Remote mode
			return NewTCPNameServer(u, dispatcher, disableCache, clientIP)
		case strings.EqualFold(u.Scheme, "tcp+local"): // DNS-over-TCP Local mode
			return NewTCPLocalNameServer(u, disableCache, clientIP)
		case strings.EqualFold(u.String(), "fakedns"):
			var fd dns.FakeDNSEngine
			err = core.RequireFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				fd = fdns
			})
			if err != nil {
				return nil, err
			}
			return NewFakeDNSServer(fd), nil
		}
	}
	if dest.Network == net.Network_Unknown {
		dest.Network = net.Network_UDP
	}
	if dest.Network == net.Network_UDP { // UDP classic DNS mode
		return NewClassicNameServer(dest, dispatcher, disableCache, clientIP), nil
	}
	return nil, errors.New("No available name server could be created from ", dest).AtWarning()
}

// NewClient creates a DNS client managing a name server with client IP, domain rules and expected IPs.
func NewClient(
	ctx context.Context,
	ns *NameServer,
	clientIP net.IP,
	disableCache bool,
	tag string,
	ipOption dns.IPOption,
	matcherInfos *[]*DomainMatcherInfo,
	updateDomainRule func(strmatcher.Matcher, int, []*DomainMatcherInfo) error,
) (*Client, error) {
	client := &Client{}

	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		// Create a new server for each client for now
		server, err := NewServer(ctx, ns.Address.AsDestination(), dispatcher, disableCache, clientIP)
		if err != nil {
			return errors.New("failed to create nameserver").Base(err).AtWarning()
		}

		// Prioritize local domains with specific TLDs or those without any dot for the local DNS
		if _, isLocalDNS := server.(*LocalNameServer); isLocalDNS {
			ns.PrioritizedDomain = append(ns.PrioritizedDomain, localTLDsAndDotlessDomains...)
			ns.OriginalRules = append(ns.OriginalRules, localTLDsAndDotlessDomainsRule)
			// The following lines is a solution to avoid core panics（rule index out of range） when setting `localhost` DNS client in config.
			// Because the `localhost` DNS client will append len(localTLDsAndDotlessDomains) rules into matcherInfos to match `geosite:private` default rule.
			// But `matcherInfos` has no enough length to add rules, which leads to core panics (rule index out of range).
			// To avoid this, the length of `matcherInfos` must be equal to the expected, so manually append it with Golang default zero value first for later modification.
			// Related issues:
			// https://github.com/v2fly/v2ray-core/issues/529
			// https://github.com/v2fly/v2ray-core/issues/719
			for i := 0; i < len(localTLDsAndDotlessDomains); i++ {
				*matcherInfos = append(*matcherInfos, &DomainMatcherInfo{
					clientIdx:     uint16(0),
					domainRuleIdx: uint16(0),
				})
			}
		}

		// Establish domain rules
		var rules []string
		ruleCurr := 0
		ruleIter := 0
		for _, domain := range ns.PrioritizedDomain {
			domainRule, err := toStrMatcher(domain.Type, domain.Domain)
			if err != nil {
				return errors.New("failed to create prioritized domain").Base(err).AtWarning()
			}
			originalRuleIdx := ruleCurr
			if ruleCurr < len(ns.OriginalRules) {
				rule := ns.OriginalRules[ruleCurr]
				if ruleCurr >= len(rules) {
					rules = append(rules, rule.Rule)
				}
				ruleIter++
				if ruleIter >= int(rule.Size) {
					ruleIter = 0
					ruleCurr++
				}
			} else { // No original rule, generate one according to current domain matcher (majorly for compatibility with tests)
				rules = append(rules, domainRule.String())
				ruleCurr++
			}
			err = updateDomainRule(domainRule, originalRuleIdx, *matcherInfos)
			if err != nil {
				return errors.New("failed to create prioritized domain").Base(err).AtWarning()
			}
		}

		// Establish expected IPs
		var expectedMatchers []*router.GeoIPMatcher
		for _, geoip := range ns.ExpectedGeoip {
			matcher, err := router.GlobalGeoIPContainer.Add(geoip)
			if err != nil {
				return errors.New("failed to create expected ip matcher").Base(err).AtWarning()
			}
			expectedMatchers = append(expectedMatchers, matcher)
		}

		// Establish unexpected IPs
		var unexpectedMatchers []*router.GeoIPMatcher
		for _, geoip := range ns.UnexpectedGeoip {
			matcher, err := router.GlobalGeoIPContainer.Add(geoip)
			if err != nil {
				return errors.New("failed to create unexpected ip matcher").Base(err).AtWarning()
			}
			unexpectedMatchers = append(unexpectedMatchers, matcher)
		}

		if len(clientIP) > 0 {
			switch ns.Address.Address.GetAddress().(type) {
			case *net.IPOrDomain_Domain:
				errors.LogInfo(ctx, "DNS: client ", ns.Address.Address.GetDomain(), " uses clientIP ", clientIP.String())
			case *net.IPOrDomain_Ip:
				errors.LogInfo(ctx, "DNS: client ", net.IP(ns.Address.Address.GetIp()), " uses clientIP ", clientIP.String())
			}
		}

		var timeoutMs = 4000 * time.Millisecond
		if ns.TimeoutMs > 0 {
			timeoutMs = time.Duration(ns.TimeoutMs) * time.Millisecond
		}

		checkSystem := ns.QueryStrategy == QueryStrategy_USE_SYS

		client.server = server
		client.skipFallback = ns.SkipFallback
		client.domains = rules
		client.expectedIPs = expectedMatchers
		client.unexpectedIPs = unexpectedMatchers
		client.actPrior = ns.ActPrior
		client.actUnprior = ns.ActUnprior
		client.tag = tag
		client.timeoutMs = timeoutMs
		client.finalQuery = ns.FinalQuery
		client.ipOption = &ipOption
		client.checkSystem = checkSystem
		return nil
	})
	return client, err
}

// Name returns the server name the client manages.
func (c *Client) Name() string {
	return c.server.Name()
}

func (c *Client) IsFinalQuery() bool {
	return c.finalQuery
}

// QueryIP sends DNS query to the name server with the client's IP.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if c.checkSystem {
		supportIPv4, supportIPv6 := checkSystemNetwork()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && c.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && c.ipOption.IPv6Enable
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeoutMs)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})
	ips, ttl, err := c.server.QueryIP(ctx, domain, option)
	cancel()

	if err != nil {
		return nil, 0, err
	}

	if len(ips) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}

	if len(c.expectedIPs) > 0 && !c.actPrior {
		ips = router.MatchIPs(c.expectedIPs, ips, false)
		errors.LogDebug(context.Background(), "domain ", domain, " expectedIPs ", ips, " matched at server ", c.Name())
		if len(ips) == 0 {
			return nil, 0, dns.ErrEmptyResponse
		}
	}

	if len(c.unexpectedIPs) > 0 && !c.actUnprior {
		ips = router.MatchIPs(c.unexpectedIPs, ips, true)
		errors.LogDebug(context.Background(), "domain ", domain, " unexpectedIPs ", ips, " matched at server ", c.Name())
		if len(ips) == 0 {
			return nil, 0, dns.ErrEmptyResponse
		}
	}

	if len(c.expectedIPs) > 0 && c.actPrior {
		ipsNew := router.MatchIPs(c.expectedIPs, ips, false)
		if len(ipsNew) > 0 {
			ips = ipsNew
			errors.LogDebug(context.Background(), "domain ", domain, " priorIPs ", ips, " matched at server ", c.Name())
		}
	}

	if len(c.unexpectedIPs) > 0 && c.actUnprior {
		ipsNew := router.MatchIPs(c.unexpectedIPs, ips, true)
		if len(ipsNew) > 0 {
			ips = ipsNew
			errors.LogDebug(context.Background(), "domain ", domain, " unpriorIPs ", ips, " matched at server ", c.Name())
		}
	}

	return ips, ttl, nil
}

func ResolveIpOptionOverride(queryStrategy QueryStrategy, ipOption dns.IPOption) dns.IPOption {
	switch queryStrategy {
	case QueryStrategy_USE_IP:
		return ipOption
	case QueryStrategy_USE_SYS:
		return ipOption
	case QueryStrategy_USE_IP4:
		return dns.IPOption{
			IPv4Enable: ipOption.IPv4Enable,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		return dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: ipOption.IPv6Enable,
			FakeEnable: false,
		}
	default:
		return ipOption
	}
}
