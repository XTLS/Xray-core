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
	QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns.IPOption, disableCache bool) ([]net.IP, uint32, error)
}

// Client is the interface for DNS client.
type Client struct {
	server             Server
	clientIP           net.IP
	skipFallback       bool
	domains            []string
	expectedIPs        []*router.GeoIPMatcher
	allowUnexpectedIPs bool
	tag                string
	timeoutMs          time.Duration
}

var errExpectedIPNonMatch = errors.New("expectedIPs not match")

// NewServer creates a name server object according to the network destination url.
func NewServer(ctx context.Context, dest net.Destination, dispatcher routing.Dispatcher, queryStrategy QueryStrategy) (Server, error) {
	if address := dest.Address; address.Family().IsDomain() {
		u, err := url.Parse(address.Domain())
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(queryStrategy), nil
		case strings.EqualFold(u.Scheme, "https"): // DNS-over-HTTPS Remote mode
			return NewDoHNameServer(u, queryStrategy, dispatcher, false), nil
		case strings.EqualFold(u.Scheme, "h2c"): // DNS-over-HTTPS h2c Remote mode
			return NewDoHNameServer(u, queryStrategy, dispatcher, true), nil
		case strings.EqualFold(u.Scheme, "https+local"): // DNS-over-HTTPS Local mode
			return NewDoHNameServer(u, queryStrategy, nil, false), nil
		case strings.EqualFold(u.Scheme, "h2c+local"): // DNS-over-HTTPS h2c Local mode
			return NewDoHNameServer(u, queryStrategy, nil, true), nil
		case strings.EqualFold(u.Scheme, "quic+local"): // DNS-over-QUIC Local mode
			return NewQUICNameServer(u, queryStrategy)
		case strings.EqualFold(u.Scheme, "tcp"): // DNS-over-TCP Remote mode
			return NewTCPNameServer(u, dispatcher, queryStrategy)
		case strings.EqualFold(u.Scheme, "tcp+local"): // DNS-over-TCP Local mode
			return NewTCPLocalNameServer(u, queryStrategy)
		case strings.EqualFold(u.String(), "fakedns"):
			var fd dns.FakeDNSEngine
			core.RequireFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				fd = fdns
			})
			return NewFakeDNSServer(fd), nil
		}
	}
	if dest.Network == net.Network_Unknown {
		dest.Network = net.Network_UDP
	}
	if dest.Network == net.Network_UDP { // UDP classic DNS mode
		return NewClassicNameServer(dest, dispatcher, queryStrategy), nil
	}
	return nil, errors.New("No available name server could be created from ", dest).AtWarning()
}

// NewClient creates a DNS client managing a name server with client IP, domain rules and expected IPs.
func NewClient(
	ctx context.Context,
	ns *NameServer,
	clientIP net.IP,
	container router.GeoIPMatcherContainer,
	matcherInfos *[]*DomainMatcherInfo,
	updateDomainRule func(strmatcher.Matcher, int, []*DomainMatcherInfo) error,
) (*Client, error) {
	client := &Client{}

	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		// Create a new server for each client for now
		server, err := NewServer(ctx, ns.Address.AsDestination(), dispatcher, ns.GetQueryStrategy())
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
		var matchers []*router.GeoIPMatcher
		for _, geoip := range ns.Geoip {
			matcher, err := container.Add(geoip)
			if err != nil {
				return errors.New("failed to create ip matcher").Base(err).AtWarning()
			}
			matchers = append(matchers, matcher)
		}

		if len(clientIP) > 0 {
			switch ns.Address.Address.GetAddress().(type) {
			case *net.IPOrDomain_Domain:
				errors.LogInfo(ctx, "DNS: client ", ns.Address.Address.GetDomain(), " uses clientIP ", clientIP.String())
			case *net.IPOrDomain_Ip:
				errors.LogInfo(ctx, "DNS: client ", ns.Address.Address.GetIp(), " uses clientIP ", clientIP.String())
			}
		}

		var timeoutMs = 4000 * time.Millisecond
		if ns.TimeoutMs > 0 {
			timeoutMs = time.Duration(ns.TimeoutMs) * time.Millisecond
		}
		
		client.server = server
		client.clientIP = clientIP
		client.skipFallback = ns.SkipFallback
		client.domains = rules
		client.expectedIPs = matchers
		client.allowUnexpectedIPs = ns.AllowUnexpectedIPs
		client.tag = ns.Tag
		client.timeoutMs = timeoutMs
		return nil
	})
	return client, err
}

// Name returns the server name the client manages.
func (c *Client) Name() string {
	return c.server.Name()
}

// QueryIP sends DNS query to the name server with the client's IP.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns.IPOption, disableCache bool) ([]net.IP, uint32, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeoutMs)
	if len(c.tag) != 0 {
		content := session.InboundFromContext(ctx)
		errors.LogDebug(ctx, "DNS: client override tag from ", content.Tag, " to ", c.tag)
		// create a new context to override the tag
		// do not direct set *content.Tag, it might be used by other clients
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})
	}
	ips, ttl, err := c.server.QueryIP(ctx, domain, c.clientIP, option, disableCache)
	cancel()

	if err != nil {
		return ips, ttl, err
	}
	netips, err := c.MatchExpectedIPs(domain, ips)
	return netips, ttl, err
}

// MatchExpectedIPs matches queried domain IPs with expected IPs and returns matched ones.
func (c *Client) MatchExpectedIPs(domain string, ips []net.IP) ([]net.IP, error) {
	if len(c.expectedIPs) == 0 {
		return ips, nil
	}
	newIps := []net.IP{}
	for _, ip := range ips {
		for _, matcher := range c.expectedIPs {
			if matcher.Match(ip) {
				newIps = append(newIps, ip)
				break
			}
		}
	}
	if len(newIps) == 0 {
		if c.allowUnexpectedIPs {
			return ips, nil
		}
		return nil, errExpectedIPNonMatch
	}
	errors.LogDebug(context.Background(), "domain ", domain, " expectedIPs ", newIps, " matched at server ", c.Name())
	return newIps, nil
}

func ResolveIpOptionOverride(queryStrategy QueryStrategy, ipOption dns.IPOption) dns.IPOption {
	switch queryStrategy {
	case QueryStrategy_USE_IP:
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
