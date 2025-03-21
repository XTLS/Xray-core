// Package dns is an implementation of core.DNS feature.
package dns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/features/dns"
)

// DNS is a DNS rely server.
type DNS struct {
	sync.Mutex
	tag                    string
	disableCache           bool
	disableFallback        bool
	disableFallbackIfMatch bool
	ipOption               *dns.IPOption
	hosts                  *StaticHosts
	clients                []*Client
	ctx                    context.Context
	domainMatcher          strmatcher.IndexMatcher
	matcherInfos           []*DomainMatcherInfo
}

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher
type DomainMatcherInfo struct {
	clientIdx     uint16
	domainRuleIdx uint16
}

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	var tag string
	if len(config.Tag) > 0 {
		tag = config.Tag
	} else {
		tag = generateRandomTag()
	}

	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, errors.New("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption *dns.IPOption
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = &dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP4:
		ipOption = &dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = &dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	}

	hosts, err := NewStaticHosts(config.StaticHosts)
	if err != nil {
		return nil, errors.New("failed to create hosts").Base(err)
	}

	clients := []*Client{}
	domainRuleCount := 0
	for _, ns := range config.NameServer {
		domainRuleCount += len(ns.PrioritizedDomain)
	}

	// MatcherInfos is ensured to cover the maximum index domainMatcher could return, where matcher's index starts from 1
	matcherInfos := make([]*DomainMatcherInfo, domainRuleCount+1)
	domainMatcher := &strmatcher.MatcherGroup{}
	geoipContainer := router.GeoIPMatcherContainer{}

	for _, ns := range config.NameServer {
		clientIdx := len(clients)
		updateDomain := func(domainRule strmatcher.Matcher, originalRuleIdx int, matcherInfos []*DomainMatcherInfo) error {
			midx := domainMatcher.Add(domainRule)
			matcherInfos[midx] = &DomainMatcherInfo{
				clientIdx:     uint16(clientIdx),
				domainRuleIdx: uint16(originalRuleIdx),
			}
			return nil
		}

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}
		client, err := NewClient(ctx, ns, myClientIP, geoipContainer, &matcherInfos, updateDomain)
		if err != nil {
			return nil, errors.New("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient())
	}

	return &DNS{
		tag:                    tag,
		hosts:                  hosts,
		ipOption:               ipOption,
		clients:                clients,
		ctx:                    ctx,
		domainMatcher:          domainMatcher,
		matcherInfos:           matcherInfos,
		disableCache:           config.DisableCache,
		disableFallback:        config.DisableFallback,
		disableFallbackIfMatch: config.DisableFallbackIfMatch,
	}, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	return nil
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	return inbound != nil && inbound.Tag == s.tag
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if domain == "" {
		return nil, 0, errors.New("empty domain name")
	}

	option.IPv4Enable = option.IPv4Enable && s.ipOption.IPv4Enable
	option.IPv6Enable = option.IPv6Enable && s.ipOption.IPv6Enable

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	// Normalize the FQDN form query
	domain = strings.TrimSuffix(domain, ".")

	// Static host lookup
	switch addrs := s.hosts.Lookup(domain, option); {
	case addrs == nil: // Domain not recorded in static host
		break
	case len(addrs) == 0: // Domain recorded, but no valid IP returned (e.g. IPv4 address with only IPv6 enabled)
		return nil, 0, dns.ErrEmptyResponse
	case len(addrs) == 1 && addrs[0].Family().IsDomain(): // Domain replacement
		errors.LogInfo(s.ctx, "domain replaced: ", domain, " -> ", addrs[0].Domain())
		domain = addrs[0].Domain()
	default: // Successfully found ip records in static host
		errors.LogInfo(s.ctx, "returning ", len(addrs), " IP(s) for domain ", domain, " -> ", addrs)
		ips, err := toNetIP(addrs)
		return ips, 10, err // Hosts ttl is 10
	}

	// Name servers lookup
	errs := []error{}
	ctx := session.ContextWithInbound(s.ctx, &session.Inbound{Tag: s.tag})
	for _, client := range s.sortClients(domain) {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(s.ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			continue
		}
		ips, ttl, err := client.QueryIP(ctx, domain, option, s.disableCache)
		if len(ips) > 0 {
			return ips, ttl, nil
		}
		if err != nil {
			errors.LogInfoInner(s.ctx, err, "failed to lookup ip for domain ", domain, " at server ", client.Name())
			errs = append(errs, err)
		}
		// 5 for RcodeRefused in miekg/dns, hardcode to reduce binary size
		if err != context.Canceled && err != context.DeadlineExceeded && err != errExpectedIPNonMatch && err != dns.ErrEmptyResponse && dns.RCodeFromError(err) != 5 {
			return nil, 0, err
		}
	}

	return nil, 0, errors.New("returning nil for domain ", domain).Base(errors.Combine(errs...))
}

// LookupHosts implements dns.HostsLookup.
func (s *DNS) LookupHosts(domain string) *net.Address {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil
	}
	// Normalize the FQDN form query
	addrs := s.hosts.Lookup(domain, *s.ipOption)
	if len(addrs) > 0 {
		errors.LogInfo(s.ctx, "domain replaced: ", domain, " -> ", addrs[0].String())
		return &addrs[0]
	}

	return nil
}

// GetIPOption implements ClientWithIPOption.
func (s *DNS) GetIPOption() *dns.IPOption {
	return s.ipOption
}

// SetQueryOption implements ClientWithIPOption.
func (s *DNS) SetQueryOption(isIPv4Enable, isIPv6Enable bool) {
	s.ipOption.IPv4Enable = isIPv4Enable
	s.ipOption.IPv6Enable = isIPv6Enable
}

// SetFakeDNSOption implements ClientWithIPOption.
func (s *DNS) SetFakeDNSOption(isFakeEnable bool) {
	s.ipOption.FakeEnable = isFakeEnable
}

func (s *DNS) sortClients(domain string) []*Client {
	clients := make([]*Client, 0, len(s.clients))
	clientUsed := make([]bool, len(s.clients))
	clientNames := make([]string, 0, len(s.clients))
	domainRules := []string{}

	// Priority domain matching
	hasMatch := false
	MatchSlice := s.domainMatcher.Match(domain)
	sort.Slice(MatchSlice, func(i, j int) bool {
		return MatchSlice[i] < MatchSlice[j]
	})
	for _, match := range MatchSlice {
		info := s.matcherInfos[match]
		client := s.clients[info.clientIdx]
		domainRule := client.domains[info.domainRuleIdx]
		domainRules = append(domainRules, fmt.Sprintf("%s(DNS idx:%d)", domainRule, info.clientIdx))
		if clientUsed[info.clientIdx] {
			continue
		}
		clientUsed[info.clientIdx] = true
		clients = append(clients, client)
		clientNames = append(clientNames, client.Name())
		hasMatch = true
	}

	if !(s.disableFallback || s.disableFallbackIfMatch && hasMatch) {
		// Default round-robin query
		for idx, client := range s.clients {
			if clientUsed[idx] || client.skipFallback {
				continue
			}
			clientUsed[idx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
		}
	}

	if len(domainRules) > 0 {
		errors.LogDebug(s.ctx, "domain ", domain, " matches following rules: ", domainRules)
	}
	if len(clientNames) > 0 {
		errors.LogDebug(s.ctx, "domain ", domain, " will use DNS in order: ", clientNames)
	}

	if len(clients) == 0 {
		clients = append(clients, s.clients[0])
		clientNames = append(clientNames, s.clients[0].Name())
		errors.LogDebug(s.ctx, "domain ", domain, " will use the first DNS: ", clientNames)
	}

	return clients
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
