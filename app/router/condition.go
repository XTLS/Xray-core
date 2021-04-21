package router

import (
	"os"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/features/routing"
)

type Condition interface {
	Apply(ctx routing.Context) bool
	RestoreRoutingRule() interface{}
}

type ConditionChan []Condition

func NewConditionChan() *ConditionChan {
	var condChan ConditionChan = make([]Condition, 0, 8)
	return &condChan
}

func (v *ConditionChan) Add(cond Condition) *ConditionChan {
	*v = append(*v, cond)
	return v
}

// Apply applies all conditions registered in this chan.
func (v *ConditionChan) Apply(ctx routing.Context) bool {
	for _, cond := range *v {
		if !cond.Apply(ctx) {
			return false
		}
	}
	return true
}

// RestoreRoutingRule Restore implements Condition.
func (v *ConditionChan) RestoreRoutingRule() interface{} {
	rule := &RoutingRule{}
	for _, condition := range *v {
		cond := condition.RestoreRoutingRule()
		switch condition.(type) {
		case *AttributeMatcher:
			{
				rule.Attributes = cond.(string)
			}
		case *DomainMatcher:
			{
				rule.Domain = cond.([]*Domain)
			}
		case *InboundTagMatcher:
			{
				rule.InboundTag = cond.([]string)
			}
		case *MultiGeoIPMatcher:
			{
				if condition.(*MultiGeoIPMatcher).onSource {
					rule.SourceGeoip = cond.([]*GeoIP)
				} else {
					rule.Geoip = cond.([]*GeoIP)
				}
			}
		case NetworkMatcher:
			{
				rule.Networks = cond.([]net.Network)
			}
		case *PortMatcher:
			{
				if condition.(*PortMatcher).onSource {
					rule.SourcePortList = cond.(*net.PortList)
				} else {
					rule.PortList = cond.(*net.PortList)
				}
			}
		case *ProtocolMatcher:
			{
				rule.Protocol = cond.([]string)
			}
		case *UserMatcher:
			{
				rule.UserEmail = cond.([]string)
			}
		}
		// fmt.Printf("%#v:={%#v}\n", condition, cond)
	}

	return rule
}

func (v *ConditionChan) Len() int {
	return len(*v)
}

var matcherTypeMap = map[Domain_Type]strmatcher.Type{
	Domain_Plain:  strmatcher.Substr,
	Domain_Regex:  strmatcher.Regex,
	Domain_Domain: strmatcher.Domain,
	Domain_Full:   strmatcher.Full,
}

func domainToMatcher(domain *Domain) (strmatcher.Matcher, error) {
	matcherType, f := matcherTypeMap[domain.Type]
	if !f {
		return nil, newError("unsupported domain type", domain.Type)
	}

	matcher, err := matcherType.New(domain.Value)
	if err != nil {
		return nil, newError("failed to create domain matcher").Base(err)
	}

	return matcher, nil
}

type DomainMatcher struct {
	matchers strmatcher.IndexMatcher
}

func NewMphMatcherGroup(domains []*Domain) (*DomainMatcher, error) {
	g := strmatcher.NewMphMatcherGroup()
	for _, d := range domains {
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			return nil, newError("unsupported domain type", d.Type)
		}
		_, err := g.AddPattern(d.Value, matcherType)
		if err != nil {
			return nil, err
		}
	}
	g.Build()
	return &DomainMatcher{
		matchers: g,
	}, nil
}

func NewDomainMatcher(domains []*Domain) (*DomainMatcher, error) {
	g := new(strmatcher.MatcherGroup)
	for _, d := range domains {
		m, err := domainToMatcher(d)
		if err != nil {
			return nil, err
		}
		g.Add(m)
	}

	return &DomainMatcher{
		matchers: g,
	}, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	return len(m.matchers.Match(strings.ToLower(domain))) > 0
}

// Apply implements Condition.
func (m *DomainMatcher) Apply(ctx routing.Context) bool {
	domain := ctx.GetTargetDomain()
	if len(domain) == 0 {
		return false
	}
	return m.ApplyDomain(domain)
}

// RestoreRoutingRule Restore implements Condition.
func (m *DomainMatcher) RestoreRoutingRule() interface{} {
	domains := make([]*Domain, 0)
	group := m.matchers.(*strmatcher.MatcherGroup)
	restoreDomains := group.Restore()
	for i := 1; i <= len(restoreDomains); i++ {
		if rd, ok := restoreDomains[uint32(i)]; ok {
			domains = append(domains, &Domain{
				Type:  Domain_Type(rd.DomainType),
				Value: rd.Value,
			})
		}
	}

	return domains
}

type MultiGeoIPMatcher struct {
	matchers []*GeoIPMatcher
	onSource bool
	// geoips routing API requires this backup.
	geoips []*GeoIP
}

func NewMultiGeoIPMatcher(geoips []*GeoIP, onSource bool) (*MultiGeoIPMatcher, error) {
	var matchers []*GeoIPMatcher
	for _, geoip := range geoips {
		matcher, err := globalGeoIPContainer.Add(geoip)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}

	matcher := &MultiGeoIPMatcher{
		matchers: matchers,
		onSource: onSource,
	}

	// The routing API requires a backup content
	if enable := os.Getenv("XRAY_ROUTER_API_GETSET"); enable == "1" {
		matcher.geoips = geoips
	}

	return matcher, nil
}

// Apply implements Condition.
func (m *MultiGeoIPMatcher) Apply(ctx routing.Context) bool {
	var ips []net.IP
	if m.onSource {
		ips = ctx.GetSourceIPs()
	} else {
		ips = ctx.GetTargetIPs()
	}
	for _, ip := range ips {
		for _, matcher := range m.matchers {
			if matcher.Match(ip) {
				return true
			}
		}
	}
	return false
}

// RestoreRoutingRule Restore implements Condition.
func (m *MultiGeoIPMatcher) RestoreRoutingRule() interface{} {
	return m.geoips
}

type PortMatcher struct {
	port     net.MemoryPortList
	onSource bool
}

// NewPortMatcher create a new port matcher that can match source or destination port
func NewPortMatcher(list *net.PortList, onSource bool) *PortMatcher {
	return &PortMatcher{
		port:     net.PortListFromProto(list),
		onSource: onSource,
	}
}

// Apply implements Condition.
func (v *PortMatcher) Apply(ctx routing.Context) bool {
	if v.onSource {
		return v.port.Contains(ctx.GetSourcePort())
	} else {
		return v.port.Contains(ctx.GetTargetPort())
	}
}

// RestoreRoutingRule Restore implements Condition.
func (v *PortMatcher) RestoreRoutingRule() interface{} {
	return v.port.RestorePortList()
}

type NetworkMatcher struct {
	list [8]bool
	// network routing API requires this backup.
	network []net.Network
}

func NewNetworkMatcher(network []net.Network) NetworkMatcher {
	var matcher NetworkMatcher
	for _, n := range network {
		matcher.list[int(n)] = true
	}
	// The routing API requires a backup content
	if enable := os.Getenv("XRAY_ROUTER_API_GETSET"); enable == "1" {
		matcher.network = network
	}
	return matcher
}

// Apply implements Condition.
func (v NetworkMatcher) Apply(ctx routing.Context) bool {
	return v.list[int(ctx.GetNetwork())]
}

// RestoreRoutingRule Restore implements Condition.
func (v NetworkMatcher) RestoreRoutingRule() interface{} {
	return v.network
}

type UserMatcher struct {
	user []string
}

func NewUserMatcher(users []string) *UserMatcher {
	usersCopy := make([]string, 0, len(users))
	for _, user := range users {
		if len(user) > 0 {
			usersCopy = append(usersCopy, user)
		}
	}
	return &UserMatcher{
		user: usersCopy,
	}
}

// Apply implements Condition.
func (v *UserMatcher) Apply(ctx routing.Context) bool {
	user := ctx.GetUser()
	if len(user) == 0 {
		return false
	}
	for _, u := range v.user {
		if u == user {
			return true
		}
	}
	return false
}

// RestoreRoutingRule Restore implements Condition.
func (v *UserMatcher) RestoreRoutingRule() interface{} {
	return v.user
}

type InboundTagMatcher struct {
	tags []string
}

func NewInboundTagMatcher(tags []string) *InboundTagMatcher {
	tagsCopy := make([]string, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 {
			tagsCopy = append(tagsCopy, tag)
		}
	}
	return &InboundTagMatcher{
		tags: tagsCopy,
	}
}

// Apply implements Condition.
func (v *InboundTagMatcher) Apply(ctx routing.Context) bool {
	tag := ctx.GetInboundTag()
	if len(tag) == 0 {
		return false
	}
	for _, t := range v.tags {
		if t == tag {
			return true
		}
	}
	return false
}

// RestoreRoutingRule Restore implements Condition.
func (v *InboundTagMatcher) RestoreRoutingRule() interface{} {
	return v.tags
}

type ProtocolMatcher struct {
	protocols []string
}

func NewProtocolMatcher(protocols []string) *ProtocolMatcher {
	pCopy := make([]string, 0, len(protocols))

	for _, p := range protocols {
		if len(p) > 0 {
			pCopy = append(pCopy, p)
		}
	}

	return &ProtocolMatcher{
		protocols: pCopy,
	}
}

// Apply implements Condition.
func (m *ProtocolMatcher) Apply(ctx routing.Context) bool {
	protocol := ctx.GetProtocol()
	if len(protocol) == 0 {
		return false
	}
	for _, p := range m.protocols {
		if strings.HasPrefix(protocol, p) {
			return true
		}
	}
	return false
}

// RestoreRoutingRule Restore implements Condition.
func (m *ProtocolMatcher) RestoreRoutingRule() interface{} {
	return m.protocols
}

type AttributeMatcher struct {
	program *starlark.Program
	// code routing API requires this backup.
	code string
}

func NewAttributeMatcher(code string) (*AttributeMatcher, error) {
	starFile, err := syntax.Parse("attr.star", "satisfied=("+code+")", 0)
	if err != nil {
		return nil, newError("attr rule").Base(err)
	}
	p, err := starlark.FileProgram(starFile, func(name string) bool {
		return name == "attrs"
	})
	if err != nil {
		return nil, err
	}

	attr := &AttributeMatcher{
		program: p,
	}
	// The routing API requires a backup content
	if addr := os.Getenv("XRAY_ROUTER_API_GETSET"); addr != "" {
		attr.code = code
	}
	return attr, nil
}

// Match implements attributes matching.
func (m *AttributeMatcher) Match(attrs map[string]string) bool {
	attrsDict := new(starlark.Dict)
	for key, value := range attrs {
		attrsDict.SetKey(starlark.String(key), starlark.String(value))
	}

	predefined := make(starlark.StringDict)
	predefined["attrs"] = attrsDict

	thread := &starlark.Thread{
		Name: "matcher",
	}
	results, err := m.program.Init(thread, predefined)
	if err != nil {
		newError("attr matcher").Base(err).WriteToLog()
	}
	satisfied := results["satisfied"]
	return satisfied != nil && bool(satisfied.Truth())
}

// Apply implements Condition.
func (m *AttributeMatcher) Apply(ctx routing.Context) bool {
	attributes := ctx.GetAttributes()
	if attributes == nil {
		return false
	}
	return m.Match(attributes)
}

// RestoreRoutingRule Restore implements Condition.
func (m *AttributeMatcher) RestoreRoutingRule() interface{} {
	return m.code
}
