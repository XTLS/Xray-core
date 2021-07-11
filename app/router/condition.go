package router

import (
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

type Condition interface {
	Apply(ctx routing.Context) bool
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

func (v *ConditionChan) Len() int {
	return len(*v)
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

type NetworkMatcher struct {
	list [8]bool
}

func NewNetworkMatcher(network []net.Network) NetworkMatcher {
	var matcher NetworkMatcher
	for _, n := range network {
		matcher.list[int(n)] = true
	}
	return matcher
}

// Apply implements Condition.
func (v NetworkMatcher) Apply(ctx routing.Context) bool {
	return v.list[int(ctx.GetNetwork())]
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

type AttributeMatcher struct {
	program *starlark.Program
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
	return &AttributeMatcher{
		program: p,
	}, nil
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
