package xdns

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

type domainSpec struct {
	name   Name
	rrType uint16
}

func rrTypeFromMethod(method string) (uint16, error) {
	switch strings.ToLower(method) {
	case "", "txt":
		return RRTypeTXT, nil
	case "a":
		return RRTypeA, nil
	case "aaaa":
		return RRTypeAAAA, nil
	default:
		return 0, errors.New("unsupported method")
	}
}

func parseDomainSpec(s string, defaultMethod string) (domainSpec, error) {
	domainPart := s
	method := ""
	hasMethod := false

	if i := strings.LastIndex(s, ":"); i >= 0 {
		domainPart = s[:i]
		method = s[i+1:]
		hasMethod = true
	} else if defaultMethod != "" {
		method = defaultMethod
		hasMethod = true
	}

	if domainPart == "" {
		return domainSpec{}, errors.New("empty domain")
	}

	name, err := ParseName(domainPart)
	if err != nil {
		return domainSpec{}, err
	}

	rrType := uint16(0)
	if hasMethod {
		var err error
		rrType, err = rrTypeFromMethod(method)
		if err != nil {
			return domainSpec{}, err
		}
	}

	return domainSpec{
		name:   name,
		rrType: rrType,
	}, nil
}

func parseResolver(s string) (Name, string, uint16, error) {
	head, server, ok := strings.Cut(s, "+udp://")
	if !ok {
		return nil, "", 0, errors.New("invalid resolver scheme")
	}
	if server == "" {
		return nil, "", 0, errors.New("empty resolver server")
	}

	spec, err := parseDomainSpec(head, "txt")
	if err != nil {
		return nil, "", 0, err
	}

	return spec.name, server, spec.rrType, nil
}
