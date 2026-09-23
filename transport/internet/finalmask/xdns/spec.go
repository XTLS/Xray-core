package xdns

import (
	stdnet "net"
	"net/url"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

type resolverProtocol uint8

const (
	resolverUDP resolverProtocol = iota
	resolverDOT
	resolverDOH
)

type resolverSpec struct {
	domain   Name
	rrType   uint16
	protocol resolverProtocol
	server   string
	dohURL   *url.URL
}

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

func parseResolver(s string) (resolverSpec, error) {
	head, endpoint, ok := strings.Cut(s, "+")
	if !ok {
		return resolverSpec{}, errors.New("invalid resolver")
	}

	domain, err := parseDomainSpec(head, "txt")
	if err != nil {
		return resolverSpec{}, err
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return resolverSpec{}, errors.New("invalid resolver endpoint").Base(err)
	}
	if u.User != nil || u.Hostname() == "" || u.Fragment != "" {
		return resolverSpec{}, errors.New("invalid resolver endpoint")
	}

	result := resolverSpec{domain: domain.name, rrType: domain.rrType}
	switch strings.ToLower(u.Scheme) {
	case "udp":
		if u.Path != "" || u.RawQuery != "" {
			return resolverSpec{}, errors.New("udp resolver must not have path or query")
		}
		if u.Port() == "" {
			return resolverSpec{}, errors.New("udp resolver requires port")
		}
		if stdnet.ParseIP(u.Hostname()) == nil {
			return resolverSpec{}, errors.New("udp resolver requires ip address")
		}
		result.protocol = resolverUDP
	case "dot":
		if u.Path != "" || u.RawQuery != "" {
			return resolverSpec{}, errors.New("dot resolver must not have path or query")
		}
		result.protocol = resolverDOT
	case "doh":
		result.protocol = resolverDOH
		u.Scheme = "https"
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		result.dohURL = u
	default:
		return resolverSpec{}, errors.New("unsupported resolver scheme")
	}

	port := u.Port()
	if port == "" && strings.HasSuffix(u.Host, ":") {
		return resolverSpec{}, errors.New("invalid resolver port")
	}
	if port == "" {
		if result.protocol == resolverDOT {
			port = "853"
		} else if result.protocol == resolverDOH {
			port = "443"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return resolverSpec{}, errors.New("invalid resolver port")
	}
	result.server = stdnet.JoinHostPort(u.Hostname(), port)
	if result.dohURL != nil {
		result.dohURL.Host = result.server
	}
	return result, nil
}

// ValidateResolver uses the same parser as the runtime client.
func ValidateResolver(s string) error {
	_, err := parseResolver(s)
	return err
}
