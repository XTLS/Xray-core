package xdns

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseResolverAddr normalizes an entry in resolvers[].addrs. DoH keeps the
// complete HTTPS URL in Addr so its path and query survive protobuf conversion.
func ParseResolverAddr(addr string) (*ResolverProto, error) {
	if addr == "" || strings.TrimSpace(addr) != addr {
		return nil, errors.New("invalid resolver address")
	}
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	protocol := u.Scheme
	port := "53"
	switch protocol {
	case "udp", "tcp":
	case "dot":
		port = "853"
	case "doh":
		port = "443"
	default:
		return nil, errors.New("invalid resolver protocol")
	}
	if u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.Contains(addr, "#") {
		return nil, errors.New("invalid resolver URL")
	}
	if !strings.HasPrefix(u.Host, "[") && strings.Count(u.Host, ":") > 1 {
		return nil, errors.New("IPv6 resolver addresses must use brackets")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("empty resolver port")
	}
	if protocol != "doh" && (u.Path != "" || u.RawQuery != "" || u.ForceQuery) {
		return nil, errors.New("resolver does not support a path or query")
	}
	if u.Port() != "" {
		port = u.Port()
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, errors.New("invalid resolver port")
	}
	server := net.JoinHostPort(u.Hostname(), strconv.FormatUint(n, 10))
	if protocol == "doh" {
		u.Scheme = "https"
		u.Host = server
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		server = u.String()
	}
	return &ResolverProto{Type: protocol, Addr: server}, nil
}

func normalizeResolver(config *ResolverProto) (*ResolverProto, error) {
	if config == nil {
		return nil, errors.New("nil resolver")
	}
	addr := config.Type + "://" + config.Addr
	if config.Type == "doh" {
		if !strings.HasPrefix(config.Addr, "https://") {
			return nil, errors.New("DoH resolver requires an HTTPS URL")
		}
		addr = "doh://" + strings.TrimPrefix(config.Addr, "https://")
	}
	return ParseResolverAddr(addr)
}
