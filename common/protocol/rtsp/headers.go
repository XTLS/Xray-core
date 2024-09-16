package rtsp

import (
	"strings"
	"strconv"
	"github.com/xtls/xray-core/common/net"
)

// ParseXTransport parses X-Transport header in RTSP headers, returning the transport options.
func ParseXTransport(header map[string]string) []string {
	xTransport := header["Transport"]
	if xTransport == "" {
		return nil
	}
	return strings.Split(xTransport, ",")
}

// RemoveHopByHopHeaders removes hop-by-hop headers in RTSP header list.
func RemoveHopByHopHeaders(header map[string]string) {
	delete(header, "Proxy-Connection")
	delete(header, "Proxy-Authenticate")
	delete(header, "Proxy-Authorization")
	delete(header, "TE")
	delete(header, "Trailers")
	delete(header, "Transfer-Encoding")
	delete(header, "Upgrade")

	connections := header["Connection"]
	delete(header, "Connection")
	if connections == "" {
		return
	}
	for _, h := range strings.Split(connections, ",") {
		delete(header, strings.TrimSpace(h))
	}
}

// ParseHost splits host and port from a raw string. Default port is used when raw string doesn't contain port.
func ParseHost(rawHost string, defaultPort net.Port) (net.Destination, error) {
	port := defaultPort
	host, rawPort, err := net.SplitHostPort(rawHost)
	if err != nil {
		if addrError, ok := err.(*net.AddrError); ok && strings.Contains(addrError.Err, "missing port") {
			host = rawHost
		} else {
			return net.Destination{}, err
		}
	} else if len(rawPort) > 0 {
		intPort, err := strconv.Atoi(rawPort)
		if err != nil {
			return net.Destination{}, err
		}
		port = net.Port(intPort)
	}

	return net.TCPDestination(net.ParseAddress(host), port), nil
}

// parsing headers RTSP
func ParseRTSPHeaders(rawHeaders string) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(rawHeaders, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}
