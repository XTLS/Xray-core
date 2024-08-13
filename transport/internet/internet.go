package internet

import (
	"net"
	"strings"
)

//go:generate go run github.com/GFW-knocker/Xray-core/common/errors/errorgen

func IsValidHTTPHost(request string, config string) bool {
	r := strings.ToLower(request)
	c := strings.ToLower(config)
	if strings.Contains(r, ":") {
		h, _, _ := net.SplitHostPort(r)
		return h == c
	}
	return r == c
}
