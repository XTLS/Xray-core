package http

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type version byte

const (
	HTTP1 version = iota
	HTTP2
)

type SniffHeader struct {
	version version
	host    string
}

func (h *SniffHeader) Protocol() string {
	switch h.version {
	case HTTP1:
		return "http1"
	case HTTP2:
		return "http2"
	default:
		return "unknown"
	}
}

func (h *SniffHeader) Domain() string {
	return h.host
}

var (
	methods = [...][]byte{
		[]byte("GET"), []byte("POST"), []byte("HEAD"), []byte("PUT"),
		[]byte("DELETE"), []byte("OPTIONS"), []byte("CONNECT"), []byte("PATCH"), []byte("TRACE"),
	}

	spaceByte     = []byte(" ")
	newlineByte   = []byte("\n")
	schemeSepByte = []byte("://")
	crByte        = []byte("\r")
	colonByte     = []byte(":")
	hostKeyByte   = []byte("host")

	errNotHTTP = errors.New("not an HTTP")
)

func isHTTPMethodPrefix(prefix []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

func isHTTPMethod(method []byte) bool {
	for _, m := range methods {
		if bytes.Equal(method, m) {
			return true
		}
	}
	return false
}

func SniffHTTP(b []byte, c context.Context) (*SniffHeader, error) {
	content := session.ContentFromContext(c)
	// If content.Attributes have information, that means it comes from HTTP inbound PlainHTTP mode.
	// It will set attributes, so skip it.
	shouldSniffAttr := content != nil && len(content.Attributes) == 0

	method, _, found := bytes.Cut(b, spaceByte)
	switch {
	case !found && isHTTPMethodPrefix(b):
		return nil, common.ErrNoClue
	case !found || !isHTTPMethod(method):
		return nil, errNotHTTP
	}

	req, afterReqLine, found := bytes.Cut(b, newlineByte)
	if !found || len(req) < 14 {
		return nil, common.ErrNoClue
	}

	_, rest, ok1 := bytes.Cut(req, spaceByte)
	uri, _, ok2 := bytes.Cut(rest, spaceByte)
	if !ok1 || !ok2 {
		return nil, common.ErrNoClue
	}
	if len(uri) == 0 {
		return nil, common.ErrNoClue
	}

	sh := &SniffHeader{
		version: HTTP1,
	}

	// Parse request line
	// Request line is like this
	// "GET /homo/114514 HTTP/1.1"
	if shouldSniffAttr {
		content.SetAttribute(":method", string(method))
		if uri[0] == '/' {
			content.SetAttribute(":path", string(uri))
		}
	}

	if uri[0] != '/' && uri[0] != '*' {
		if _, afterScheme, found := bytes.Cut(uri, schemeSepByte); found {
			uri = afterScheme
		}

		var path string
		if i := bytes.IndexAny(uri, "/?#"); i >= 0 {
			path = string(uri[i:])
			if path[0] != '/' {
				path = "/" + path
			}
			uri = uri[:i]
		} else {
			path = "/"
		}
		if shouldSniffAttr {
			content.SetAttribute(":path", path)
		}

		if i := bytes.LastIndexByte(uri, '@'); i >= 0 {
			uri = uri[i+1:]
		}

		if host, ok := sniffHost(uri); ok {
			sh.host = host
		}
	}

	rest = afterReqLine
	for {
		line, tail, found := bytes.Cut(rest, newlineByte)
		line = bytes.TrimSuffix(line, crByte)
		if !found || len(line) == 0 {
			break
		}
		rest = tail

		key, value, found := bytes.Cut(line, colonByte)
		if !found {
			continue
		}

		value = bytes.TrimSpace(value)
		if sh.host == "" && bytes.EqualFold(key, hostKeyByte) {
			if host, ok := sniffHost(value); ok {
				sh.host = host
			}
		}
		if shouldSniffAttr {
			content.SetAttribute(strings.ToLower(string(key)), string(value)) // Put header in attribute
		}
	}

	if sh.host == "" {
		return nil, common.ErrNoClue
	}

	return sh, nil
}

func sniffHost(raw []byte) (string, bool) {
	dest, err := ParseHost(string(raw), net.Port(80))
	if err != nil {
		return "", false
	}
	return dest.Address.String(), true
}
