package http

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"unsafe"

	"github.com/xtls/xray-core/common"
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
	validMethods = map[string]bool{}
	errNotHTTP   = errors.New("not an HTTP request")
)

func init() {
	// https://www.iana.org/assignments/http-methods
	methods := []string{
		"ACL", "BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT",
		"CONNECT", "COPY", "DELETE", "GET", "HEAD",
		"LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY",
		"MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE",
		"OPTIONS", "ORDERPATCH", "PATCH", "POST", "PRI",
		"PROPFIND", "PROPPATCH", "PUT", "QUERY", "REBIND",
		"REPORT", "SEARCH", "TRACE", "UNBIND", "UNCHECKOUT",
		"UNLINK", "UNLOCK", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
	}
	for _, m := range methods {
		validMethods[m] = true
	}
}

func isValidHTTPMethod(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	idx := bytes.IndexByte(b, ' ')
	if idx == -1 {
		return false
	}
	method := unsafe.String(unsafe.SliceData(b), idx)
	return validMethods[method]
}

func SniffHTTP(b []byte, c context.Context) (*SniffHeader, error) {
	if !isValidHTTPMethod(b) {
		return nil, errNotHTTP
	}
	content := session.ContentFromContext(c)
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, common.ErrNoClue
		}
		return nil, errNotHTTP
	}
	if r.Host == "" {
		return nil, common.ErrNoClue
	}
	sh := &SniffHeader{
		version: HTTP1,
		host:    r.Host,
	}
	// If content.Attributes have information, that means it comes from HTTP inbound PlainHTTP mode.
	// It will set attributes, so skip it.
	if content != nil && len(content.Attributes) == 0 {
		for key, h := range r.Header {
			content.Attributes[key] = strings.Join(h, ",")
		}
		content.Attributes[":method"] = r.Method
		content.Attributes[":path"] = r.URL.Path
	}

	return sh, nil
}
