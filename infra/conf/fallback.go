package conf

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy"
)

type FallbackConfig struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

func (fbconf *FallbackConfig) Build() (*proxy.Fallback, error) {
	var i uint16
	var s string
	if err := json.Unmarshal(fbconf.Dest, &i); err == nil {
		s = strconv.Itoa(int(i))
	} else {
		_ = json.Unmarshal(fbconf.Dest, &s)
	}
	fb := &proxy.Fallback{
		Name: fbconf.Name,
		Alpn: fbconf.Alpn,
		Path: fbconf.Path,
		Type: fbconf.Type,
		Dest: s,
		Xver: fbconf.Xver,
	}

	if fb.Path != "" && fb.Path[0] != '/' {
		return nil, newError(`inbound fallbacks: "path" must be empty or start with "/"`)
	}
	if fb.Type == "" && fb.Dest != "" {
		if fb.Dest == "serve-ws-none" {
			fb.Type = "serve"
		} else if filepath.IsAbs(fb.Dest) || fb.Dest[0] == '@' {
			fb.Type = "unix"
			if strings.HasPrefix(fb.Dest, "@@") && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
				fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path)) // may need padding to work with haproxy
				copy(fullAddr, fb.Dest[1:])
				fb.Dest = string(fullAddr)
			}
		} else {
			if _, err := strconv.Atoi(fb.Dest); err == nil {
				fb.Dest = "127.0.0.1:" + fb.Dest
			}
			if _, _, err := net.SplitHostPort(fb.Dest); err == nil {
				fb.Type = "tcp"
			}
		}
	}
	if fb.Type == "" {
		return nil, newError(`inbound fallbacks: please fill in a valid value for every "dest"`)
	}
	if fb.Xver > 2 {
		return nil, newError(`inbound fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
	}
	return fb, nil
}
