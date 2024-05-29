package proxy

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
)

type FallbackMap = map[string]map[string]map[string]*Fallback

func BuildFallbackMap(fallbacks []*Fallback) FallbackMap {
	fbmap := make(map[string]map[string]map[string]*Fallback)
	for _, fb := range fallbacks {
		if fbmap[fb.Name] == nil {
			fbmap[fb.Name] = make(map[string]map[string]*Fallback)
		}
		if fbmap[fb.Name][fb.Alpn] == nil {
			fbmap[fb.Name][fb.Alpn] = make(map[string]*Fallback)
		}
		fbmap[fb.Name][fb.Alpn][fb.Path] = fb
	}
	if fbmap[""] != nil {
		for name, apfb := range fbmap {
			if name != "" {
				for alpn := range fbmap[""] {
					if apfb[alpn] == nil {
						apfb[alpn] = make(map[string]*Fallback)
					}
				}
			}
		}
	}
	for _, apfb := range fbmap {
		if apfb[""] != nil {
			for alpn, pfb := range apfb {
				if alpn != "" { // && alpn != "h2" {
					for path, fb := range apfb[""] {
						if pfb[path] == nil {
							pfb[path] = fb
						}
					}
				}
			}
		}
	}
	if fbmap[""] != nil {
		for name, apfb := range fbmap {
			if name != "" {
				for alpn, pfb := range fbmap[""] {
					for path, fb := range pfb {
						if apfb[alpn][path] == nil {
							apfb[alpn][path] = fb
						}
					}
				}
			}
		}
	}
	return fbmap
}

func SearchFallbackMap(napfb FallbackMap, ctx context.Context, buf *buf.Buffer, bufLen int64, name string, alpn string) (*Fallback, error) {
	if len(napfb) > 1 || napfb[""] == nil {
		if name != "" && napfb[name] == nil {
			match := ""
			for n := range napfb {
				if n != "" && strings.Contains(name, n) && len(n) > len(match) {
					match = n
				}
			}
			name = match
		}
	}

	if napfb[name] == nil {
		name = ""
	}
	apfb := napfb[name]
	if apfb == nil {
		return nil, newError(`failed to find the default "name" config`).AtWarning()
	}

	if apfb[alpn] == nil {
		alpn = ""
	}
	pfb := apfb[alpn]
	if pfb == nil {
		return nil, newError(`failed to find the default "alpn" config`).AtWarning()
	}

	path := ""
	if len(pfb) > 1 || pfb[""] == nil {
		if bufLen >= 18 && buf.Byte(4) != '*' { // not h2c
			bufBytes := buf.Bytes()
			for i := 4; i <= 8; i++ { // 5 -> 9
				if bufBytes[i] == '/' && bufBytes[i-1] == ' ' {
					search := len(bufBytes)
					if search > 64 {
						search = 64 // up to about 60
					}
					for j := i + 1; j < search; j++ {
						k := bufBytes[j]
						if k == '\r' || k == '\n' { // avoid logging \r or \n
							break
						}
						if k == '?' || k == ' ' {
							path = string(bufBytes[i:j])
							if ctx != nil {
								sid := session.ExportIDToError(ctx)
								newError("realPath = " + path).AtInfo().WriteToLog(sid)
							}
							if pfb[path] == nil {
								path = ""
							}
							break
						}
					}
					break
				}
			}
		}
	}
	fb := pfb[path]
	if fb == nil {
		return nil, newError(`failed to find the default "path" config`).AtWarning()
	}
	return fb, nil
}
