package splithttp

import (
	"net/http"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]

	if path == "" || path[0] != '/' {
		path = "/" + path
	}

	if path[len(path)-1] != '/' {
		path = path + "/"
	}

	return path
}

func (c *Config) GetNormalizedQuery() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	query := ""

	if len(pathAndQuery) > 1 {
		query = pathAndQuery[1]
	}

	/*
		if query != "" {
			query += "&"
		}
		query += "x_version=" + core.Version()
	*/

	return query
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Headers {
		header.Add(k, v)
	}
	return header
}

func (c *Config) WriteResponseHeader(writer http.ResponseWriter) {
	// CORS headers for the browser dialer
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "*")
	// writer.Header().Set("X-Version", core.Version())
}

func (c *Config) GetNormalizedUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return "POST"
	}

	return c.UplinkHTTPMethod
}

func (c *Config) GetNormalizedScMaxEachPostBytes() RangeConfig {
	if c.ScMaxEachPostBytes == nil || c.ScMaxEachPostBytes.To == 0 {
		return RangeConfig{
			From: 1000000,
			To:   1000000,
		}
	}

	return *c.ScMaxEachPostBytes
}

func (c *Config) GetNormalizedScMinPostsIntervalMs() RangeConfig {
	if c.ScMinPostsIntervalMs == nil || c.ScMinPostsIntervalMs.To == 0 {
		return RangeConfig{
			From: 30,
			To:   30,
		}
	}

	return *c.ScMinPostsIntervalMs
}

func (c *Config) GetNormalizedScMaxBufferedPosts() int {
	if c.ScMaxBufferedPosts == 0 {
		return 30
	}

	return int(c.ScMaxBufferedPosts)
}

func (c *Config) GetNormalizedScStreamUpServerSecs() RangeConfig {
	if c.ScStreamUpServerSecs == nil || c.ScStreamUpServerSecs.To == 0 {
		return RangeConfig{
			From: 20,
			To:   80,
		}
	}

	return *c.ScStreamUpServerSecs
}

func (c *Config) GetNormalizedSessionPlacement() string {
	if c.SessionPlacement == "" {
		return PlacementPath
	}
	return c.SessionPlacement
}

func (c *Config) GetNormalizedSeqPlacement() string {
	if c.SeqPlacement == "" {
		return PlacementPath
	}
	return c.SeqPlacement
}

func (c *Config) GetNormalizedUplinkDataPlacement() string {
	if c.UplinkDataPlacement == "" {
		return PlacementBody
	}
	return c.UplinkDataPlacement
}

func (c *Config) GetNormalizedSessionKey() string {
	if c.SessionKey != "" {
		return c.SessionKey
	}
	switch c.GetNormalizedSessionPlacement() {
	case PlacementHeader:
		return "X-Session"
	case PlacementCookie, PlacementQuery:
		return "x_session"
	default:
		return ""
	}
}

func (c *Config) GetNormalizedSeqKey() string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	switch c.GetNormalizedSeqPlacement() {
	case PlacementHeader:
		return "X-Seq"
	case PlacementCookie, PlacementQuery:
		return "x_seq"
	default:
		return ""
	}
}

func (c *Config) ApplyMetaToRequest(req *http.Request, sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	if sessionId != "" {
		switch sessionPlacement {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionId)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(sessionKey, sessionId)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(sessionKey, sessionId)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: sessionKey, Value: sessionId})
		}
	}

	if seqStr != "" {
		switch seqPlacement {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(seqKey, seqStr)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(seqKey, seqStr)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: seqKey, Value: seqStr})
		}
	}
}

func (c *Config) ExtractMetaFromRequest(req *http.Request, path string) (sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	if sessionPlacement == PlacementPath && seqPlacement == PlacementPath {
		subpath := strings.Split(req.URL.Path[len(path):], "/")
		if len(subpath) > 0 {
			sessionId = subpath[0]
		}
		if len(subpath) > 1 {
			seqStr = subpath[1]
		}
		return sessionId, seqStr
	}

	switch sessionPlacement {
	case PlacementQuery:
		sessionId = req.URL.Query().Get(sessionKey)
	case PlacementHeader:
		sessionId = req.Header.Get(sessionKey)
	case PlacementCookie:
		if cookie, e := req.Cookie(sessionKey); e == nil {
			sessionId = cookie.Value
		}
	}

	switch seqPlacement {
	case PlacementQuery:
		seqStr = req.URL.Query().Get(seqKey)
	case PlacementHeader:
		seqStr = req.Header.Get(seqKey)
	case PlacementCookie:
		if cookie, e := req.Cookie(seqKey); e == nil {
			seqStr = cookie.Value
		}
	}

	return sessionId, seqStr
}

func (m *XmuxConfig) GetNormalizedMaxConcurrency() RangeConfig {
	if m.MaxConcurrency == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.MaxConcurrency
}

func (m *XmuxConfig) GetNormalizedMaxConnections() RangeConfig {
	if m.MaxConnections == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.MaxConnections
}

func (m *XmuxConfig) GetNormalizedCMaxReuseTimes() RangeConfig {
	if m.CMaxReuseTimes == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.CMaxReuseTimes
}

func (m *XmuxConfig) GetNormalizedHMaxRequestTimes() RangeConfig {
	if m.HMaxRequestTimes == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.HMaxRequestTimes
}

func (m *XmuxConfig) GetNormalizedHMaxReusableSecs() RangeConfig {
	if m.HMaxReusableSecs == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.HMaxReusableSecs
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

func (c RangeConfig) rand() int32 {
	return int32(crypto.RandBetween(int64(c.From), int64(c.To)))
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}
