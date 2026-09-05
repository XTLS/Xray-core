package splithttp

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
)

const MaxResponsePreludeLength int32 = 4096

func (c *Config) GetNormalizedResponsePreludePlacement() string {
	if c.ResponsePrelude == nil {
		return ""
	}
	if c.ResponsePrelude.Placement == "" {
		return PlacementCookie
	}
	return c.ResponsePrelude.Placement
}

func (c *Config) GetNormalizedResponsePreludeKey() string {
	if c.ResponsePrelude == nil {
		return ""
	}
	if c.ResponsePrelude.Key != "" {
		return c.ResponsePrelude.Key
	}
	switch c.GetNormalizedResponsePreludePlacement() {
	case PlacementHeader:
		return "X-Sample-ID"
	case PlacementCookie, PlacementQuery:
		return "sample_id"
	default:
		return ""
	}
}

func (c *Config) GetNormalizedResponsePreludeTable() string {
	if c.ResponsePrelude == nil {
		return ""
	}
	table := c.ResponsePrelude.Table
	if table == "" {
		table = "Base62"
	}
	if predefined, ok := PredefinedTable[table]; ok {
		return predefined
	}
	return table
}

func (c *Config) GetNormalizedResponsePreludeLength() *RangeConfig {
	if c.ResponsePrelude == nil {
		return nil
	}
	if c.ResponsePrelude.Length == nil || c.ResponsePrelude.Length.From <= 0 || c.ResponsePrelude.Length.To <= 0 {
		return &RangeConfig{From: 16, To: 32}
	}
	return c.ResponsePrelude.Length
}

func (c *Config) GenerateResponsePrelude() string {
	if c.ResponsePrelude == nil {
		return ""
	}
	lengthConfig := c.GetNormalizedResponsePreludeLength()
	table := c.GetNormalizedResponsePreludeTable()
	if lengthConfig == nil || table == "" {
		return ""
	}
	length := lengthConfig.rand()
	if length <= 0 {
		return ""
	}
	value := make([]byte, length)
	for i := range value {
		value[i] = table[rand.N(len(table))]
	}
	return string(value)
}

func (c *Config) ApplyResponsePreludeToRequest(req *http.Request, value string) {
	if c.ResponsePrelude == nil || value == "" {
		return
	}
	placement := c.GetNormalizedResponsePreludePlacement()
	key := c.GetNormalizedResponsePreludeKey()
	switch placement {
	case PlacementPath:
		req.URL.Path = appendToPath(req.URL.Path, value)
	case PlacementQuery:
		q := req.URL.Query()
		q.Set(key, value)
		req.URL.RawQuery = q.Encode()
	case PlacementHeader:
		req.Header.Set(key, value)
	case PlacementCookie:
		req.AddCookie(&http.Cookie{Name: key, Value: value})
	}
}

func (c *Config) ExtractResponsePreludeFromRequest(req *http.Request, basePath string) string {
	if c.ResponsePrelude == nil {
		return ""
	}
	placement := c.GetNormalizedResponsePreludePlacement()
	key := c.GetNormalizedResponsePreludeKey()
	switch placement {
	case PlacementPath:
		remainder := strings.TrimPrefix(req.URL.Path, basePath)
		remainder = strings.TrimPrefix(remainder, "/")
		if remainder == "" || strings.Contains(remainder, "/") {
			return ""
		}
		return remainder
	case PlacementQuery:
		return req.URL.Query().Get(key)
	case PlacementHeader:
		return req.Header.Get(key)
	case PlacementCookie:
		if cookie, err := req.Cookie(key); err == nil {
			return cookie.Value
		}
	}
	return ""
}

func (c *Config) IsResponsePreludeValid(value string) bool {
	if c.ResponsePrelude == nil || value == "" {
		return false
	}
	lengthConfig := c.GetNormalizedResponsePreludeLength()
	if lengthConfig == nil || int32(len(value)) < lengthConfig.From || int32(len(value)) > lengthConfig.To {
		return false
	}
	table := c.GetNormalizedResponsePreludeTable()
	if table == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !strings.ContainsRune(table, rune(value[i])) {
			return false
		}
	}
	return true
}

type responsePreludeReadCloser struct {
	source   io.ReadCloser
	expected []byte
	reader   io.Reader
	checked  bool
}

func newResponsePreludeReadCloser(source io.ReadCloser, expected string) io.ReadCloser {
	if source == nil || expected == "" {
		return source
	}
	return &responsePreludeReadCloser{source: source, expected: []byte(expected)}
}

func (r *responsePreludeReadCloser) Read(p []byte) (int, error) {
	if !r.checked {
		r.checked = true
		got := make([]byte, len(r.expected))
		n, err := io.ReadFull(r.source, got)
		if err == nil && bytes.Equal(got, r.expected) {
			r.reader = r.source
		} else {
			r.reader = io.MultiReader(bytes.NewReader(got[:n]), r.source)
		}
	}
	return r.reader.Read(p)
}

func (r *responsePreludeReadCloser) Close() error {
	return r.source.Close()
}

func shouldApplyResponsePrelude(c *Config, body io.Reader, uploadOnly bool) bool {
	return c != nil && c.ResponsePrelude != nil && body == nil && !uploadOnly
}
