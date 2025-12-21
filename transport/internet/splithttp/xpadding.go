package splithttp

import (
	"net/http"
	"net/url"
	"strings"
)

type Placement string
type PaddingMethod string

const (
	PlacementQueryInHeader Placement = "queryInHeader"
	PlacementCookie        Placement = "cookie"
	PlacementHeader        Placement = "header"
	PlacementQuery         Placement = "query"
)

const (
	PaddingMethodRepeatX  PaddingMethod = "repeat-x"
	PaddingMethodTokenish PaddingMethod = "tokenish"
)

type XPaddingPlacement struct {
	Placement Placement
	Key       string
	Header    string
	RawURL    string
}

type XPaddingConfig struct {
	Length    int
	Placement XPaddingPlacement
	Method    PaddingMethod
}

func GeneratePadding(method PaddingMethod, length int) string {
	switch method {
	case PaddingMethodRepeatX:
		return strings.Repeat("X", length)
	case PaddingMethodTokenish:
		// TODO: implement tokenish
		return strings.Repeat("X", length)
	default:
		return strings.Repeat("X", length)
	}
}

func ApplyPaddingToCookie(req *http.Request, name, value string) {
	if req == nil || name == "" || value == "" {
		return
	}
	req.AddCookie(&http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	})
}

func ApplyPaddingToQuery(u *url.URL, key, value string) {
	if u == nil || key == "" || value == "" {
		return
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
}

func (c *Config) GetNormalizedXPaddingBytes() RangeConfig {
	if c.XPaddingBytes == nil || c.XPaddingBytes.To == 0 {
		return RangeConfig{
			From: 100,
			To:   1000,
		}
	}

	return *c.XPaddingBytes
}

func (c *Config) ApplyXPaddingToHeader(h http.Header, config XPaddingConfig) {
	if h == nil {
		return
	}

	paddingValue := GeneratePadding(config.Method, config.Length)

	if config.Placement.Placement == PlacementHeader {
		h.Set(config.Placement.Header, paddingValue)
	} else if config.Placement.Placement == PlacementQueryInHeader {
		u, err := url.Parse(config.Placement.RawURL)
		if err != nil || u == nil {
			return
		}
		u.RawQuery = config.Placement.Key + "=" + paddingValue
		h.Set(config.Placement.Header, u.String())
	}
}

func (c *Config) ApplyXPaddingToRequest(req *http.Request, config XPaddingConfig) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	if config.Placement.Placement == PlacementHeader || config.Placement.Placement == PlacementQueryInHeader {
		c.ApplyXPaddingToHeader(req.Header, config)
		return
	}

	paddingValue := GeneratePadding(config.Method, config.Length)

	switch config.Placement.Placement {
	case PlacementCookie:
		ApplyPaddingToCookie(req, config.Placement.Key, paddingValue)
	case PlacementQuery:
		ApplyPaddingToQuery(req.URL, config.Placement.Key, paddingValue)
	}
}

func (c *Config) ExtractXPaddingFromRequest(req *http.Request, obfsMode bool) (string, string) {
	if req == nil {
		return "", ""
	}

	if obfsMode {
		referrer := req.Header.Get("Referer")

		if referrer != "" {
			if referrerURL, err := url.Parse(referrer); err == nil {
				paddingValue := referrerURL.Query().Get("x_padding")
				paddingPlacement := string(PlacementQueryInHeader) + "=Referer, key=x_padding"
				return paddingValue, paddingPlacement
			}
		} else {
			paddingValue := req.URL.Query().Get("x_padding")
			return paddingValue, string(PlacementQuery) + ", key=x_padding"
		}
	}

	key := c.XPaddingKey
	header := c.XPaddingHeader

	if cookie, err := req.Cookie(key); err == nil {
		if cookie != nil && cookie.Value != "" {
			paddingValue := cookie.Value
			paddingPlacement := string(PlacementCookie) + ", key=" + key
			return paddingValue, paddingPlacement
		}
	}

	headerValue := req.Header.Get(header)

	if headerValue != "" {
		if c.XPaddingPlacement == string(PlacementHeader) {
			paddingPlacement := string(PlacementHeader) + "=" + header
			return headerValue, paddingPlacement
		}

		if parsedURL, err := url.Parse(headerValue); err == nil {
			paddingPlacement := string(PlacementQueryInHeader) + "=" + header + ", key=" + key

			return parsedURL.Query().Get(key), paddingPlacement
		}
	}

	queryValue := req.URL.Query().Get(key)

	if queryValue != "" {
		paddingPlacement := string(PlacementQuery) + ", key=" + key
		return queryValue, paddingPlacement
	}

	return "", ""
}
