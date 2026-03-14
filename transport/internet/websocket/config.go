package websocket

import (
	"net/http"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath() string {
	path := c.Path
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Header {
		header.Add(k, v)
	}
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", utils.ChromeUA)
		header.Set("Sec-CH-UA", utils.ChromeUACH)
		header.Set("Sec-CH-UA-Mobile", "?0")
		header.Set("Sec-CH-UA-Platform", "Windows")
		header.Set("Sec-Fetch-Mode", "websocket") // Vary!
		header.Set("Sec-Fetch-Dest", "empty") // Vary!
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-User", "?1")
	}
	return header
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
