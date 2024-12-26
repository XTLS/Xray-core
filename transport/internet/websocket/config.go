package websocket

import (
	"net/http"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/transport/internet"
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
	header.Set("Host", c.Host)

	// GFW-Knocker
	uagent := header.Get("User-Agent")
	if uagent == "" {
		header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	}

	return header
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
