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
	// UA header would have already been set by now with the current implementation
	//if len(header.Values("User-Agent")) < 1 {
	switch header.Get("User-Agent") {
	case "", "!chrome":
		utils.ApplyDefaultHeaders(header, "chrome", "ws")
	case "!firefox":
		utils.ApplyDefaultHeaders(header, "firefox", "ws")
	case "!go":
		utils.ApplyDefaultHeaders(header, "go", "ws")
	}
	return header
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
