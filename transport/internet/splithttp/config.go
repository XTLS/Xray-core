package splithttp

import (
	"net/http"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath() string {
	path := c.Path
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path = path + "/"
	}
	return path
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Header {
		header.Add(k, v)
	}
	return header
}

func (c *Config) GetNormalizedMaxConcurrentUploads() int32 {
	if c.MaxConcurrentUploads == 0 {
		return 10
	}

	return c.MaxConcurrentUploads
}

func (c *Config) GetNormalizedMaxUploadSize() int32 {
	if c.MaxUploadSize == 0 {
		return 1000000
	}

	return c.MaxUploadSize
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
