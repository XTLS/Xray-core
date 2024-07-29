package splithttp

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath(addPath string, addQuery bool) string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]
	query := ""
	if len(pathAndQuery) > 1 && addQuery {
		query = "?" + pathAndQuery[1]
	}

	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path = path + "/"
	}

	return path + addPath + query
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Header {
		header.Add(k, v)
	}
	return header
}

func (c *Config) GetNormalizedMaxConcurrentUploads(isServer bool) RandRangeConfig {
	if c.MaxConcurrentUploads == nil || c.MaxConcurrentUploads.To == 0 {
		return RandRangeConfig{
			From: 100,
			To:   100,
		}
	}

	return *c.MaxConcurrentUploads
}

func (c *Config) GetNormalizedMaxUploadBytes(isServer bool) RandRangeConfig {
	if c.MaxUploadBytes == nil || c.MaxUploadBytes.To == 0 {
		return RandRangeConfig{
			From: 1000000,
			To:   1000000,
		}
	}

	return *c.MaxUploadBytes
}

func (c *Config) GetNormalizedMinUploadInterval() RandRangeConfig {
	if c.MinUploadIntervalMs == nil || c.MinUploadIntervalMs.To == 0 {
		return RandRangeConfig{
			From: 30,
			To:   30,
		}
	}

	return *c.MinUploadIntervalMs
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

func (c RandRangeConfig) roll() int32 {
	if c.From == c.To {
		return c.From
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(c.To-c.From)))
	return c.From + int32(bigInt.Int64())
}
