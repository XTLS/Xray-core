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

func (c *Config) GetNormalizedScMaxConcurrentPosts() RandRangeConfig {
	if c.ScMaxConcurrentPosts == nil || c.ScMaxConcurrentPosts.To == 0 {
		return RandRangeConfig{
			From: 100,
			To:   100,
		}
	}

	return *c.ScMaxConcurrentPosts
}

func (c *Config) GetNormalizedScMaxEachPostBytes() RandRangeConfig {
	if c.ScMaxEachPostBytes == nil || c.ScMaxEachPostBytes.To == 0 {
		return RandRangeConfig{
			From: 1000000,
			To:   1000000,
		}
	}

	return *c.ScMaxEachPostBytes
}

func (c *Config) GetNormalizedScMinPostsIntervalMs() RandRangeConfig {
	if c.ScMinPostsIntervalMs == nil || c.ScMinPostsIntervalMs.To == 0 {
		return RandRangeConfig{
			From: 30,
			To:   30,
		}
	}

	return *c.ScMinPostsIntervalMs
}

func (c *Config) GetNormalizedResponseOkPadding() RandRangeConfig {
	if c.ResponseOkPadding == nil || c.ResponseOkPadding.To == 0 {
		return RandRangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *c.ResponseOkPadding
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
