package conf

import (
	"encoding/base64"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/blackhole"
	"google.golang.org/protobuf/proto"
)

type ResponseConfig struct {
	Type               string `json:"type"`
	CustomResponseData string `json:"customResponseData"`
}

type BlackholeConfig struct {
	Response *ResponseConfig `json:"response"`
}

func (v *BlackholeConfig) Build() (proto.Message, error) {
	config := new(blackhole.Config)
	if v.Response != nil {
		responseName := strings.ToLower(v.Response.Type)
		switch responseName {
		case "none", "":
			config.Response = &blackhole.Response{Type: "none"}
		case "http":
			config.Response = &blackhole.Response{Type: "http"}
		case "custom":
			data, err := base64.StdEncoding.DecodeString(v.Response.CustomResponseData)
			if err != nil {
				return nil, errors.New("failed to decode custom response data: " + err.Error())
			}
			config.Response = &blackhole.Response{Type: "custom", CustomResponseData: data}
		default:
			return nil, errors.New("unknown blackhole response: " + responseName)
		}
	}

	return config, nil
}
