package conf

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/responder"
	"google.golang.org/protobuf/proto"
)

type ResponderConfig struct {
	Type     string `json:"type"`
	Response string `json:"response"`
}

func (c *ResponderConfig) Build() (proto.Message, error) {
	config := new(responder.Config)
	switch strings.ToLower(c.Type) {
	case "http":
		response := http.Response{
			StatusCode: 403,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Connection":    {"close"},
				"Cache-Control": {"max-age=3600, public"},
			},
		}
		var data bytes.Buffer
		common.Must(response.Write(&data))
		config.Response = data.Bytes()
	case "custom":
		data, err := base64.StdEncoding.DecodeString(c.Response)
		if err != nil {
			return nil, errors.New("failed to decode response").Base(err)
		}
		config.Response = data
	default:
		return nil, errors.New("unknown responder response type: ", c.Type)
	}
	return config, nil
}
