package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/hysteria"
)

func TestHysteriaClientConfig(t *testing.T) {
	rawJSON := `{"version": 2, "address": "127.0.0.1", "port": 443}`
	config := new(HysteriaClientConfig)
	common.Must(json.Unmarshal([]byte(rawJSON), config))

	message, err := config.Build()
	common.Must(err)

	client, ok := message.(*hysteria.ClientConfig)
	if !ok {
		t.Fatal("expected *hysteria.ClientConfig")
	}
	if client.Server.Port != 443 {
		t.Error("port: ", client.Server.Port)
	}
}

func TestHysteriaClientConfigWithoutAddress(t *testing.T) {
	rawJSON := `{"version": 2, "port": 443}`
	config := new(HysteriaClientConfig)
	common.Must(json.Unmarshal([]byte(rawJSON), config))

	if _, err := config.Build(); err == nil {
		t.Error("expected error, but got nil")
	}
}
