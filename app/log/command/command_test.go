package command_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/v1/app/dispatcher"
	"github.com/xtls/xray-core/v1/app/log"
	. "github.com/xtls/xray-core/v1/app/log/command"
	"github.com/xtls/xray-core/v1/app/proxyman"
	_ "github.com/xtls/xray-core/v1/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/v1/app/proxyman/outbound"
	"github.com/xtls/xray-core/v1/common"
	"github.com/xtls/xray-core/v1/common/serial"
	"github.com/xtls/xray-core/v1/core"
)

func TestLoggerRestart(t *testing.T) {
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	})
	common.Must(err)
	common.Must(v.Start())

	server := &LoggerServer{
		V: v,
	}
	common.Must2(server.RestartLogger(context.Background(), &RestartLoggerRequest{}))
}
