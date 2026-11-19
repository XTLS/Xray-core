package commander_test

import (
	"runtime"
	"testing"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

func TestCommanderImmediateClose(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	for _, tc := range []struct {
		name   string
		listen string
	}{
		{name: "direct", listen: "127.0.0.1:0"},
		{name: "tagged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 16 {
				instance, err := core.New(&core.Config{
					App: []*serial.TypedMessage{
						serial.ToTypedMessage(&log.Config{
							AccessLogType: log.LogType_None,
							ErrorLogType:  log.LogType_None,
						}),
						serial.ToTypedMessage(&proxyman.OutboundConfig{}),
						serial.ToTypedMessage(&commander.Config{Tag: "api", Listen: tc.listen}),
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := instance.Start(); err != nil {
					instance.Close()
					t.Fatal(err)
				}
				if err := instance.Close(); err != nil {
					t.Fatal(err)
				}
				// Let the API goroutine run after the core has stopped.
				runtime.Gosched()
			}
		})
	}
}
