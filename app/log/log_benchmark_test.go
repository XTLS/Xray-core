package log_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/app/log"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	clog "github.com/xtls/xray-core/common/log"
)

type discardHandler struct{}

func (discardHandler) Handle(msg clog.Message) {
	_ = msg.String()
}

func BenchmarkLog(b *testing.B) {
	if err := log.RegisterHandlerCreator(log.LogType_Event, func(log.LogType, log.HandlerCreatorOptions) (clog.Handler, error) {
		return discardHandler{}, nil
	}); err != nil {
		b.Fatal(err)
	}
	ctx := c.ContextWithID(context.Background(), 123456)
	for _, tc := range []struct {
		name    string
		logType log.LogType
		level   clog.Severity
		log     func(context.Context, ...interface{})
	}{
		{"DisabledDebug", log.LogType_Event, clog.Severity_Warning, errors.LogDebug},
		{"DisabledInfo", log.LogType_Event, clog.Severity_Warning, errors.LogInfo},
		{"None", log.LogType_None, clog.Severity_Debug, errors.LogError},
		{"EnabledDebug", log.LogType_Event, clog.Severity_Debug, errors.LogDebug},
	} {
		b.Run(tc.name, func(b *testing.B) {
			logger, err := log.New(context.Background(), &log.Config{
				ErrorLogType: tc.logType, ErrorLogLevel: tc.level, AccessLogType: log.LogType_None,
			})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := logger.Close(); err != nil {
					b.Error(err)
				}
			})
			b.Run("Serial", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					tc.log(ctx, "message")
				}
			})
			b.Run("Parallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						tc.log(ctx, "message")
					}
				})
			})
		})
	}
}
