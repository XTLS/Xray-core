package singbridge

import (
	"context"

	"github.com/sagernet/sing/common/logger"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
)

var _ logger.ContextLogger = (*XrayLogger)(nil)

type XrayLogger struct {
	newError func(values ...any) *errors.Error
}

func NewLogger(newErrorFunc func(values ...any) *errors.Error) *XrayLogger {
	return &XrayLogger{
		newErrorFunc,
	}
}

func (l *XrayLogger) Trace(args ...any) {
}

func (l *XrayLogger) Debug(args ...any) {
	l.newError(args...).AtDebug().WriteToLog()
}

func (l *XrayLogger) Info(args ...any) {
	l.newError(args...).AtInfo().WriteToLog()
}

func (l *XrayLogger) Warn(args ...any) {
	l.newError(args...).AtWarning().WriteToLog()
}

func (l *XrayLogger) Error(args ...any) {
	l.newError(args...).AtError().WriteToLog()
}

func (l *XrayLogger) Fatal(args ...any) {
}

func (l *XrayLogger) Panic(args ...any) {
}

func (l *XrayLogger) TraceContext(ctx context.Context, args ...any) {
}

func (l *XrayLogger) DebugContext(ctx context.Context, args ...any) {
	l.newError(args...).AtDebug().WriteToLog(session.ExportIDToError(ctx))
}

func (l *XrayLogger) InfoContext(ctx context.Context, args ...any) {
	l.newError(args...).AtInfo().WriteToLog(session.ExportIDToError(ctx))
}

func (l *XrayLogger) WarnContext(ctx context.Context, args ...any) {
	l.newError(args...).AtWarning().WriteToLog(session.ExportIDToError(ctx))
}

func (l *XrayLogger) ErrorContext(ctx context.Context, args ...any) {
	l.newError(args...).AtError().WriteToLog(session.ExportIDToError(ctx))
}

func (l *XrayLogger) FatalContext(ctx context.Context, args ...any) {
}

func (l *XrayLogger) PanicContext(ctx context.Context, args ...any) {
}
