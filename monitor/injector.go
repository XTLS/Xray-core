package monitor

import (
	"context"
	"fmt"
	"github.com/amirdlt/flex"
	"github.com/amirdlt/flex/db/mongo"
	"runtime"
	"time"
)

type I struct {
	*flex.BasicInjector
}

func (i *I) LogCol() *mongo.Collection {
	return logCol
}

func (i *I) AddressCol() *mongo.Collection {
	return addressCol
}

func (i *I) WindowCol() *mongo.Collection {
	return windowCol
}

func (i *I) OnlineStatCol() *mongo.Collection {
	return onlineStatCol
}

func (i *I) ReportIfErr(err any, msg ...any) {
	if err == nil {
		return
	}

	var stackTrace []string
	const maxStackDepth = 10
	for depth := 0; depth < maxStackDepth; depth++ {
		pc, file, line, ok := runtime.Caller(depth)
		if !ok {
			break
		}

		function := runtime.FuncForPC(pc).Name()
		stackTrace = append(stackTrace, fmt.Sprintf("%s:%d %s", file, line, function))
	}

	_, file, line, ok := runtime.Caller(1)
	fileInfo := ""
	if ok {
		fileInfo = fmt.Sprintf("%s:%d", file, line)
	}

	_, _ = i.LogCol().InsertOne(context.TODO(), Log{
		Level:      "error",
		Message:    fmt.Sprint(msg...),
		CreatedAt:  time.Now(),
		Error:      fmt.Sprint(err),
		StackTrace: stackTrace,
		File:       fileInfo,
	})
}

func (i *I) ReportInfo(data any, msg ...any) {
	_, _ = i.LogCol().InsertOne(context.TODO(), Log{
		Level:     "info",
		Message:   fmt.Sprint(msg...),
		Data:      data,
		CreatedAt: time.Now(),
	})
}
