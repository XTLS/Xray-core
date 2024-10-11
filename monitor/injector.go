package monitor

import (
	"fmt"
	"github.com/amirdlt/flex"
	"github.com/amirdlt/flex/db/mongo"
	"time"
)

type I struct {
	*flex.BasicInjector
}

func (i *I) DestinationCol() *mongo.Collection {
	return DestinationCol
}

func (i *I) LogCol() *mongo.Collection {
	return LogCol
}

func (i *I) ReportIfErr(err any, msg ...any) {
	if err == nil {
		return
	}

	_, _ = i.LogCol().InsertOne(ctx, Log{
		Level:     "error",
		Message:   fmt.Sprint(msg...),
		CreatedAt: time.Now(),
		Error:     fmt.Sprint(err),
	})
}
